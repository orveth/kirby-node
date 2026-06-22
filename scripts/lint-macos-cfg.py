#!/usr/bin/env python3
"""Pre-Mac cfg-gating lint: catch the cross-platform-build break class from a Linux host.

THE BUG CLASS (the one bob's agent hit, fixed in 8f0ef6b): a *cross-platform* code
path references a symbol that only exists in a *Linux-only* module (one gated
`#[cfg(target_os = "linux")]`). On Linux it compiles; on macOS the module is cfg'd
out, the path is unresolved, and the build breaks -- but ONLY on a Mac, so the Linux
CI never sees it. bob's was an INLINE ref (`crate::idempotent_run::is_lock_contention`
inside the cross-platform `boot::open_treasury_retrying`), not a `use`, so a naive
grep that only checks `use` lines would miss exactly that.

WHY THIS EXISTS: a full macOS-target `cargo check` from Linux would catch the class at
check time, but it's blocked on turtle -- the C `-sys` crates (secp256k1-sys, ring,
zstd-sys) can't cross-compile their C for arm64-darwin without an Apple SDK / darwin
cross-cc. So this static lint is the pre-Mac gate instead: it reads ground truth (the
module gating in lib.rs) and flags any reference into a Linux-only module from code
that also compiles on macOS, UNLESS that reference is itself under a Linux cfg scope.

It is a guard-rail, not a proof: it understands `#[cfg(...)]` scope via a
string/comment-safe brace tracker, which covers the real patterns in this crate
(cfg'd `use`, cfg'd fields, cfg'd fn signatures + bodies, inline refs in un-cfg'd
fns). The authoritative check remains a real macOS build; this just stops the known
class from reaching a teammate's Mac. Exit 0 = clean, 1 = a latent Mac break, 2 = usage.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
REPO = HERE.parent.parent
SRC = REPO / "crates" / "kirby-node" / "src"
LIB = SRC / "lib.rs"


def requires_linux(gate: str) -> bool:
    """True iff a cfg gate restricts compilation to Linux (so it guards a Linux-only
    reference). `any(target_os = "linux", target_os = "macos")` does NOT -- it still
    compiles on macOS, where a Linux-only ref would break."""
    return ('target_os = "linux"' in gate) and ("macos" not in gate)


def parse_linux_only_modules(lib_src: str) -> set:
    """Modules declared `#[cfg(target_os = "linux")] (pub) mod X;` in lib.rs.
    Self-maintaining: adding/regating a module updates the lint automatically."""
    linux_only = set()
    pending_gate = None
    for line in lib_src.splitlines():
        s = line.strip()
        m = re.match(r"#\[cfg\((.*)\)\]", s)
        if m:
            pending_gate = m.group(1) if pending_gate is None else pending_gate + " " + m.group(1)
            continue
        mod = re.match(r"(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", s)
        if mod:
            if pending_gate is not None and requires_linux(pending_gate):
                linux_only.add(mod.group(1))
            pending_gate = None
            continue
        if s and not s.startswith("//"):
            pending_gate = None
    return linux_only


def blank_strings_and_comments(text: str) -> str:
    """Return `text` with the CONTENT of comments and string/char literals replaced by
    spaces (length + newlines preserved, so offsets and line numbers stay exact), so
    brace/paren counting and path-matching never trip on `format!("{}")`, doc comments
    naming a module, raw strings, lifetimes, etc. Structural punctuation OUTSIDE
    literals (incl. the parens of `#[cfg(...)]`) is preserved verbatim."""
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if two == "//":
            while i < n and text[i] != "\n":
                out.append(" "); i += 1
            continue
        if two == "/*":  # Rust nests block comments
            depth = 0
            while i < n:
                if text[i:i + 2] == "/*":
                    depth += 1; out.append("  "); i += 2; continue
                if text[i:i + 2] == "*/":
                    depth -= 1; out.append("  "); i += 2
                    if depth == 0:
                        break
                    continue
                out.append("\n" if text[i] == "\n" else " "); i += 1
            continue
        rm = re.match(r'b?r(#*)"', text[i:])  # raw / byte-raw string
        if rm:
            close = '"' + rm.group(1)
            start, j = i, i + rm.end()
            end = text.find(close, j)
            end = n if end == -1 else end + len(close)
            for k in range(start, end):
                out.append("\n" if text[k] == "\n" else " ")
            i = end; continue
        sm = re.match(r'b?"', text[i:])  # normal / byte string
        if sm:
            start, j = i, i + sm.end()
            while j < n:
                if text[j] == "\\":
                    j += 2; continue
                if text[j] == '"':
                    j += 1; break
                j += 1
            for k in range(start, j):
                out.append("\n" if text[k] == "\n" else " ")
            i = j; continue
        if c == "'":  # char literal vs lifetime
            if text[i + 1:i + 2] == "\\":
                end = text.find("'", i + 2)
                if end != -1:
                    for _ in range(i, end + 1):
                        out.append(" ")
                    i = end + 1; continue
            elif text[i + 2:i + 3] == "'":  # 'x'
                out.append("   "); i += 3; continue
            # else: a lifetime like 'a -- emit the quote, fall through
        out.append(c); i += 1
    return "".join(out)


def analyze(path: Path, linux_only: set):
    """Flag references into a Linux-only module that are NOT under a Linux cfg scope."""
    raw = path.read_text()
    code = blank_strings_and_comments(raw)
    raw_lines = raw.splitlines()

    def lineno_at(off: int) -> int:
        return code.count("\n", 0, off) + 1

    mod_alt = "|".join(sorted(re.escape(m) for m in linux_only))
    # Only crate-local paths: catches inline `crate::idempotent_run::x` AND
    # `use crate::firecracker::Y` (contains `crate::firecracker`), but NOT a foreign
    # `use openraft::network` (different `network`).
    ref_re = re.compile(r"\b(?:crate|super|self)\s*::\s*(?:" + mod_alt + r")\b")
    refs = [(m.start(), m.group(0)) for m in ref_re.finditer(code)]
    cfg_re = re.compile(r"#\[\s*cfg\s*\(")

    depth = paren = brack = 0      # {} / () / [] nesting
    stack = []                     # per {-block: does it require linux?
    pending_active = False         # a #[cfg] attr awaiting its item
    pending_req = False
    pending_depth = 0

    def under_linux() -> bool:
        return (pending_active and pending_req) or any(stack)

    findings = []
    ref_idx, i, n = 0, 0, len(code)
    while i < n:
        while ref_idx < len(refs) and refs[ref_idx][0] == i:
            off, snippet = refs[ref_idx]
            if not under_linux():
                ln = lineno_at(off)
                src = raw_lines[ln - 1].strip() if ln - 1 < len(raw_lines) else snippet
                mod = snippet.split("::")[-1].strip()
                findings.append((ln, src, mod))
            ref_idx += 1

        if code[i] == "#" and cfg_re.match(code[i:]):  # #[cfg(...)]
            j = code.find("(", i)
            d, k = 0, j
            while k < n:
                if code[k] == "(":
                    d += 1
                elif code[k] == ")":
                    d -= 1
                    if d == 0:
                        break
                k += 1
            gate = raw[j + 1:k]  # read the gate from RAW (strings intact)
            req = requires_linux(gate)
            pending_req = (pending_req or req) if pending_active else req
            pending_active = True
            pending_depth = depth
            i = k + 1
            continue

        c = code[i]
        if c == "{":
            stack.append(pending_active and pending_req)
            pending_active = pending_req = False
            depth += 1
        elif c == "}":
            if stack:
                stack.pop()
            depth = max(0, depth - 1)
        elif c == "(":
            paren += 1
        elif c == ")":
            paren = max(0, paren - 1)
        elif c == "[":
            brack += 1
        elif c == "]":
            brack = max(0, brack - 1)
        elif c in ";,":
            # a #[cfg] on a non-block item (use/field/let) is consumed at its
            # terminator -- but only at top level, so fn-signature commas inside
            # `(...)` don't prematurely drop a cfg that governs the whole fn.
            if pending_active and depth == pending_depth and paren == 0 and brack == 0:
                pending_active = pending_req = False
        i += 1

    return findings


def main() -> int:
    if not LIB.is_file():
        print(f"lint-macos-cfg: cannot find {LIB}", file=sys.stderr)
        return 2
    linux_only = parse_linux_only_modules(LIB.read_text())
    if not linux_only:
        print("lint-macos-cfg: no Linux-only modules in lib.rs (nothing to guard)")
        return 0
    print(f"lint-macos-cfg: Linux-only modules = {', '.join(sorted(linux_only))}")

    linux_files = {SRC / f"{m}.rs" for m in linux_only}
    all_findings = []
    for path in sorted(SRC.rglob("*.rs")):
        if path in linux_files:
            continue  # a Linux-only module's own file never compiles on macOS
        for ln, src, mod in analyze(path, linux_only):
            all_findings.append((path, ln, src, mod))

    if not all_findings:
        print("lint-macos-cfg: OK -- no un-gated references into Linux-only modules "
              "from macOS-compiled code.")
        return 0

    print("\nlint-macos-cfg: FAIL -- macOS build break(s): a reference into a Linux-only "
          "module from code that also compiles on macOS, not under a "
          "`#[cfg(target_os = \"linux\")]` scope:\n", file=sys.stderr)
    for path, ln, src, mod in all_findings:
        print(f"  {path.relative_to(REPO)}:{ln}: reaches Linux-only `{mod}` -> {src}",
              file=sys.stderr)
    print(f"\n{len(all_findings)} finding(s). Fix: move the symbol to a cross-platform "
          "module (see 8f0ef6b: is_lock_contention -> treasury.rs), or gate the "
          "reference with `#[cfg(target_os = \"linux\")]`.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
