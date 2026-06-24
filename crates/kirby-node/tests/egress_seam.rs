//! FAST, UNGATED G4 egress-isolation seam tests (spec 3.7, gate G4).
//!
//! The real G4 enforcement (`egress_lockdown.rs`) needs a Firecracker microVM,
//! real nftables, real eBPF, and root, so it SKIPS green without the genome
//! image. These tests cover the same invariants WITHOUT any hardware by driving
//! the injectable command-execution + eBPF-load seams:
//!
//!   (a) RULESET VALIDITY + NO-ROUTE: capture every privileged argv the lockdown
//!       issues; assert the nft ruleset binds the ingress filter hook to the TAP,
//!       defaults to `policy drop`, carries the drop counter, and that NO
//!       `ip route` / IP-forwarding command is ever issued for the VM TAP.
//!   (b) RULESET VALIDATOR: a parser/validator over the nft rule string that
//!       FAILS on a malformed hook / policy / device / counter (negative cases).
//!   (c) eBPF INGRESS DIRECTION + SPAWN HANDSHAKE: assert the meter attaches in
//!       the INGRESS direction (the VM-egress direction for a TAP), and that the
//!       spawn/`attached` handshake completes against a mocked loader child.

#![cfg(target_os = "linux")]

use std::time::Duration;

use kirby_node::meter_egress::{self, EgressMeter, EgressMeterDirection};
use kirby_node::network::{
    self, egress_ruleset, validate_egress_ruleset, CommandRunner, VmTap,
};

// ---- A capture CommandRunner: records every privileged argv + stdin, no OS ----

#[derive(Default)]
struct CaptureRunner {
    calls: std::sync::Mutex<Vec<network::PrivilegedCommand>>,
}

impl CaptureRunner {
    fn calls(&self) -> Vec<network::PrivilegedCommand> {
        self.calls.lock().unwrap().clone()
    }
    fn record(&self, args: &[&str], stdin: Option<&str>) {
        self.calls.lock().unwrap().push(network::PrivilegedCommand {
            args: args.iter().map(|s| s.to_string()).collect(),
            stdin: stdin.map(|s| s.to_string()),
        });
    }
}

impl CommandRunner for CaptureRunner {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> anyhow::Result<()> {
        self.record(args, stdin);
        Ok(())
    }
    fn capture(&self, args: &[&str]) -> anyhow::Result<String> {
        self.record(args, None);
        // A benign counter read; never exercised by these tests' assertions.
        Ok("counter dropped_egress { packets 0 bytes 0 }".to_string())
    }
    fn discard(&self, args: &[&str]) {
        self.record(args, None);
    }
}

/// A clone-able handle so the test keeps the recorder after moving a Box into VmTap.
#[derive(Clone, Default)]
struct SharedCapture(std::sync::Arc<CaptureRunner>);

impl CommandRunner for SharedCapture {
    fn run(&self, args: &[&str], stdin: Option<&str>) -> anyhow::Result<()> {
        self.0.run(args, stdin)
    }
    fn capture(&self, args: &[&str]) -> anyhow::Result<String> {
        self.0.capture(args)
    }
    fn discard(&self, args: &[&str]) {
        self.0.discard(args)
    }
}

// ---- (a) RULESET VALIDITY + NO `ip route` / NO FORWARDING for the VM TAP ----

#[test]
fn a_lockdown_installs_ingress_drop_ruleset_and_never_routes_the_tap() {
    let recorder = SharedCapture::default();
    let tap = VmTap::create_with_runner("g4seam-12345678", 1001, 1001, Box::new(recorder.clone()))
        .expect("create the locked-down TAP through the capture runner");

    let dev = tap.name().to_string();
    let calls = recorder.0.calls();
    assert!(!calls.is_empty(), "the lockdown must issue privileged commands");

    // The nft ruleset is fed on stdin to `nft -f -`. Find it and validate it.
    let nft = calls
        .iter()
        .find(|c| c.args.first().map(String::as_str) == Some("nft") && c.stdin.is_some())
        .expect("the lockdown must install an nft ruleset via `nft -f -`");
    assert_eq!(
        nft.args,
        vec!["nft".to_string(), "-f".to_string(), "-".to_string()],
        "ruleset must be installed via `nft -f -`"
    );
    let ruleset = nft.stdin.as_deref().expect("nft ruleset on stdin");

    // The ingress filter hook is bound to THIS TAP, with policy drop + drop counter.
    validate_egress_ruleset(ruleset, &dev)
        .unwrap_or_else(|e| panic!("installed ruleset must enforce G4 for {dev}: {e}"));
    assert!(
        ruleset.contains(&format!("hook ingress device \"{dev}\"")),
        "the ingress hook must be bound to the VM TAP {dev}; got:\n{ruleset}"
    );
    assert!(ruleset.contains("policy drop"), "default-deny `policy drop` required");
    assert!(
        ruleset.contains("counter dropped_egress"),
        "the dropped-egress counter must be declared"
    );

    // The TAP gets only an on-link /30 address and is brought up; the host is
    // NEVER made a router for it. Scan EVERY argv: no `ip route`, no forwarding
    // sysctl, no NAT/masquerade, no default route.
    for call in &calls {
        let argv = call.args.join(" ");
        assert!(
            !(call.args.first().map(String::as_str) == Some("ip")
                && call.args.get(1).map(String::as_str) == Some("route")),
            "the VM TAP must never get an `ip route`; saw: {argv}"
        );
        assert!(
            !argv.contains("ip_forward") && !argv.contains("forwarding"),
            "IP forwarding must never be enabled for the VM TAP; saw: {argv}"
        );
        assert!(
            !argv.contains("MASQUERADE") && !argv.contains("masquerade") && !argv.contains("snat"),
            "no NAT/masquerade may be configured for the VM TAP; saw: {argv}"
        );
        assert!(
            !argv.contains("default") && !argv.contains("via"),
            "no default route / gateway may be configured for the VM TAP; saw: {argv}"
        );
    }

    // The only `ip addr` add is the on-link /30 (no path off-link).
    let addr = calls
        .iter()
        .find(|c| {
            c.args.first().map(String::as_str) == Some("ip")
                && c.args.get(1).map(String::as_str) == Some("addr")
        })
        .expect("the TAP gets an on-link host address");
    assert!(
        addr.args.iter().any(|a| a == "172.16.0.1/30"),
        "the host end is an on-link /30 only (no routable subnet); got {:?}",
        addr.args
    );

    // The TAP is created owned by the daemon uid/gid (so the daemon, not root,
    // hands it to the jailed firecracker) and brought up.
    let tuntap = calls
        .iter()
        .find(|c| c.args.iter().any(|a| a == "tuntap"))
        .expect("the TAP is created via `ip tuntap add`");
    assert!(
        tuntap.args.iter().any(|a| a == "1001"),
        "the TAP is owned by the daemon uid/gid; got {:?}",
        tuntap.args
    );

    // Keep the TAP from running real teardown commands on drop; it would just
    // record more no-op calls through the capture runner, which is harmless, but
    // tear down explicitly for clarity.
    tap.teardown();
}

// ---- (b) RULESET VALIDATOR: rejects malformed rulesets (negative cases) ----

#[test]
fn b_validator_rejects_malformed_rulesets() {
    let dev = "kirby-tap-07480";

    // The well-formed ruleset passes.
    let good = egress_ruleset("kirby_egress_abcd1234", dev);
    assert!(validate_egress_ruleset(&good, dev).is_ok(), "the real ruleset must validate");

    // Wrong direction: an EGRESS hook only sees host-to-guest, so the VM's egress
    // would NOT be filtered. This is the most dangerous typo and must be rejected.
    let egress_hook = good.replace("hook ingress", "hook egress");
    let err = validate_egress_ruleset(&egress_hook, dev)
        .expect_err("an egress-hook ruleset must be REJECTED (VM egress would leak)");
    assert!(err.to_lowercase().contains("egress"), "error must name the wrong hook: {err}");

    // Missing the default-deny policy: the chain would default to ACCEPT.
    let no_drop = good.replace("policy drop;", "policy accept;");
    validate_egress_ruleset(&no_drop, dev)
        .expect_err("a ruleset without `policy drop` must be REJECTED (default-deny missing)");

    // Bound to the WRONG device: the hook would not cover this VM's TAP at all.
    let wrong_dev = good.replace(dev, "eth0");
    validate_egress_ruleset(&wrong_dev, dev)
        .expect_err("a ruleset bound to another device must be REJECTED for this TAP");

    // Missing the drop counter: G4 loses its observable evidence.
    let no_counter = good.replace("counter dropped_egress { }\n", "");
    validate_egress_ruleset(&no_counter, dev)
        .expect_err("a ruleset without the dropped_egress counter must be REJECTED");

    // Not a netdev table at all (e.g. an inet/filter table that does not bind a
    // device hook): rejected.
    let not_netdev = "table inet filter { chain x { policy drop; } }";
    validate_egress_ruleset(not_netdev, dev)
        .expect_err("a non-netdev table must be REJECTED");
}

// ---- (c) eBPF INGRESS DIRECTION + SPAWN/ATTACHED HANDSHAKE ----

#[test]
fn c_egress_meter_direction_is_ingress() {
    // The single source of truth the privileged meter maps to aya's attach type
    // MUST be INGRESS (the VM-egress direction for a TAP). The egress hook would
    // only see host-to-guest and silently meter ~0 for real VM egress.
    assert_eq!(
        meter_egress::EGRESS_METER_DIRECTION,
        EgressMeterDirection::Ingress,
        "the egress meter must attach on the TAP's INGRESS hook (the VM-egress direction)"
    );
}

#[tokio::test]
async fn c_egress_meter_spawn_attached_handshake_completes() {
    // Mock the privileged loader child WITHOUT a kernel: a fake `sudo` that just
    // execs its trailing argv, and a fake `kirby-node` (via KIRBY_NODE_BIN) that
    // prints `attached` then a couple of `EGRESS_BYTES <n>` lines, exactly the
    // handshake EgressMeter::spawn waits for. This proves the spawn -> attached
    // handshake completes and the live byte counter is read, with no eBPF/root.
    let dir = std::env::temp_dir().join(format!("kirby-egress-seam-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("scratch dir");

    // Fake sudo: drop the leading `-n` and exec the rest (so `sudo -n <bin> ...`
    // runs `<bin> ...`). Records the full argv to a file so we can assert --iface.
    let argv_log = dir.join("argv.log");
    let fake_sudo = dir.join("fake-sudo");
    std::fs::write(
        &fake_sudo,
        format!(
            "#!/bin/sh\n\
             # drop the leading -n, log the rest, exec it\n\
             shift\n\
             printf '%s\\n' \"$*\" >> {log}\n\
             exec \"$@\"\n",
            log = argv_log.display(),
        ),
    )
    .expect("write fake sudo");

    // Fake kirby-node: emit the attach handshake and a byte counter, then idle so
    // the meter's stdout reader stays alive until shutdown kills it.
    let fake_node = dir.join("kirby-node");
    std::fs::write(
        &fake_node,
        "#!/bin/sh\n\
         echo attached\n\
         echo 'EGRESS_BYTES 0'\n\
         echo 'EGRESS_BYTES 1500'\n\
         # stay attached until the parent tears us down\n\
         while true; do sleep 1; done\n",
    )
    .expect("write fake node");

    for p in [&fake_sudo, &fake_node] {
        let mut perms = std::fs::metadata(p).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o755);
        std::fs::set_permissions(p, perms).expect("chmod +x");
    }

    // Point the meter at the fake kirby-node binary (the documented test override).
    std::env::set_var("KIRBY_NODE_BIN", &fake_node);

    let tap = "kirby-tap-07480";
    let meter = EgressMeter::spawn(tap, fake_sudo.clone(), Duration::from_millis(50))
        .await
        .expect("the spawn -> attached handshake must complete against the mock loader");

    // The handshake completed and the live counter is being read from the child.
    // Give the second tick a moment to land, then assert the byte counter advanced.
    for _ in 0..40 {
        if meter.egress_bytes() >= 1500 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        meter.egress_bytes() >= 1500,
        "the meter must read the live EGRESS_BYTES counter from the attached child; got {}",
        meter.egress_bytes()
    );

    // The child was launched with the correct interface argument.
    let logged = std::fs::read_to_string(&argv_log).unwrap_or_default();
    assert!(
        logged.contains("ebpf-egress") && logged.contains("--iface") && logged.contains(tap),
        "the meter child must be launched `ebpf-egress --iface {tap}`; argv log:\n{logged}"
    );

    meter.shutdown().await;
    std::env::remove_var("KIRBY_NODE_BIN");
    let _ = std::fs::remove_dir_all(&dir);
}
