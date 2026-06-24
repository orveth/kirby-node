//! Fleet-host S0 gates (non-gated, pure): G-CLEAN (the fleet block is additive and
//! inert when off) and G-ALLOC (the allocator's distinctness/exhaustion/no-restart-
//! reuse teeth, the heart of which lives in `kirby_node::fleet`'s unit tests; here we
//! drive the allocator through its PUBLIC surface as an integration consumer would).
//!
//! These run with no genome image (pure bookkeeping + config parsing).

use kirby_node::config::{FleetConfig, KirbyConfig};
use kirby_node::fleet::{AllocError, Allocator};

/// A minimal well-formed config with NO `[fleet]` block (the single-agent shape a
/// teammate writes today). It must parse and behave exactly as before fleet existed.
fn minimal_toml_no_fleet() -> &'static str {
    r#"
        genome_image = { path = "/tmp/kirby/genome-image" }

        [identity]
        key_path = "/tmp/kirby/node.nostr.key"

        [relay]
        url = "ws://127.0.0.1:7777"
    "#
}

/// G-CLEAN: with fleet OFF (no `[fleet]` block), a config parses to the SAME
/// single-agent shape as before, and the defaulted `fleet` block is the documented
/// inert default. The off-path is structurally unchanged: every pre-fleet field keeps
/// its pre-fleet default and the fleet block is purely additive.
#[test]
fn g_clean_bare_config_is_unchanged_and_fleet_defaults_inert() {
    let cfg = KirbyConfig::from_toml_str(minimal_toml_no_fleet()).expect("bare config parses");

    // Every pre-fleet default is exactly what it was before the fleet block existed.
    assert_eq!(cfg.agent_id, "agent-0");
    assert_eq!(cfg.node_id, "node-1");
    assert_eq!(cfg.funding.initial_sats, 1_000_000);
    assert_eq!(cfg.relay.presence_interval_secs, 15);
    assert_eq!(cfg.relay.presence_stale_after_secs, 45);

    // The fleet block defaulted in, and it is the documented inert default.
    assert_eq!(cfg.fleet, FleetConfig::default());
    assert_eq!(cfg.fleet.base_cid, 100, "base CID must clear the vsock-reserved 0..=2");
    assert!(cfg.fleet.base_cid > 2);
    assert_eq!(cfg.fleet.max_tenants, 16);
    assert_eq!(cfg.fleet.gateway_port_base, 9000);
}

/// G-CLEAN (additivity teeth): adding an EXPLICIT `[fleet]` block does not perturb any
/// other field, and an omitted block parses identically to an explicit all-defaults
/// block. So a teammate adding `[fleet]` knobs changes ONLY the fleet block.
#[test]
fn g_clean_explicit_fleet_block_matches_default_and_perturbs_nothing() {
    let with_explicit = r#"
        genome_image = { path = "/tmp/kirby/genome-image" }
        [identity]
        key_path = "/tmp/kirby/node.nostr.key"
        [relay]
        url = "ws://127.0.0.1:7777"
        [fleet]
        base_cid = 100
        max_tenants = 16
        gateway_port_base = 9000
    "#;
    let bare = KirbyConfig::from_toml_str(minimal_toml_no_fleet()).unwrap();
    let explicit = KirbyConfig::from_toml_str(with_explicit).unwrap();
    // An explicit all-defaults [fleet] block yields a byte-identical config value.
    assert_eq!(bare, explicit, "an explicit all-defaults [fleet] block must equal the omitted one");
}

/// G-ALLOC (consumer view): the allocator hands distinct CID/instance_id/gateway_port
/// to N tenants and rejects past the cap. The exhaustive teeth (restart-no-reuse,
/// per-agent at-most-once) are pinned in the `fleet` unit tests; this is the public
/// integration contract.
#[test]
fn g_alloc_distinct_triples_and_exhaustion() {
    let fleet = FleetConfig { base_cid: 100, max_tenants: 3, gateway_port_base: 9000 };
    let mut alloc = Allocator::new(&fleet);

    let mut cids = std::collections::BTreeSet::new();
    let mut ports = std::collections::BTreeSet::new();
    for n in 0..3 {
        let a = alloc.allocate(&format!("agent-{n}")).expect("allocate within cap");
        assert!(a.guest_cid > 2);
        assert_eq!(a.instance_id, format!("kirby-agent-{n}"));
        assert!(cids.insert(a.guest_cid), "two live tenants got the same CID");
        assert!(ports.insert(a.gateway_port), "two live tenants got the same port");
    }
    // Past the cap, allocation is rejected and consumes no slot.
    let err = alloc.allocate("agent-overflow").unwrap_err();
    assert!(matches!(err, AllocError::Exhausted { max_tenants: 3, live: 3 }));
    assert_eq!(alloc.live_count(), 3);
}
