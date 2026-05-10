# PathForge — Developer Guide

PathForge is a BGP-4 daemon written in Rust, built from scratch against RFC 4271.
This file is the quick-start guide for working in the codebase with Claude Code.

## Build & Run

```bash
# Debug build
cargo build

# Release build (used in smoke tests)
cargo build --release

# Run with defaults (AS 65001, router-id 1.1.1.1, listen 0.0.0.0:179)
./target/debug/pathforge --local-as 65001 --router-id 10.0.0.1

# Run from a config file
./target/debug/pathforge --config pathforge.example.toml
```

## Tests

```bash
# All unit tests
cargo test

# Run clippy with CI-matching flags
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check

# Smoke test (requires release build first)
cargo build --release && python3 tests/smoke_test.py

# Docker Compose integration (pathforge + FRRouting)
make up && make smoke && make down
```

## Module Map

| Module | File | Purpose |
|--------|------|---------|
| `main` | `src/main.rs` | CLI (clap), initializes Server + MgmtServer |
| `server` | `src/server.rs` | TCP listener; spawns one Tokio task per peer |
| `peer` | `src/peer.rs` | Per-peer session loop; drives the FSM |
| `fsm` | `src/fsm.rs` | `BgpState` + `BgpEvent` enums (RFC 4271 §8) |
| `timer` | `src/timer.rs` | Hold timer, keepalive timer, `LocalConfig` |
| `message` | `src/message/` | BGP message header parsing; OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH |
| `attr` | `src/attr.rs` | Path attribute parsing/serialization (ORIGIN, AS_PATH, NEXT_HOP, MED, LOCAL_PREF, Communities, ORIGINATOR_ID, CLUSTER_LIST, unknown pass-through) |
| `rib` | `src/rib.rs` | Adj-RIB-In, Loc-RIB, Adj-RIB-Out; RFC 4271 §9.1 decision process |
| `capabilities` | `src/capabilities.rs` | BGP capability negotiation (RFC 5492, 4760, 6793, 4724, 2918) |
| `mp` | `src/mp.rs` | Multi-protocol NLRI: MP_REACH_NLRI / MP_UNREACH_NLRI (RFC 4760) |
| `rr` | `src/rr.rs` | Route Reflector logic (RFC 4456); `#![allow(dead_code)]` — not yet wired into peer |
| `policy` | `src/policy.rs` | Prefix-list + community-list route filtering; `#![allow(dead_code)]` — not yet wired into peer |
| `metrics` | `src/metrics.rs` | Prometheus counters (atomic u64, no lock) |
| `mgmt` | `src/mgmt.rs` | Unix socket management API (show commands) |
| `config` | `src/config.rs` | TOML config loading + validation |

## Key Data Flow

```
TCP accept (server.rs)
  → Peer::handle_incoming (peer.rs)
    → run_session: send OPEN with capabilities → recv OPEN → KEEPALIVE exchange → Established
    → handle_message: UPDATE → rib.process_update() → BGP decision process → Loc-RIB
                    : NOTIFICATION → rib.remove_peer()
                    : KEEPALIVE → reset hold timer
  → metrics counters incremented throughout
  → MgmtServer reads RIB + MgmtState over Unix socket (read-only, no lock held long)
```

## Adding a New RFC Feature

1. **Protocol structures**: parse in `message/` or a new module, add roundtrip tests.
2. **Wire into peer.rs**: handle the new message type or capability in `handle_message`.
3. **Config support**: add fields to `config.rs` and validate in `Config::validate`.
4. **Tests**: unit tests in the module file, and update `tests/smoke_test.py` for integration.
5. **Metrics**: add `AtomicU64` counter to `Metrics` struct; increment from `peer.rs`.

## Known Intentionally Unconnected Modules

These modules are complete and fully tested but not yet wired into the production path:

- **`rr.rs`**: Route Reflector (RFC 4456) — needs neighbor `route_reflector_client` flag read from config
- **`policy.rs`**: Prefix/community policy engine — needs `import_policy`/`export_policy` config fields passed into peer
- **`mp.rs`**: Multi-protocol NLRI — needs attr.rs to parse type codes 14/15 and surface to peer

## Dead Code Policy

- **Broad suppression removed**: `#![allow(dead_code, unused_imports, unused_variables)]` was removed from `main.rs` in Iteration 19.
- **Module-level allows**: `rr.rs`, `policy.rs`, `mp.rs` carry `#![allow(dead_code)]` because they're intentionally complete-but-not-wired.
- **Item-level allows**: used for protocol-complete API surface (serializers, error variants) that aren't yet called from production code but should not be removed.

## Management CLI

```bash
pathforge-cli() { echo "$1" | socat - UNIX-CONNECT:/tmp/pathforge.sock; }

pathforge-cli "show bgp summary"
pathforge-cli "show bgp rib"
pathforge-cli "show bgp rib prefix 10.0.0.0/8"
pathforge-cli "show bgp neighbors"
pathforge-cli "show bgp neighbors 10.0.0.1"
pathforge-cli "show bgp metrics"
pathforge-cli "metrics"          # Prometheus exposition format
```
