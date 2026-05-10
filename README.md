# PathForge

> A BGP-4 daemon written in Rust, built from scratch against RFC 4271

[![Build Status](https://github.com/arazmj/pathforge/actions/workflows/rust.yml/badge.svg)](https://github.com/arazmj/pathforge/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PathForge is a from-scratch implementation of the **Border Gateway Protocol version 4** ([RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)) written in Rust. It is designed for correctness, observability, and extensibility — 5 400 lines of Rust, 109 unit tests, 4 fuzz harnesses.

---

## Features

### Protocol Core

| Feature | RFC | Status |
|---------|-----|--------|
| BGP-4 message framing (19-byte header, marker) | RFC 4271 §4.1 | ✅ |
| OPEN message — version, AS, hold time, router-id | RFC 4271 §4.2 | ✅ |
| KEEPALIVE message | RFC 4271 §4.4 | ✅ |
| UPDATE message — withdrawn routes, path attrs, NLRI | RFC 4271 §4.3 | ✅ |
| NOTIFICATION message — error codes + subcodes | RFC 4271 §4.5 | ✅ |
| BGP FSM — all 6 states, all RFC-defined transitions | RFC 4271 §8 | ✅ |
| Hold timer & keepalive timer | RFC 4271 §10 | ✅ |
| ROUTE-REFRESH message | RFC 2918 | ✅ |

### Path Attributes

| Attribute | RFC | Status |
|-----------|-----|--------|
| ORIGIN, AS_PATH (2-byte + 4-byte), NEXT_HOP | RFC 4271 | ✅ |
| MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR | RFC 4271 | ✅ |
| COMMUNITIES (well-known + numeric) | RFC 1997 | ✅ |
| ORIGINATOR_ID, CLUSTER_LIST | RFC 4456 | ✅ |
| MP_REACH_NLRI / MP_UNREACH_NLRI (IPv4 + IPv6) | RFC 4760 | ✅ |
| Unknown attributes — pass-through | RFC 4271 | ✅ |

### Capability Negotiation

| Capability | RFC | Status |
|------------|-----|--------|
| Capability optional parameter framing | RFC 5492 | ✅ |
| Multi-Protocol (AFI/SAFI) | RFC 4760 | ✅ |
| Route Refresh | RFC 2918 | ✅ |
| 4-byte AS Number | RFC 6793 | ✅ |
| Graceful Restart | RFC 4724 | ✅ |

### RIB & Decision Process

| Feature | RFC | Status |
|---------|-----|--------|
| Adj-RIB-In per peer | RFC 4271 §9 | ✅ |
| Loc-RIB with best-path selection | RFC 4271 §9.1 | ✅ |
| Decision process: LOCAL_PREF → AS_PATH → ORIGIN → MED | RFC 4271 §9.1.2 | ✅ |
| Adj-RIB-Out (data structure) | RFC 4271 §9 | ✅ |
| Longest Prefix Match lookup | — | ✅ |
| Graceful Restart — stale routes + restart timer | RFC 4724 | ✅ |
| End-of-RIB marker detection | RFC 4724 §4.1 | ✅ |
| Route Dampening — penalty, suppress, reuse | RFC 2439 | ✅ |
| RPKI/ROA validation (Disabled / Loose / Strict) | RFC 6811 | ✅ |

### Routing Policy

| Feature | Status |
|---------|--------|
| Named prefix lists (permit/deny, ge/le range) | ✅ |
| Named community lists | ✅ |
| Import / export policy per neighbor | ✅ |
| Route Reflector — client/non-client, loop detection | ✅ |

### Operations

| Feature | Status |
|---------|--------|
| TOML configuration file | ✅ |
| Config validation (router-id, AS, hold time, neighbor checks) | ✅ |
| MD5 TCP authentication config (RFC 2385) | ✅ |
| Unix socket management CLI | ✅ |
| Prometheus metrics (sessions, messages, routes, errors) | ✅ |
| Structured logging with `tracing` + `#[instrument]` spans | ✅ |
| Docker Compose test environment (PathForge + FRRouting) | ✅ |
| GitHub Actions CI (test, coverage, build, security audit) | ✅ |
| cargo-fuzz harnesses (4 targets) | ✅ |

---

## Architecture

```
pathforge/
├── src/
│   ├── main.rs          # CLI (clap), initializes Server + MgmtServer
│   ├── lib.rs           # Library root — exposes all modules for fuzz + external use
│   ├── server.rs        # TCP listener; spawns one Tokio task per peer
│   ├── peer.rs          # Per-peer session loop; drives the FSM
│   ├── fsm.rs           # BgpState + BgpEvent enums (RFC 4271 §8)
│   ├── timer.rs         # Hold timer, keepalive timer, LocalConfig
│   ├── message/
│   │   ├── mod.rs           # Header, BgpMessage, MessageType
│   │   ├── open.rs          # OPEN message (RFC 4271 §4.2)
│   │   ├── keepalive.rs     # KEEPALIVE (RFC 4271 §4.4)
│   │   ├── notification.rs  # NOTIFICATION (RFC 4271 §4.5)
│   │   ├── update.rs        # UPDATE + NLRI prefix parsing (RFC 4271 §4.3)
│   │   └── route_refresh.rs # ROUTE-REFRESH (RFC 2918)
│   ├── attr.rs          # Path attribute parsing/serialization
│   ├── capabilities.rs  # Capability negotiation (RFC 5492 + 4760 + 6793 + 4724 + 2918)
│   ├── rib.rs           # Adj-RIB-In, Loc-RIB, Adj-RIB-Out; decision process; LPM
│   ├── dampening.rs     # Route dampening engine (RFC 2439)
│   ├── rpki.rs          # RPKI/ROA validation stub (RFC 6811)
│   ├── rr.rs            # Route Reflector logic (RFC 4456)
│   ├── policy.rs        # Prefix-list + community-list filtering
│   ├── mp.rs            # Multi-protocol NLRI (RFC 4760)
│   ├── metrics.rs       # Prometheus counters (atomic u64)
│   ├── mgmt.rs          # Unix socket management API
│   └── config.rs        # TOML config loading + validation
├── fuzz/
│   └── fuzz_targets/
│       ├── fuzz_bgp_message.rs    # Fuzzes BgpMessage::parse()
│       ├── fuzz_open_message.rs   # Fuzzes OpenMessage::parse()
│       ├── fuzz_update_message.rs # Fuzzes UpdateMessage::parse()
│       └── fuzz_path_attrs.rs     # Fuzzes PathAttributes::parse()
└── tests/
    ├── smoke_test.py    # Full BGP handshake → UPDATE → RIB verification
    └── e2e.sh           # Docker Compose end-to-end script
```

### BGP State Machine

```
Idle → Connect → OpenSent → OpenConfirm → Established
          ↓
        Active
```

### Key Data Flow

```
TCP accept (server.rs)
  → Peer::handle_incoming (peer.rs)
    → run_session: send OPEN (with capabilities) → recv OPEN → KEEPALIVE exchange → Established
    → handle_message:
        UPDATE  → dampening check → RPKI validation → rib.process_update()
                → decision process → Loc-RIB
        GR disconnect → rib.mark_peer_stale() → stale-timer task
        End-of-RIB → rib.remove_stale_for_peer()
        NOTIFICATION → rib.remove_peer()
        KEEPALIVE → reset hold timer
  → metrics counters incremented throughout
  → MgmtServer reads RIB over Unix socket
```

---

## Getting Started

### Prerequisites

- Rust 1.70+ (`rustup update stable`)

### Build

```bash
git clone https://github.com/arazmj/pathforge
cd pathforge
cargo build --release
```

### Run

```bash
# From a config file
sudo ./target/release/pathforge --config pathforge.example.toml

# CLI flags only (no config file)
sudo ./target/release/pathforge --local-as 65001 --router-id 10.0.0.1
```

### Example config

```toml
[router]
local_as    = 65001
router_id   = "10.0.0.1"
listen      = "0.0.0.0:179"
hold_time   = 90

[[neighbors]]
addr        = "192.168.1.2"
remote_as   = 65002
description = "Transit provider"
md5_password = "s3cr3t"         # RFC 2385 — requires Linux TCP_MD5SIG
import_policy = "import-from-transit"

[[neighbors]]
addr        = "10.0.0.2"
remote_as   = 65001
description = "iBGP peer"
route_reflector_client = true

[policy]
[[policy.prefix_lists]]
name = "import-from-transit"
entries = [
    { action = "deny",   prefix = "10.0.0.0/8" },
    { action = "permit", prefix = "0.0.0.0/0", ge = 8, le = 24 },
]
```

---

## Management CLI

Connect via Unix socket (default `/tmp/pathforge.sock`):

```bash
pathforge-cli() { echo "$1" | socat - UNIX-CONNECT:/tmp/pathforge.sock; }

pathforge-cli "show bgp summary"             # Peer count + Loc-RIB size
pathforge-cli "show bgp rib"                 # Full routing table (with ROV state)
pathforge-cli "show bgp rib prefix 10.0.0.0/8"
pathforge-cli "show bgp rib aspath 65002"    # Routes with AS 65002 in path
pathforge-cli "show bgp rib nexthop 10.0.0.1"
pathforge-cli "show bgp neighbors"
pathforge-cli "show bgp neighbors 10.0.0.1"
pathforge-cli "show bgp metrics"             # Human-readable counters
pathforge-cli "metrics"                      # Prometheus exposition format
pathforge-cli "version"
```

---

## Tests

```bash
# Unit tests (109 tests)
cargo test

# Lint
cargo clippy --all-targets -- -D warnings

# Format
cargo fmt --all -- --check

# Smoke test (requires release build + running daemon)
cargo build --release && python3 tests/smoke_test.py
```

### Fuzz Testing

```bash
# Build all 4 fuzz harnesses (requires nightly + cargo-fuzz)
cargo +nightly fuzz build

# Run a harness (ctrl-c to stop, corpus/crashes saved automatically)
cargo +nightly fuzz run fuzz_bgp_message
cargo +nightly fuzz run fuzz_update_message
cargo +nightly fuzz run fuzz_open_message
cargo +nightly fuzz run fuzz_path_attrs
```

The fuzz harnesses exercise the four most security-critical parsing surfaces:
every harness is required to return `Err` or `None` on malformed input — never panic or exhibit undefined behavior.

---

## Docker Compose Test Environment

Spin up PathForge alongside **FRRouting** for a real BGP session:

```bash
make up      # Build & start pathforge + FRR containers
make logs    # Follow logs from both containers
make smoke   # Python smoke test (handshake + UPDATE + management verification)
make down    # Tear down and remove volumes
```

Network layout (`172.20.0.0/24`):

| Container | IP | AS |
|-----------|----|----|
| PathForge | 172.20.0.2 | 65001 |
| FRRouting | 172.20.0.3 | 65002 |

FRR advertises `10.1.0.0/24` and `10.2.0.0/24` via eBGP to PathForge.

---

## Relevant RFCs

| RFC | Description |
|-----|-------------|
| [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) | Border Gateway Protocol 4 |
| [RFC 5492](https://datatracker.ietf.org/doc/html/rfc5492) | Capabilities Advertisement |
| [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760) | Multiprotocol Extensions for BGP-4 |
| [RFC 6793](https://datatracker.ietf.org/doc/html/rfc6793) | 4-Octet AS Number |
| [RFC 2918](https://datatracker.ietf.org/doc/html/rfc2918) | Route Refresh Capability |
| [RFC 4724](https://datatracker.ietf.org/doc/html/rfc4724) | Graceful Restart |
| [RFC 2439](https://datatracker.ietf.org/doc/html/rfc2439) | Route Flap Damping |
| [RFC 6811](https://datatracker.ietf.org/doc/html/rfc6811) | BGP Prefix Origin Validation (RPKI) |
| [RFC 2385](https://datatracker.ietf.org/doc/html/rfc2385) | TCP MD5 Signature Option |
| [RFC 4456](https://datatracker.ietf.org/doc/html/rfc4456) | BGP Route Reflection |
| [RFC 1997](https://datatracker.ietf.org/doc/html/rfc1997) | BGP Communities Attribute |
| [RFC 4486](https://datatracker.ietf.org/doc/html/rfc4486) | Subcodes for BGP Cease NOTIFICATION |

---

## License

MIT
