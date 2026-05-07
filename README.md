# PathForge 🦀

> A feature-rich BGP-4 daemon written in Rust

[![Build Status](https://github.com/arazmj/pathforge/actions/workflows/rust.yml/badge.svg)](https://github.com/arazmj/pathforge/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

PathForge is a from-scratch implementation of the **Border Gateway Protocol version 4** ([RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271)) written in Rust. It is designed for correctness, observability, and extensibility.

---

## Features

| Feature | Status |
|---------|--------|
| BGP OPEN message parsing & serialization | ✅ |
| BGP KEEPALIVE message | ✅ |
| BGP UPDATE message (NLRI + withdrawn routes) | ✅ |
| NOTIFICATION message | ✅ |
| BGP message header (19-byte, RFC 4271 §4.1) | ✅ |
| BGP FSM — full RFC 4271 §8 (all 6 states + transitions) | ✅ |
| Hold timer & keepalive timer | ✅ |
| BGP session event loop (async tokio task per peer) | ✅ |
| Path attributes: ORIGIN, AS_PATH (4-byte), NEXT_HOP, MED, LOCAL_PREF | ✅ |
| Path attributes: ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITIES (RFC 1997) | ✅ |
| Path attributes: ORIGINATOR_ID, CLUSTER_LIST, unknown pass-through | ✅ |
| Routing Information Base: Adj-RIB-In, Loc-RIB, Adj-RIB-Out | ✅ |
| BGP decision process (LOCAL_PREF → AS_PATH → ORIGIN → MED) | ✅ |
| Route withdrawal propagation to RIB | ✅ |
| NOTIFICATION messages & error handling | ✅ |
| TOML configuration file (router, neighbors, policy) | ✅ |
| BGP Communities (RFC 1997): parsing, well-known, display | ✅ |
| Route filtering: prefix lists (ge/le range), community lists | ✅ |
| Import/export policy engine | ✅ |
| Multi-protocol / IPv6 (RFC 4760) | ⏳ Planned |
| CLI management interface | ⏳ Planned |
| gRPC / REST API | ⏳ Planned |
| Route Reflector (RFC 4456) | ⏳ Planned |
| Prometheus metrics | ⏳ Planned |
| Docker Compose test environment | ⏳ Planned |
| End-to-end tests with FRRouting | ⏳ Planned |

---

## Architecture

```
pathforge/
├── src/
│   ├── main.rs       # Entry point, CLI argument parsing
│   ├── server.rs     # TCP listener, connection dispatch
│   ├── peer.rs       # Peer state, connection handler
│   ├── config.rs     # TOML configuration: router, neighbors, prefix lists, communities
│   ├── message/      # BGP message types
│   │   ├── mod.rs        # Header, BgpMessage, MessageType
│   │   ├── open.rs       # OPEN message (RFC 4271 §4.2)
│   │   ├── keepalive.rs  # KEEPALIVE message (RFC 4271 §4.4)
│   │   ├── notification.rs # NOTIFICATION message (RFC 4271 §4.5)
│   │   └── update.rs     # UPDATE message + NLRI prefix parsing (RFC 4271 §4.3)
└── Cargo.toml
```

### BGP State Machine

PathForge implements the RFC 4271 FSM with these states:

```
Idle → Connect → OpenSent → OpenConfirm → Established
          ↓
        Active
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

### Run with config file

```bash
# Run with a TOML config file
sudo ./target/release/pathforge --config pathforge.toml

# Or use CLI flags (no config file needed)
sudo ./target/release/pathforge --local-as 65001 --router-id 10.0.0.1
```

### Example config (`pathforge.example.toml`)

```toml
[router]
local_as = 65001
router_id = "10.0.0.1"
listen = "0.0.0.0:179"
hold_time = 90

[[neighbors]]
addr = "192.168.1.2"
remote_as = 65002
description = "Transit provider"
import_policy = "import-from-transit"

[[neighbors]]
addr = "10.0.0.2"
remote_as = 65001
description = "iBGP peer"

[policy]
[[policy.prefix_lists]]
name = "import-from-transit"
entries = [
    { action = "deny",   prefix = "10.0.0.0/8" },
    { action = "permit", prefix = "0.0.0.0/0", ge = 8, le = 24 },
]
```

---

## Relevant RFCs

| RFC | Description |
|-----|-------------|
| [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) | A Border Gateway Protocol 4 (BGP-4) |
| [RFC 4760](https://datatracker.ietf.org/doc/html/rfc4760) | Multiprotocol Extensions for BGP-4 |
| [RFC 1997](https://datatracker.ietf.org/doc/html/rfc1997) | BGP Communities Attribute |
| [RFC 4456](https://datatracker.ietf.org/doc/html/rfc4456) | BGP Route Reflection |
| [RFC 4486](https://datatracker.ietf.org/doc/html/rfc4486) | Subcodes for BGP Cease NOTIFICATION |

---

## License

MIT
