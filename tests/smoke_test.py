#!/usr/bin/env python3
"""Smoke test: start pathforge, verify BGP session handshake + route exchange + management."""
import socket, time, struct, sys, subprocess, os

BINARY = os.path.join(os.path.dirname(__file__), '..', 'target', 'release', 'pathforge')
MGMT_SOCK = '/tmp/pathforge-smoke.sock'
BGP_PORT = 1791

PASS = "\033[32m✅\033[0m"
FAIL = "\033[31m❌\033[0m"
errors = []

def check(name, condition, detail=""):
    if condition:
        print(f"{PASS} {name}")
    else:
        print(f"{FAIL} {name}: {detail}")
        errors.append(name)

# ── BGP message builders ──────────────────────────────────────────────────────

MARKER = b'\xff' * 16

def bgp_header(msg_type, body):
    length = 19 + len(body)
    return MARKER + struct.pack('!HB', length, msg_type) + body

def bgp_open(my_as, hold_time, bgp_id_str):
    id_bytes = bytes(int(x) for x in bgp_id_str.split('.'))
    body = bytes([4]) + struct.pack('!HH', my_as, hold_time) + id_bytes + b'\x00'
    return bgp_header(1, body)

def bgp_keepalive():
    return bgp_header(4, b'')

def bgp_update(withdrawn=None, path_attrs=b'', nlri_prefixes=None):
    """Build a BGP UPDATE message.

    withdrawn: list of (prefix_addr_str, prefix_len) to withdraw
    path_attrs: raw bytes for path attributes section
    nlri_prefixes: list of (prefix_addr_str, prefix_len) to announce
    """
    def encode_prefix(addr_str, plen):
        nbytes = (plen + 7) // 8
        addr_bytes = bytes(int(x) for x in addr_str.split('.'))
        return bytes([plen]) + addr_bytes[:nbytes]

    withdrawn_bytes = b''
    if withdrawn:
        for addr, plen in withdrawn:
            withdrawn_bytes += encode_prefix(addr, plen)

    nlri_bytes = b''
    if nlri_prefixes:
        for addr, plen in nlri_prefixes:
            nlri_bytes += encode_prefix(addr, plen)

    body = (struct.pack('!H', len(withdrawn_bytes)) + withdrawn_bytes +
            struct.pack('!H', len(path_attrs)) + path_attrs +
            nlri_bytes)
    return bgp_header(2, body)

def encode_path_attrs(next_hop_str, as_path_asns, origin=0):
    """Encode minimal path attributes: ORIGIN, AS_PATH, NEXT_HOP."""
    attrs = b''
    # ORIGIN (type 1, length 1)
    attrs += bytes([0x40, 1, 1, origin])  # TRANSITIVE, type=ORIGIN, len=1
    # AS_PATH (type 2, 4-byte ASNs)
    seg = bytes([2, len(as_path_asns)])   # AS_SEQUENCE, count
    for asn in as_path_asns:
        seg += struct.pack('!I', asn)
    attrs += bytes([0x40, 2, len(seg)]) + seg
    # NEXT_HOP (type 3, length 4)
    nh = bytes(int(x) for x in next_hop_str.split('.'))
    attrs += bytes([0x40, 3, 4]) + nh
    return attrs

# ── Start daemon ──────────────────────────────────────────────────────────────

try: os.remove(MGMT_SOCK)
except: pass

proc = subprocess.Popen(
    [BINARY, '--listen', f'127.0.0.1:{BGP_PORT}',
     '--local-as', '65001', '--router-id', '10.0.0.1',
     '--hold-time', '30', '--mgmt-socket', MGMT_SOCK],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
)
time.sleep(1.0)
check("Server starts", proc.poll() is None, "process exited early")

# ── BGP session handshake ─────────────────────────────────────────────────────

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
r = s.connect_ex(('127.0.0.1', BGP_PORT))
check("TCP connect", r == 0)

if r == 0:
    time.sleep(0.3)
    data = s.recv(4096)
    check("BGP marker valid", data[:16] == MARKER)
    check("OPEN message received", data[18] == 1)
    check("BGP version 4", data[19] == 4)
    check("AS 65001", struct.unpack('!H', data[20:22])[0] == 65001)
    check("Hold time 30", struct.unpack('!H', data[22:24])[0] == 30)
    bgp_id = '.'.join(str(b) for b in data[24:28])
    check("Router ID 10.0.0.1", bgp_id == '10.0.0.1')

    # Complete the OPEN exchange
    s.sendall(bgp_open(65002, 30, '10.0.0.2'))
    time.sleep(0.3)
    resp = s.recv(4096)
    check("KEEPALIVE received after OPEN", len(resp) >= 19 and resp[18] == 4)

    # Send our KEEPALIVE to complete the handshake → session reaches Established
    s.sendall(bgp_keepalive())
    time.sleep(0.3)

    # ── Route exchange ────────────────────────────────────────────────────────

    # Build an UPDATE announcing two prefixes
    path_attrs = encode_path_attrs(
        next_hop_str='10.0.0.2',
        as_path_asns=[65002, 65100],
        origin=0,  # IGP
    )
    update = bgp_update(
        path_attrs=path_attrs,
        nlri_prefixes=[('192.168.1.0', 24), ('10.99.0.0', 16)],
    )
    s.sendall(update)
    time.sleep(0.5)

    # Verify routes landed in the RIB via management socket
    m = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    m.settimeout(5)
    try:
        m.connect(MGMT_SOCK)
        time.sleep(0.2)
        m.recv(4096)  # consume banner

        def cmd(c):
            m.sendall((c + '\n').encode()); time.sleep(0.3)
            return m.recv(8192).decode(errors='replace')

        rib_out = cmd('show bgp rib')
        check("Route 192.168.1.0/24 in RIB", '192.168.1.0/24' in rib_out,
              f"RIB output: {rib_out[:200]}")
        check("Route 10.99.0.0/16 in RIB", '10.99.0.0/16' in rib_out,
              f"RIB output: {rib_out[:200]}")

        # Check RIB summary shows 2 prefixes
        summary = cmd('show bgp summary')
        check("Loc-RIB count >= 2", any(
            f'Loc-RIB: {n}' in summary for n in ['2', '3', '4', '5']
        ), f"summary: {summary[:200]}")

        # Test aspath filter
        aspath_out = cmd('show bgp rib aspath 65100')
        check("aspath filter finds 65100", '65100' in aspath_out,
              f"aspath output: {aspath_out[:200]}")

        # Test nexthop filter
        nh_out = cmd('show bgp rib nexthop 10.0.0.2')
        check("nexthop filter finds 10.0.0.2 routes", '192.168.1.0' in nh_out,
              f"nexthop output: {nh_out[:200]}")

        # Existing management command checks
        check("show bgp summary", 'Loc-RIB' in summary)
        check("show bgp metrics", 'Sessions' in cmd('show bgp metrics'))
        prom = cmd('metrics')
        check("Prometheus bgp_sessions_active", 'bgp_sessions_active' in prom)
        check("Prometheus # HELP", '# HELP' in prom)
        check("Prometheus routes_received > 0", 'bgp_routes_received_total 2' in prom)
        check("version command", 'PathForge' in cmd('version'))
        check("unknown command error", 'Unknown' in cmd('foobar'))
        m.close()
    except Exception as e:
        check("Management socket", False, str(e))

    # Send a withdrawal UPDATE and verify routes are removed
    withdraw = bgp_update(
        withdrawn=[('192.168.1.0', 24), ('10.99.0.0', 16)],
    )
    s.sendall(withdraw)
    time.sleep(0.5)

    m2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    m2.settimeout(5)
    try:
        m2.connect(MGMT_SOCK)
        time.sleep(0.2)
        m2.recv(4096)
        def cmd2(c):
            m2.sendall((c + '\n').encode()); time.sleep(0.3)
            return m2.recv(8192).decode(errors='replace')
        rib_after = cmd2('show bgp rib')
        check("Routes withdrawn from RIB",
              '192.168.1.0/24' not in rib_after and '10.99.0.0/16' not in rib_after,
              f"RIB still has routes: {rib_after[:200]}")
        m2.close()
    except Exception as e:
        check("Management socket (post-withdraw)", False, str(e))

    s.close()

# ── Management socket basic checks (no BGP session) ──────────────────────────

m3 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
m3.settimeout(5)
try:
    m3.connect(MGMT_SOCK)
    time.sleep(0.2)
    banner = m3.recv(4096).decode(errors='replace')
    check("Management banner", 'PathForge' in banner)
    m3.close()
except Exception as e:
    check("Management socket (standalone)", False, str(e))

# ── Teardown ──────────────────────────────────────────────────────────────────

proc.terminate()
proc.wait(timeout=5)

print()
if errors:
    print(f"FAILED: {len(errors)} check(s): {errors}")
    sys.exit(1)
else:
    print("All smoke tests passed! ✅")
