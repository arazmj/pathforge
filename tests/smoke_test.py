#!/usr/bin/env python3
"""Smoke test: start pathforge, verify BGP session handshake + management commands."""
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

def bgp_open(my_as, hold_time, bgp_id_str):
    marker = b'\xff' * 16
    id_bytes = bytes(int(x) for x in bgp_id_str.split('.'))
    body = bytes([4]) + struct.pack('!HH', my_as, hold_time) + id_bytes + b'\x00'
    length = 19 + len(body)
    return marker + struct.pack('!HB', length, 1) + body

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

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
r = s.connect_ex(('127.0.0.1', BGP_PORT))
check("TCP connect", r == 0)
if r == 0:
    time.sleep(0.3)
    data = s.recv(4096)
    check("BGP marker valid", data[:16] == b'\xff'*16)
    check("OPEN message received", data[18] == 1)
    check("BGP version 4", data[19] == 4)
    check("AS 65001", struct.unpack('!H', data[20:22])[0] == 65001)
    check("Hold time 30", struct.unpack('!H', data[22:24])[0] == 30)
    bgp_id = '.'.join(str(b) for b in data[24:28])
    check("Router ID 10.0.0.1", bgp_id == '10.0.0.1')
    s.sendall(bgp_open(65002, 30, '10.0.0.2'))
    time.sleep(0.3)
    resp = s.recv(4096)
    check("KEEPALIVE received", len(resp) >= 19 and resp[18] == 4)
    s.close()

m = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
m.settimeout(5)
try:
    m.connect(MGMT_SOCK)
    time.sleep(0.2)
    banner = m.recv(4096).decode(errors='replace')
    check("Management banner", 'PathForge' in banner)

    def cmd(c):
        m.sendall((c + '\n').encode()); time.sleep(0.2)
        return m.recv(8192).decode(errors='replace')

    check("show bgp summary", 'Loc-RIB' in cmd('show bgp summary'))
    check("show bgp rib", 'empty' in cmd('show bgp rib').lower())
    check("show bgp metrics", 'Sessions' in cmd('show bgp metrics'))
    prom = cmd('metrics')
    check("Prometheus bgp_sessions_active", 'bgp_sessions_active' in prom)
    check("Prometheus # HELP", '# HELP' in prom)
    check("unknown command error", 'Unknown' in cmd('foobar'))
    m.close()
except Exception as e:
    check("Management socket", False, str(e))

proc.terminate()
proc.wait(timeout=5)

print()
if errors:
    print(f"FAILED: {len(errors)} check(s): {errors}")
    sys.exit(1)
else:
    print("All smoke tests passed! ✅")
