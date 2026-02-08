#!/usr/bin/env bash
#
# test_firewall.sh — Integration test for the LBVS-based XDP firewall
#
# Prerequisites:
#   - Linux with kernel >= 5.x (XDP support)
#   - Root privileges (sudo)
#   - Build completed: make && cd xpx && go build -o packetXpress .
#
# This script:
#   1. Creates network namespaces + veth pairs
#   2. Starts packetXpress in master mode
#   3. Tests INPUT chain (DROP/ACCEPT) and FORWARD chain (redirect)
#   4. Cleans up everything on exit
#
set -euo pipefail

# ---- Color helpers ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

FAILURES=0
PXP_PID=""

# ---- Paths ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${SCRIPT_DIR}/xpx/packetXpress"
RULES_FILE="/tmp/packetxpress/firewall_rules.json"

# ---- Cleanup ----
cleanup() {
    info "Cleaning up..."
    [ -n "$PXP_PID" ] && kill "$PXP_PID" 2>/dev/null && wait "$PXP_PID" 2>/dev/null || true
    ip link del veth_host 2>/dev/null || true
    ip link del veth_fwd0 2>/dev/null || true
    ip netns del ns_client 2>/dev/null || true
    ip netns del ns_server 2>/dev/null || true
    rm -f "$RULES_FILE"
    # Unpin BPF maps
    rm -rf /sys/fs/bpf/packetxpress 2>/dev/null || true
    info "Cleanup done."
}
trap cleanup EXIT

# ---- Pre-flight checks ----
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (sudo)."
    exit 1
fi

if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN"
    echo "Build first:  cd xpx && go build -o packetXpress . && cd .."
    exit 1
fi

# ---- Remove stale state ----
cleanup 2>/dev/null || true

echo "============================================"
echo "  packetXpress Firewall Test Suite (LBVS)"
echo "============================================"
echo

# ================================================================
# TEST SETUP: Create namespaces and veth pairs
#
#  ns_client (10.0.0.2) <--veth--> host (10.0.0.1) = DUT with firewall
#
#  For FORWARD tests:
#  ns_client (10.0.0.2) <--veth_host--> host <--veth_fwd0--> ns_server (10.0.1.2)
# ================================================================

info "Creating network namespaces and veth pairs..."

# Client namespace + veth
ip netns add ns_client
ip link add veth_host type veth peer name veth_client
ip link set veth_client netns ns_client

ip addr add 10.0.0.1/24 dev veth_host
ip link set veth_host up
ip netns exec ns_client ip addr add 10.0.0.2/24 dev veth_client
ip netns exec ns_client ip link set veth_client up
ip netns exec ns_client ip link set lo up

# Server namespace + veth (for FORWARD tests)
ip netns add ns_server
ip link add veth_fwd0 type veth peer name veth_srv
ip link set veth_srv netns ns_server

ip addr add 10.0.1.1/24 dev veth_fwd0
ip link set veth_fwd0 up
ip netns exec ns_server ip addr add 10.0.1.2/24 dev veth_srv
ip netns exec ns_server ip link set veth_srv up
ip netns exec ns_server ip link set lo up

# Enable forwarding on host
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Default route in client namespace → host
ip netns exec ns_client ip route add default via 10.0.0.1

info "Network setup complete."
echo

# ================================================================
# START PACKETXPRESS
# ================================================================

info "Starting packetXpress on veth_host..."
cd "$SCRIPT_DIR"
"$BIN" --role master veth_host &
PXP_PID=$!
sleep 3

if ! kill -0 "$PXP_PID" 2>/dev/null; then
    fail "packetXpress failed to start"
    exit 1
fi
info "packetXpress running (PID=$PXP_PID)"

# Register the host IP as local (for chain selection)
"$BIN" fw local-ip --add 10.0.0.1
"$BIN" fw local-ip --add 10.0.1.1
echo

# ================================================================
# TEST 1: Default ACCEPT policy — ping should work
# ================================================================
info "TEST 1: Default ACCEPT policy (ping from client to host)"
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    pass "Ping works with default ACCEPT"
else
    fail "Ping failed with default ACCEPT"
fi
echo

# ================================================================
# TEST 2: INPUT DROP rule — drop ICMP
# ================================================================
info "TEST 2: Add INPUT rule to DROP ICMP"
"$BIN" fw add --chain INPUT --proto icmp --action drop
"$BIN" fw list
echo

if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    fail "Ping should have been dropped by ICMP rule"
else
    pass "ICMP correctly dropped by INPUT rule"
fi
echo

# ================================================================
# TEST 3: Delete the ICMP DROP rule — ping should work again
# ================================================================
info "TEST 3: Delete ICMP drop rule (ID 0)"
"$BIN" fw del --id 0
echo

if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    pass "Ping restored after rule deletion"
else
    fail "Ping should work after deleting the drop rule"
fi
echo

# ================================================================
# TEST 4: INPUT rule — drop TCP to port 80
# ================================================================
info "TEST 4: Add INPUT rule to DROP TCP port 80"
"$BIN" fw add --chain INPUT --proto tcp --dst-port 80 --action drop
"$BIN" fw list
echo

# Start a simple TCP listener on port 80 on the host
python3 -c "
import socket, threading, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.0.0.1', 80))
s.listen(1)
s.settimeout(10)
try:
    conn, addr = s.accept()
    conn.close()
except:
    pass
s.close()
" &
LISTENER_PID=$!
sleep 1

# Try connecting from client namespace
if ip netns exec ns_client bash -c "echo | nc -w 2 10.0.0.1 80" > /dev/null 2>&1; then
    fail "TCP to port 80 should have been dropped"
else
    pass "TCP to port 80 correctly dropped"
fi

kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true

# TCP to other ports should still work (e.g., port 8080)
info "  Verify TCP to port 8080 still works (not blocked)"
python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('10.0.0.1', 8080))
s.listen(1)
s.settimeout(5)
try:
    conn, addr = s.accept()
    conn.sendall(b'OK')
    conn.close()
except:
    pass
s.close()
" &
LISTENER_PID=$!
sleep 1

if ip netns exec ns_client bash -c "echo | nc -w 2 10.0.0.1 8080" > /dev/null 2>&1; then
    pass "TCP to port 8080 allowed (not affected by port 80 rule)"
else
    fail "TCP to port 8080 should not be blocked"
fi

kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
echo

# ================================================================
# TEST 5: Set default policy to DROP
# ================================================================
info "TEST 5: Set INPUT default policy to DROP"
"$BIN" fw del --id 0  # remove port 80 rule first
"$BIN" fw policy --chain INPUT --action drop
echo

if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    fail "Ping should be dropped by default DROP policy"
else
    pass "Default DROP policy works"
fi

# Add an explicit ACCEPT rule for ICMP
info "  Add ACCEPT rule for ICMP"
"$BIN" fw add --chain INPUT --proto icmp --action accept
echo

if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    pass "ICMP allowed by explicit ACCEPT rule despite DROP default"
else
    fail "ICMP should be allowed by explicit ACCEPT rule"
fi
echo

# ================================================================
# TEST 6: Multiple rules — priority ordering
# ================================================================
info "TEST 6: Multiple rules with priority (first match wins)"
"$BIN" fw del --id 0  # clear
"$BIN" fw policy --chain INPUT --action accept  # restore default
# Rule 0: DROP all from 10.0.0.2
"$BIN" fw add --chain INPUT --src-ip 10.0.0.2 --action drop
# Rule 1: ACCEPT ICMP (lower priority)
"$BIN" fw add --chain INPUT --proto icmp --action accept
"$BIN" fw list
echo

# Rule 0 (DROP from 10.0.0.2) has higher priority than rule 1 (ACCEPT ICMP)
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    fail "DROP rule (ID 0) should take priority over ACCEPT rule (ID 1)"
else
    pass "Priority ordering correct: DROP (rule 0) beats ACCEPT (rule 1)"
fi
echo

# ================================================================
# CLEANUP & SUMMARY
# ================================================================
# Clear all rules for clean state
"$BIN" fw del --id 1 2>/dev/null || true
"$BIN" fw del --id 0 2>/dev/null || true
"$BIN" fw policy --chain INPUT --action accept 2>/dev/null || true

echo "============================================"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "  ${GREEN}ALL TESTS PASSED${NC}"
else
    echo -e "  ${RED}${FAILURES} TEST(S) FAILED${NC}"
fi
echo "============================================"

exit "$FAILURES"
