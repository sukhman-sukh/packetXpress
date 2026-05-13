#!/usr/bin/env bash
#
# demo_firewall.sh — Screenshot-friendly walkthrough of the LBVS XDP firewall.
#
# Each section is wrapped in a visible banner. Run it once on a Linux host
# (root, kernel >= 5.x with XDP), then scroll back and screenshot any
# section between its "=== MOMENT N ===" and "=== END MOMENT N ===" banners.
#
# What gets proved (in order):
#   1. XDP program is attached to the interface (kernel data path)
#   2. The LBVS pinned BPF maps exist (per-field bitvectors)
#   3. A DROP rule shows up in fw_rules + bitvector maps + drops traffic
#   4. Rule deletion restores traffic
#   5. Default DROP + explicit ACCEPT override (policy semantics)
#   6. First-match-wins priority across two overlapping rules
#
# Prereqs: build first --
#   cd packetXpress && make && cd xpx && go build -o packetXpress . && cd ..
#
set -uo pipefail

# ---- Colors & banners ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
NC='\033[0m'

banner_open() {
    local n="$1" title="$2"
    echo
    echo -e "${CYAN}${BOLD}==============================================================${NC}"
    echo -e "${CYAN}${BOLD} === MOMENT ${n}: ${title} ===${NC}"
    echo -e "${CYAN}${BOLD}==============================================================${NC}"
}
banner_close() {
    local n="$1"
    echo -e "${CYAN}${BOLD}--- END MOMENT ${n} -------------------------------------------${NC}"
    echo
}
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES+1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
cmd()  { echo -e "${BOLD}\$ $*${NC}"; "$@"; }

FAILURES=0
PXP_PID=""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="${SCRIPT_DIR}/xpx/packetXpress"
RULES_FILE="/tmp/packetxpress/firewall_rules.json"
BPF_DIR="/sys/fs/bpf/packetxpress"

cleanup() {
    echo
    info "Cleaning up demo environment..."
    [ -n "${PXP_PID}" ] && kill "${PXP_PID}" 2>/dev/null && wait "${PXP_PID}" 2>/dev/null || true
    ip link del veth_host 2>/dev/null || true
    ip netns del ns_client 2>/dev/null || true
    rm -f "$RULES_FILE"
    rm -rf "$BPF_DIR" 2>/dev/null || true
    info "Cleanup done."
}
trap cleanup EXIT

# ---- Pre-flight ----
if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (sudo $0)." ; exit 1
fi
if [ ! -x "$BIN" ]; then
    echo "Binary not found at $BIN"
    echo "Build first:  cd packetXpress && make && cd xpx && go build -o packetXpress . && cd .."
    exit 1
fi
if ! command -v bpftool >/dev/null 2>&1; then
    echo "bpftool not installed — install linux-tools or bpftool. Some moments need it."
fi

# ---- Stale state ----
cleanup 2>/dev/null || true

clear
echo -e "${BOLD}#####################################################################${NC}"
echo -e "${BOLD}#  packetXpress — LBVS XDP firewall demo                            #${NC}"
echo -e "${BOLD}#  Algorithm: Miano et al., 'Securing Linux with a Faster and       #${NC}"
echo -e "${BOLD}#  Scalable Iptables' (per-field bitvector AND + priority pick).    #${NC}"
echo -e "${BOLD}#####################################################################${NC}"
echo

# ---- Topology ----
info "Building test topology:  ns_client(10.0.0.2) <-veth-> host(10.0.0.1) [XDP firewall here]"
ip netns add ns_client
ip link add veth_host type veth peer name veth_client
ip link set veth_client netns ns_client
ip addr add 10.0.0.1/24 dev veth_host
ip link set veth_host up
ip netns exec ns_client ip addr add 10.0.0.2/24 dev veth_client
ip netns exec ns_client ip link set veth_client up
ip netns exec ns_client ip link set lo up
ip netns exec ns_client ip route add default via 10.0.0.1
sysctl -w net.ipv4.ip_forward=1 > /dev/null

info "Launching packetXpress in master mode on veth_host..."
cd "$SCRIPT_DIR"
"$BIN" --role master veth_host &
PXP_PID=$!
sleep 3
if ! kill -0 "$PXP_PID" 2>/dev/null; then
    fail "packetXpress did not start" ; exit 1
fi
"$BIN" fw local-ip --add 10.0.0.1 >/dev/null

# ====================================================================
banner_open 1 "XDP program is loaded into the kernel"
# ====================================================================
echo "Proves: the firewall classifier runs in XDP, not netfilter."
echo
cmd ip -d link show veth_host | sed -n '1,12p'
echo
if command -v bpftool >/dev/null 2>&1; then
    cmd bpftool prog show | grep -E "xdp|pxp" -A 1 || true
fi
banner_close 1

# ====================================================================
banner_open 2 "LBVS pinned bitvector maps exist"
# ====================================================================
echo "Proves: classification uses per-field bitvector hash maps,"
echo "not a linear iptables-style chain."
echo
cmd ls -la "$BPF_DIR" 2>/dev/null || true
echo
if command -v bpftool >/dev/null 2>&1; then
    echo -e "${BOLD}\$ bpftool map show | grep fw_${NC}"
    bpftool map show | grep fw_ || true
fi
banner_close 2

# ====================================================================
banner_open 3 "Add DROP rule and watch LBVS maps populate"
# ====================================================================
echo "Action: add INPUT rule  proto=icmp  action=drop."
echo "Proves: a rule materialises as bit-0 set in the proto bitvector"
echo "        and as an entry in fw_rules with priority + action."
echo

# Baseline ping (should succeed)
info "Baseline ping (no rule, default ACCEPT):"
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    pass "Ping succeeds (default ACCEPT)"
else
    fail "Baseline ping failed"
fi
echo

cmd "$BIN" fw add --chain INPUT --proto icmp --action drop
echo
cmd "$BIN" fw list
echo

if command -v bpftool >/dev/null 2>&1; then
    echo -e "${BOLD}\$ bpftool map dump name fw_rules${NC}"
    bpftool map dump name fw_rules 2>/dev/null | head -40 || true
    echo
    echo -e "${BOLD}\$ bpftool map dump name fw_proto_bv${NC}"
    bpftool map dump name fw_proto_bv 2>/dev/null | head -20 || true
fi
echo

info "Ping after DROP rule:"
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    fail "Ping should be dropped"
else
    pass "ICMP correctly dropped by rule 0"
fi
banner_close 3

# ====================================================================
banner_open 4 "Delete rule — traffic restored"
# ====================================================================
echo "Action: fw del --id 0."
echo "Proves: removing a rule clears its bit; the data plane reacts live."
echo
cmd "$BIN" fw del --id 0
echo
cmd "$BIN" fw list
echo
info "Ping after deletion:"
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    pass "Ping restored"
else
    fail "Ping should work again after rule deletion"
fi
banner_close 4

# ====================================================================
banner_open 5 "Default-DENY policy + explicit ACCEPT override"
# ====================================================================
echo "Proves: policy is the fall-through after LBVS AND/priority pick,"
echo "        and explicit ACCEPT for ICMP overrides a DROP default."
echo
cmd "$BIN" fw policy --chain INPUT --action drop
echo
cmd "$BIN" fw list
echo
info "Ping under default DROP (no rules):"
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    fail "Ping should be dropped by default policy"
else
    pass "Default DROP policy blocks ICMP"
fi
echo
cmd "$BIN" fw add --chain INPUT --proto icmp --action accept
echo
info "Ping with explicit ICMP ACCEPT rule on top of default DROP:"
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    pass "Explicit ACCEPT overrides default DROP"
else
    fail "Explicit ACCEPT should override"
fi
banner_close 5

# ====================================================================
banner_open 6 "Priority — first match wins across overlapping rules"
# ====================================================================
echo "Setup: rule 0 = DROP from 10.0.0.2 (specific)."
echo "       rule 1 = ACCEPT proto icmp  (broad, lower priority)."
echo "Proves: after the bitwise AND, LBVS picks the lowest-index set bit,"
echo "        so rule 0 wins over rule 1 even though both match."
echo

# Reset state
"$BIN" fw del --id 0 2>/dev/null || true
"$BIN" fw policy --chain INPUT --action accept >/dev/null

cmd "$BIN" fw add --chain INPUT --src-ip 10.0.0.2 --action drop
cmd "$BIN" fw add --chain INPUT --proto icmp --action accept
echo
cmd "$BIN" fw list
echo

if command -v bpftool >/dev/null 2>&1; then
    echo -e "${BOLD}\$ bpftool map dump name fw_src_ip_bv${NC}"
    bpftool map dump name fw_src_ip_bv 2>/dev/null | head -20 || true
    echo
    echo -e "${BOLD}\$ bpftool map dump name fw_proto_bv${NC}"
    bpftool map dump name fw_proto_bv 2>/dev/null | head -20 || true
fi
echo

info "Ping from 10.0.0.2 (matches both rule 0 DROP and rule 1 ACCEPT):"
if ip netns exec ns_client ping -c 2 -W 2 10.0.0.1 > /dev/null 2>&1; then
    fail "DROP (rule 0) should beat ACCEPT (rule 1)"
else
    pass "Priority correct: rule 0 (DROP) wins over rule 1 (ACCEPT)"
fi
banner_close 6

# ---- Reset to clean state ----
"$BIN" fw del --id 1 2>/dev/null || true
"$BIN" fw del --id 0 2>/dev/null || true
"$BIN" fw policy --chain INPUT --action accept 2>/dev/null || true

echo
echo -e "${BOLD}#####################################################################${NC}"
if [ "$FAILURES" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}#  DEMO COMPLETE — all 6 moments produced expected output           #${NC}"
else
    echo -e "${RED}${BOLD}#  DEMO FINISHED with ${FAILURES} failed assertion(s)                          #${NC}"
fi
echo -e "${BOLD}#####################################################################${NC}"
echo
echo "Screenshot guide:"
echo "  Moment 1 — XDP attached  (ip -d link show + bpftool prog show)"
echo "  Moment 2 — LBVS maps     (ls of /sys/fs/bpf/packetxpress + bpftool map show)"
echo "  Moment 3 — rule add      (fw list + bpftool map dump + dropped ping)"
echo "  Moment 4 — rule delete   (fw list empty + ping restored)"
echo "  Moment 5 — default DENY  (DROP policy + explicit ACCEPT override)"
echo "  Moment 6 — priority      (rule 0 DROP beats rule 1 ACCEPT)"
echo

exit "$FAILURES"
