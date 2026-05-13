#!/usr/bin/env bash
# Run micro-benchmarks for firewall classification (userspace models).
#
# Compares:
#   - Linear scan (iptables-style ordered rules, worst case = last rule matches)
#   - 4-level octet trie on dst IPv4 + linear scan at leaf (BPF-style hierarchical lookup)
#   - LBVS bitvector AND + priority (this project's XDP firewall algorithm)
#
# For real kernel packet rates (iptables vs XDP), use pktgen, TRex, or iperf with
# identical rulesets on a test NIC — this script only measures classification CPU.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
XPX="$ROOT/xpx"
OUT="${OUT:-$ROOT/scripts/bench/out}"
mkdir -p "$OUT"

if ! command -v go >/dev/null 2>&1; then
  echo "go not found in PATH" >&2
  exit 1
fi

# go.mod may require a newer toolchain than the host (e.g. 1.25.x); download if needed.
export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

cd "$XPX"
STAMP="$(date +%Y%m%d-%H%M%S)"
RAW="$OUT/firewall_bench_${STAMP}.txt"

echo "Writing $RAW"
go test ./core -bench='BenchmarkFW_' -benchmem -count=5 -run='^$' | tee "$RAW"

if command -v benchstat >/dev/null 2>&1; then
  benchstat "$RAW" | tee "$OUT/firewall_bench_${STAMP}_summary.txt"
else
  echo "Install golang.org/x/perf/cmd/benchstat for statistical summary: go install golang.org/x/perf/cmd/benchstat@latest"
fi

if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/scripts/bench/plot_firewall.py" "$RAW" "$OUT/firewall_classify_${STAMP}.png" || true
fi

echo "Done."
