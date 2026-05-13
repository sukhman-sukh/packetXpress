#!/usr/bin/env bash
# Load-balancer control-plane micro-benchmarks (Maglev table build, per-flow hash, lookup).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
XPX="$ROOT/xpx"
OUT="${OUT:-$ROOT/scripts/bench/out}"
mkdir -p "$OUT"

if ! command -v go >/dev/null 2>&1; then
  echo "go not found in PATH" >&2
  exit 1
fi

export GOTOOLCHAIN="${GOTOOLCHAIN:-auto}"

cd "$XPX"
STAMP="$(date +%Y%m%d-%H%M%S)"
RAW="$OUT/lb_bench_${STAMP}.txt"

echo "Writing $RAW"
go test ./utils -bench='BenchmarkMaglev|BenchmarkHash5Tuple' -benchmem -count=5 -run='^$' | tee "$RAW"

if command -v benchstat >/dev/null 2>&1; then
  benchstat "$RAW" | tee "$OUT/lb_bench_${STAMP}_summary.txt"
else
  echo "Install benchstat for summary: go install golang.org/x/perf/cmd/benchstat@latest"
fi

if command -v python3 >/dev/null 2>&1; then
  python3 "$ROOT/scripts/bench/plot_lb.py" "$RAW" "$OUT/lb_maglev_${STAMP}.png" || true
fi

echo "Done."
