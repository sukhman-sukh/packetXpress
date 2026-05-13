#!/usr/bin/env python3
"""Plot Maglev build time vs backend count from go test bench output."""
import re
import sys
from collections import defaultdict

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib not installed; skip plot.", file=sys.stderr)
    sys.exit(0)

# BenchmarkMaglevBuild/Backends128-12         	   50000	     25000 ns/op
BUILD_RE = re.compile(
    r"^BenchmarkMaglevBuild/Backends(?P<n>\d+)-\d+\s+\d+\s+(?P<ns>[\d.]+)\s+ns/op"
)


def parse(path):
    by_n = defaultdict(list)
    with open(path) as f:
        for line in f:
            m = BUILD_RE.match(line.strip())
            if not m:
                continue
            by_n[int(m.group("n"))].append(float(m.group("ns")))
    return by_n


def median(vals):
    s = sorted(vals)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def main():
    if len(sys.argv) < 3:
        print("usage: plot_lb.py <bench_output.txt> <out.png>", file=sys.stderr)
        sys.exit(1)
    inp, outp = sys.argv[1], sys.argv[2]
    by_n = parse(inp)
    if not by_n:
        print("no BenchmarkMaglevBuild lines matched", file=sys.stderr)
        sys.exit(1)
    xs = sorted(by_n)
    ys = [median(by_n[x]) for x in xs]

    plt.figure(figsize=(8, 5))
    plt.plot(xs, ys, marker="o", color="C0")
    plt.xlabel("Number of backends")
    plt.ylabel("ns/op (median) — full Maglev table rebuild")
    plt.title("LB control plane: Maglev BuildMaglev (table size prime ≈ 65537)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(outp, dpi=150)
    print(outp)


if __name__ == "__main__":
    main()
