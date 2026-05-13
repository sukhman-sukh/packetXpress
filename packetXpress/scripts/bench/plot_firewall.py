#!/usr/bin/env python3
"""Parse go test -bench output for BenchmarkFW_* and plot ns/op vs rule count."""
import re
import sys
from collections import defaultdict

try:
    import matplotlib.pyplot as plt
except ImportError:
    print("matplotlib not installed; skip plot. pip install matplotlib", file=sys.stderr)
    sys.exit(0)

# BenchmarkFW_Linear_LastMatch/Rules64-12          10000000       105.3 ns/op
LINE_RE = re.compile(
    r"^BenchmarkFW_(?P<algo>Linear|TrieOct|LBVS)_(?P<kind>\w+)/Rules(?P<n>\d+)-\d+\s+\d+\s+(?P<ns>[\d.]+)\s+ns/op"
)


def want_plot(key):
    return key[1] == "LastMatch"


def parse(path):
    series = defaultdict(dict)  # (algo, kind) -> n -> ns list
    with open(path) as f:
        for line in f:
            m = LINE_RE.match(line.strip())
            if not m:
                continue
            key = (m.group("algo"), m.group("kind"))
            n = int(m.group("n"))
            ns = float(m.group("ns"))
            if n not in series[key]:
                series[key][n] = []
            series[key][n].append(ns)
    return series


def median(vals):
    s = sorted(vals)
    mid = len(s) // 2
    return s[mid] if len(s) % 2 else (s[mid - 1] + s[mid]) / 2


def main():
    if len(sys.argv) < 3:
        print("usage: plot_firewall.py <bench_output.txt> <out.png>", file=sys.stderr)
        sys.exit(1)
    inp, outp = sys.argv[1], sys.argv[2]
    series = parse(inp)
    if not series:
        print("no BenchmarkFW_ lines matched", file=sys.stderr)
        sys.exit(1)

    plt.figure(figsize=(9, 5))
    styles = {
        ("Linear", "LastMatch"): ("iptables-style linear", "C0"),
        ("TrieOct", "LastMatch"): ("dst IPv4 octet trie + leaf", "C1"),
        ("LBVS", "LastMatch"): ("LBVS (this project)", "C2"),
    }
    for (algo, kind), by_n in sorted(series.items()):
        if not want_plot((algo, kind)):
            continue
        label = styles.get((algo, kind), (f"{algo}/{kind}", "C3"))
        if isinstance(label, tuple):
            label, color = label
        else:
            color = None
        xs = sorted(by_n)
        ys = [median(by_n[x]) for x in xs]
        plt.plot(xs, ys, marker="o", label=label, color=color)

    plt.xlabel("Number of rules (worst case: last rule matches)")
    plt.ylabel("ns/op (median over runs)")
    plt.title("Firewall classification (userspace model)")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.xscale("log", base=2)
    plt.tight_layout()
    plt.savefig(outp, dpi=150)
    print(outp)


if __name__ == "__main__":
    main()
