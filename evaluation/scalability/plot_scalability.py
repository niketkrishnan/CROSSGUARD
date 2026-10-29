"""Regenerates figures/scalability.pdf from scale_sweep_results_fresh.csv.
Usage: python3 plot_scalability.py evaluation/scalability/scale_sweep_results_fresh.csv scalability.pdf
Fit: least squares on log10(mean time) vs log10(nodes) over the 11 size means."""
import csv, math, sys, statistics as st, collections
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

src = sys.argv[1] if len(sys.argv) > 1 else "scale_sweep_results_fresh.csv"
out = sys.argv[2] if len(sys.argv) > 2 else "scalability.pdf"

by = collections.defaultdict(list)
for r in csv.DictReader(open(src)):
    by[int(r["nodes"])].append(float(r["seconds"]))
ns = sorted(by)
means = [st.mean(by[n]) for n in ns]
sds = [st.stdev(by[n]) for n in ns]

xs = [math.log10(n) for n in ns]
ys = [math.log10(m) for m in means]
k = len(xs); mx = sum(xs) / k; my = sum(ys) / k
slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
icpt = my - slope * mx
r2 = 1 - sum((y - (icpt + slope * x)) ** 2 for x, y in zip(xs, ys)) / sum((y - my) ** 2 for y in ys)
print("slope=%.4f intercept=%.4f R2=%.5f" % (slope, icpt, r2))

plt.rcParams.update({"font.family": "serif", "mathtext.fontset": "stix", "font.size": 7,
                     "axes.labelsize": 7, "legend.fontsize": 6, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5})
fig, ax = plt.subplots(figsize=(2.5, 1.75))
xf = [ns[0], ns[-1]]
ax.plot(xf, [10 ** (icpt + slope * math.log10(x)) for x in xf], "--", color="#c00000", lw=1,
        label="Fit: slope %.2f, $R^2$ = %.3f" % (slope, r2))
ax.errorbar(ns, means, yerr=sds, fmt="o", ms=2.8, color="#1f4e79", ecolor="#1f4e79", elinewidth=0.7,
            capsize=1.5, label="Measured (mean $\\pm$ s.d.)")
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("Graph size (nodes)"); ax.set_ylabel("Pathfinding time (s)")
ax.grid(True, which="both", color="#cccccc", lw=0.3, ls=":")
ax.legend(loc="upper left", frameon=True, framealpha=0.95, borderpad=0.4, handlelength=1.8)
fig.tight_layout(pad=0.3)
fig.savefig(out)
