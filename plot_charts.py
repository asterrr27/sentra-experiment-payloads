"""
Generate publication-quality charts from experiment results.

Produces (PNG + PDF for each):
  - pass_rate_by_scenario
  - owasp_pass_rate
  - failure_heatmap
  - latency_boxplot
  - pass_rate_by_scenario_individual  (one chart per agent)

Saved to results/figures/
"""

import json
import os
from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 13,
    "axes.titlesize": 14,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 10,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "savefig.bbox": "tight",
})

RESULTS_DIR = "results"
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")
AGENTS = ["A", "B", "C", "D", "E"]
AGENT_LABELS = {"A": "Agent A (Weak)", "B": "Agent B (Medium)", "C": "Agent C (Strong)",
                "D": "Agent D (Gemma)", "E": "Agent E (GPT-4o-mini)"}
AGENT_SHORT = {"A": "A (Weak)", "B": "B (Medium)", "C": "C (Strong)",
               "D": "D (Gemma)", "E": "E (GPT-4o-mini)"}
AGENT_COLORS = {"A": "#e74c3c", "B": "#f39c12", "C": "#2ecc71", "D": "#3498db", "E": "#9b59b6"}
AGENT_HATCH = {"A": "///", "B": "\\\\", "C": "xx", "D": "..", "E": "--"}


def load_results(agent_label):
    path = os.path.join(RESULTS_DIR, f"agent_{agent_label}_results.json")
    if not os.path.exists(path):
        print(f"  Warning: {path} not found")
        return None
    with open(path) as f:
        return json.load(f)


def compute_scenario_pass_rates(data):
    results = data.get("results", [])
    by_scenario = defaultdict(lambda: {"pass": 0, "total": 0})
    for r in results:
        s = r["scenario"]
        by_scenario[s]["total"] += 1
        if r["result"] == "PASS":
            by_scenario[s]["pass"] += 1
    rates = {}
    for s, v in sorted(by_scenario.items()):
        rates[s] = round(v["pass"] / v["total"] * 100, 1)
    return rates


def compute_owasp_pass_rates(data):
    results = data.get("results", [])
    by_owasp = defaultdict(lambda: {"pass": 0, "total": 0})
    for r in results:
        o = r["owasp_category"]
        by_owasp[o]["total"] += 1
        if r["result"] == "PASS":
            by_owasp[o]["pass"] += 1
    rates = {}
    for o, v in sorted(by_owasp.items()):
        rates[o] = round(v["pass"] / v["total"] * 100, 1)
    return rates


def _save_figure(fig, name):
    for ext in [".png", ".pdf"]:
        path = os.path.join(FIGURES_DIR, name + ext)
        fig.savefig(path)
        print(f"  Saved: {path}")


def plot_pass_rate_by_scenario(all_data):
    scenario_names = sorted(set(
        r["scenario"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    x = np.arange(len(scenario_names))
    width = 0.25

    fig, ax = plt.subplots(figsize=(14, 6))
    for i, label in enumerate(AGENTS):
        data = all_data.get(label)
        rates = compute_scenario_pass_rates(data) if data else {}
        values = [rates.get(s, 0) for s in scenario_names]
        bars = ax.bar(x + i * width, values, width, label=AGENT_SHORT[label],
                      color=AGENT_COLORS[label], edgecolor="black", linewidth=0.5)
        for bar, v in zip(bars, values):
            if v > 0 and v < 100:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                        f"{v:.0f}", ha="center", va="bottom", fontsize=6, rotation=90)

    ax.set_xlabel("Attack Scenario", fontsize=13)
    ax.set_ylabel("Pass Rate (%)", fontsize=13)
    ax.set_xticks(x + width)
    ax.set_xticklabels(scenario_names, rotation=45, ha="right", fontsize=9)
    ax.set_ylim(0, 115)
    ax.legend(fontsize=10, loc="upper right")
    ax.axhline(y=70, color="green", linestyle="--", alpha=0.4, linewidth=1)
    ax.axhline(y=40, color="orange", linestyle="--", alpha=0.3, linewidth=1)
    ax.grid(axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    plt.tight_layout()
    _save_figure(fig, "pass_rate_by_scenario")
    plt.close(fig)


def plot_pass_rate_by_scenario_individual(all_data):
    scenario_names = sorted(set(
        r["scenario"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    n = len(AGENTS)
    ncols = 3
    nrows = (n + ncols - 1) // ncols
    fig, axes = plt.subplots(nrows, ncols, figsize=(6 * ncols, 4 * nrows), sharey=True)
    axes_flat = axes.flatten() if n > 1 else [axes]
    for idx, label in enumerate(AGENTS):
        ax = axes_flat[idx]
        data = all_data.get(label)
        rates = compute_scenario_pass_rates(data) if data else {}
        values = [rates.get(s, 0) for s in scenario_names]
        colors = [AGENT_COLORS[label]] * len(scenario_names)
        bars = ax.barh(range(len(scenario_names)), values, color=colors, edgecolor="black",
                       height=0.6, alpha=0.85)
        ax.set_yticks(range(len(scenario_names)))
        ax.set_yticklabels(scenario_names if idx == 0 else [], fontsize=8)
        ax.set_xlim(0, 105)
        ax.set_xlabel("Pass Rate (%)", fontsize=11)
        ax.set_title(f"Agent {AGENT_SHORT[label]}", fontsize=12)
        ax.axvline(x=70, color="green", linestyle="--", alpha=0.4, linewidth=0.8)
        ax.axvline(x=40, color="orange", linestyle="--", alpha=0.3, linewidth=0.8)
        ax.grid(axis="x", alpha=0.3)
        ax.set_axisbelow(True)
        for bar, v in zip(bars, values):
            if v > 0:
                ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height() / 2,
                        f"{v:.0f}%", ha="left", va="center", fontsize=7)

    for j in range(idx + 1, len(axes_flat)):
        axes_flat[j].set_visible(False)

    plt.tight_layout()
    _save_figure(fig, "pass_rate_by_scenario_individual")
    plt.close(fig)


def plot_owasp_pass_rate(all_data):
    owasp_categories = sorted(set(
        r["owasp_category"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    x = np.arange(len(owasp_categories))
    width = 0.25

    fig, ax = plt.subplots(figsize=(9, 5.5))
    for i, label in enumerate(AGENTS):
        data = all_data.get(label)
        rates = compute_owasp_pass_rates(data) if data else {}
        values = [rates.get(o, 0) for o in owasp_categories]
        bars = ax.bar(x + i * width, values, width, label=AGENT_SHORT[label],
                      color=AGENT_COLORS[label], edgecolor="black", linewidth=0.5)
        for bar, v in zip(bars, values):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                        f"{v:.0f}", ha="center", va="bottom", fontsize=8)

    ax.set_xlabel("OWASP LLM Top 10 Category", fontsize=13)
    ax.set_ylabel("Pass Rate (%)", fontsize=13)
    ax.set_xticks(x + width)
    ax.set_xticklabels(owasp_categories, fontsize=10)
    ax.set_ylim(0, 115)
    ax.legend(fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    plt.tight_layout()
    _save_figure(fig, "owasp_pass_rate")
    plt.close(fig)


def plot_failure_heatmap(all_data):
    scenarios = sorted(set(
        r["scenario"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    failure_types = sorted(set(
        r["failure_type"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))

    n_scenarios = len(scenarios)
    n_types = len(failure_types)
    matrix = np.zeros((n_scenarios, n_types))
    for i, s in enumerate(scenarios):
        for j, ft in enumerate(failure_types):
            count = 0
            for label in AGENTS:
                data = all_data.get(label)
                if data:
                    count += sum(
                        1 for r in data["results"]
                        if r["scenario"] == s and r["failure_type"] == ft
                    )
            matrix[i][j] = count

    fig, ax = plt.subplots(figsize=(10, 7))
    cmap = sns.color_palette("YlOrRd", as_cmap=True)
    sns.heatmap(matrix, annot=True, fmt=".0f", cmap=cmap,
                xticklabels=failure_types, yticklabels=scenarios,
                ax=ax, cbar_kws={"label": "Failure Count (All Agents)"},
                linewidths=0.5, linecolor="white")

    ax.set_xlabel("Failure Type", fontsize=12)
    ax.set_ylabel("Attack Scenario", fontsize=12)
    ax.set_title("Failure Type Heatmap", fontsize=13, fontweight="bold")
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right", fontsize=9)
    plt.setp(ax.get_yticklabels(), fontsize=9)

    plt.tight_layout()
    _save_figure(fig, "failure_heatmap")
    plt.close(fig)


def plot_latency_boxplot(all_data):
    fig, ax = plt.subplots(figsize=(7, 5))
    positions = []
    labels = []

    for i, label in enumerate(AGENTS):
        data = all_data.get(label)
        if data:
            latencies = [r["response_latency_ms"] for r in data.get("results", [])]
            bp = ax.boxplot(latencies, positions=[i], widths=0.5, patch_artist=True)
            bp["boxes"][0].set_facecolor(AGENT_COLORS[label])
            bp["boxes"][0].set_alpha(0.7)
            bp["boxes"][0].set_edgecolor("black")
            bp["medians"][0].set_color("black")
            bp["medians"][0].set_linewidth(2)
            bp["whiskers"][0].set_color("black")
            bp["whiskers"][1].set_color("black")
            bp["caps"][0].set_color("black")
            bp["caps"][1].set_color("black")
            positions.append(i)
            labels.append(AGENT_SHORT[label])

    ax.set_xlabel("Agent Security Posture", fontsize=13)
    ax.set_ylabel("Response Latency (ms)", fontsize=13)
    ax.set_title("Response Latency Distribution by Agent", fontsize=13, fontweight="bold")
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, fontsize=10)
    ax.grid(axis="y", alpha=0.3)
    ax.set_axisbelow(True)

    plt.tight_layout()
    _save_figure(fig, "latency_boxplot")
    plt.close(fig)


def main():
    print("\n" + "=" * 60)
    print("  Sentra Experiment — Chart Generator")
    print("=" * 60 + "\n")

    os.makedirs(FIGURES_DIR, exist_ok=True)

    all_data = {}
    for label in AGENTS:
        all_data[label] = load_results(label)
        if all_data[label]:
            print(f"  Agent {label}: {len(all_data[label].get('results', []))} records loaded")
        else:
            print(f"  Agent {label}: not found")

    available = [l for l, d in all_data.items() if d is not None]
    if not available:
        print("  Error: No results found. Run experiment_runner.py first.")
        return

    print()
    plot_pass_rate_by_scenario(all_data)
    plot_pass_rate_by_scenario_individual(all_data)
    plot_owasp_pass_rate(all_data)
    plot_failure_heatmap(all_data)
    plot_latency_boxplot(all_data)

    print(f"\n  Done. All charts saved to {FIGURES_DIR}/\n")


if __name__ == "__main__":
    main()
