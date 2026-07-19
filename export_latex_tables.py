"""
Export LaTeX tables for IEEE paper from experiment results.

Reads results/agent_{A,B,C}_results.json and results/paper_stats.json
Generates .tex files in results/tables/
"""

import json
import os
from collections import defaultdict

RESULTS_DIR = "results"
TABLES_DIR = os.path.join(RESULTS_DIR, "tables")
AGENTS = ["A", "B", "C", "D", "E"]
POSTURES = {"A": "Weak", "B": "Medium", "C": "Strong", "D": "Gemma-4-31b", "E": "GPT-4o-mini"}


def load_results(label):
    path = os.path.join(RESULTS_DIR, f"agent_{label}_results.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def load_paper_stats():
    path = os.path.join(RESULTS_DIR, "paper_stats.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def esc(text):
    """Escape LaTeX special characters."""
    return text.replace("%", "\\%").replace("_", "\\_").replace("&", "\\&").replace("#", "\\#")


def make_table_overall(stats):
    rows = []
    rows.append(r"\begin{table}[ht]")
    rows.append(r"\centering")
    rows.append(r"\caption{Overall Experiment Results by Agent Security Posture}")
    rows.append(r"\label{tab:overall}")
    rows.append(r"\begin{tabular}{lcccc}")
    rows.append(r"\toprule")
    rows.append(r"Agent & Posture & Pass Rate (\%) & Fail Rate (\%) & Total Runs \\")
    rows.append(r"\midrule")
    for label in AGENTS:
        s = stats.get(f"agent_{label}", {})
        pr = s.get("overall_pass_rate", 0)
        fr = s.get("overall_fail_rate", 0)
        total = s.get("total_payloads", 0)
        rows.append(f"Agent {label} & {POSTURES[label]} & {pr}\\% & {fr}\\% & {total} \\\\")
    rows.append(r"\bottomrule")
    rows.append(r"\end{tabular}")
    rows.append(r"\end{table}")
    return "\n".join(rows)


def make_table_scenario(all_data):
    scenario_names = sorted(set(
        r["scenario"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    rows = []
    rows.append(r"\begin{table}[ht]")
    rows.append(r"\centering")
    rows.append(r"\caption{Pass Rate by Attack Scenario (\%)}")
    rows.append(r"\label{tab:scenario}")
    cols = "l" + "c" * (len(AGENTS) + 1)
    rows.append(r"\begin{tabular}{" + cols + r"}")
    rows.append(r"\toprule")
    header = "Scenario"
    for a in AGENTS:
        header += f" & Agent {a}"
    header += r" & Improvement A$\to$C (\%) \\"
    rows.append(header)
    rows.append(r"\midrule")
    for scenario in scenario_names:
        rates = {}
        for label in AGENTS:
            data = all_data.get(label)
            if data:
                srs = [r for r in data["results"] if r["scenario"] == scenario]
                total = len(srs)
                passes = sum(1 for r in srs if r["result"] == "PASS")
                rates[label] = round(passes / total * 100, 1) if total > 0 else 0.0
            else:
                rates[label] = "—"
        ra, rc = rates.get("A"), rates.get("C")
        if isinstance(ra, (int, float)) and isinstance(rc, (int, float)) and ra > 0:
            impr = round(((rc - ra) / ra) * 100, 1)
        else:
            impr = "—"
        line = f"{esc(scenario)}"
        for a in AGENTS:
            v = rates.get(a, "—")
            line += f" & {v}"
        line += f" & {impr} \\\\"
        rows.append(line)
    rows.append(r"\bottomrule")
    rows.append(r"\end{tabular}")
    rows.append(r"\end{table}")
    return "\n".join(rows)


def make_table_owasp(all_data):
    owasp_categories = sorted(set(
        r["owasp_category"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    rows = []
    rows.append(r"\begin{table}[ht]")
    rows.append(r"\centering")
    rows.append(r"\caption{Pass Rate by OWASP Category (\%)}")
    rows.append(r"\label{tab:owasp}")
    cols = "l" + "c" * len(AGENTS)
    rows.append(r"\begin{tabular}{" + cols + r"}")
    rows.append(r"\toprule")
    header = "OWASP Category"
    for a in AGENTS:
        header += f" & Agent {a}"
    rows.append(header)
    rows.append(r"\midrule")
    for owasp in owasp_categories:
        line = f"{esc(owasp)}"
        for label in AGENTS:
            data = all_data.get(label)
            if data:
                ores = [r for r in data["results"] if r["owasp_category"] == owasp]
                total = len(ores)
                passes = sum(1 for r in ores if r["result"] == "PASS")
                rate = round(passes / total * 100, 1) if total > 0 else 0.0
                line += f" & {rate}"
            else:
                line += " & —"
        rows.append(line + r" \\")
    rows.append(r"\bottomrule")
    rows.append(r"\end{tabular}")
    rows.append(r"\end{table}")
    return "\n".join(rows)


def make_table_timing(all_data):
    rows = []
    rows.append(r"\begin{table}[ht]")
    rows.append(r"\centering")
    rows.append(r"\caption{Response Latency Statistics (ms)}")
    rows.append(r"\label{tab:timing}")
    rows.append(r"\begin{tabular}{lcccc}")
    rows.append(r"\toprule")
    rows.append(r"Agent & Min (ms) & Max (ms) & Mean (ms) & Median (ms) \\")
    rows.append(r"\midrule")
    for label in AGENTS:
        data = all_data.get(label)
        if data:
            latencies = [r["response_latency_ms"] for r in data["results"]]
            if latencies:
                mn = round(min(latencies), 1)
                mx = round(max(latencies), 1)
                mean = round(sum(latencies) / len(latencies), 1)
                med = round(sorted(latencies)[len(latencies) // 2], 1)
                rows.append(f"Agent {label} ({POSTURES[label]}) & {mn} & {mx} & {mean} & {med} \\\\")
    rows.append(r"\bottomrule")
    rows.append(r"\end{tabular}")
    rows.append(r"\end{table}")
    return "\n".join(rows)


def main():
    print("\n" + "=" * 60)
    print("  Sentra Experiment — LaTeX Table Generator")
    print("=" * 60 + "\n")

    os.makedirs(TABLES_DIR, exist_ok=True)

    stats = load_paper_stats()
    all_data = {label: load_results(label) for label in AGENTS}

    if not stats:
        print("  Error: paper_stats.json not found. Run analysis.py first.")
        return

    tables = {
        "table_overall.tex": make_table_overall(stats),
        "table_scenario.tex": make_table_scenario(all_data),
        "table_owasp.tex": make_table_owasp(all_data),
        "table_timing.tex": make_table_timing(all_data),
    }

    for filename, content in tables.items():
        path = os.path.join(TABLES_DIR, filename)
        with open(path, "w") as f:
            f.write(content + "\n")
        print(f"  Saved: {path}")

    print(f"\n  Done. Generated {len(tables)} LaTeX table files.\n")


if __name__ == "__main__":
    main()
