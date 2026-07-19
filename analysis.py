"""
Analysis and Report Generator for Sentra Controlled Experiment.

Reads all 3 agent result files and generates:
- comparison_table.csv
- owasp_breakdown.csv
- paper_stats.json
- experiment_report.html (color-coded)
- experiment_report.md (plain text)
- Failure type heatmap
- Payload effectiveness ranking
- Timing analysis
- Before/after system prompt comparison
"""

import json
import math
import os
import subprocess
from datetime import datetime, timezone
from collections import defaultdict

from scipy.stats import mannwhitneyu
from numpy import mean, std


RESULTS_DIR = "results"
AGENTS = ["A", "B", "C", "D", "E"]
POSTURES = {"A": "Weak", "B": "Medium", "C": "Strong", "D": "Gemma-4-31b", "E": "GPT-4o-mini"}
EXTERNAL_AGENTS = {"D", "E"}


def load_results(agent_label: str) -> dict:
    path = os.path.join(RESULTS_DIR, f"agent_{agent_label}_results.json")
    if not os.path.exists(path):
        print(f"Warning: {path} not found. Skipping agent {agent_label}.")
        return None
    with open(path) as f:
        return json.load(f)


def get_git_hash() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return "unknown"


def build_comparison_table(all_data: dict) -> list:
    scenario_names = set()
    for label, data in all_data.items():
        if data:
            for r in data.get("results", []):
                scenario_names.add(r["scenario"])

    sorted_scenarios = sorted(scenario_names)
    rows = []
    for scenario in sorted_scenarios:
        row = {"scenario": scenario}
        rates = {}
        for label in AGENTS:
            data = all_data.get(label)
            if data:
                scenario_results = [r for r in data["results"] if r["scenario"] == scenario]
                total = len(scenario_results)
                passes = sum(1 for r in scenario_results if r["result"] == "PASS")
                rate = round(passes / total * 100, 2) if total > 0 else 0.0
                row[f"agent_{label}_pass_rate"] = rate
                rates[label] = rate
            else:
                row[f"agent_{label}_pass_rate"] = None

        if rates.get("A") is not None and rates.get("C") is not None and rates["A"] > 0:
            improvement = round(((rates["C"] - rates["A"]) / rates["A"]) * 100, 2)
            row["improvement_a_to_c_pct"] = improvement
        else:
            row["improvement_a_to_c_pct"] = None

        rows.append(row)

    return rows


def build_owasp_breakdown(all_data: dict) -> list:
    owasp_categories = set()
    for label, data in all_data.items():
        if data:
            for r in data.get("results", []):
                owasp_categories.add(r["owasp_category"])

    sorted_owasp = sorted(owasp_categories)
    rows = []
    for owasp in sorted_owasp:
        row = {"owasp_category": owasp}
        for label in AGENTS:
            data = all_data.get(label)
            if data:
                owasp_results = [r for r in data["results"] if r["owasp_category"] == owasp]
                total = len(owasp_results)
                passes = sum(1 for r in owasp_results if r["result"] == "PASS")
                rate = round(passes / total * 100, 2) if total > 0 else 0.0
                row[f"agent_{label}_pass_rate"] = rate
            else:
                row[f"agent_{label}_pass_rate"] = None
        rows.append(row)

    return rows


def build_failure_heatmap(all_data: dict) -> dict:
    heatmap = {}
    for label, data in all_data.items():
        if not data:
            continue
        for r in data.get("results", []):
            scenario = r["scenario"]
            ftype = r["failure_type"]
            if scenario not in heatmap:
                heatmap[scenario] = {}
            if ftype not in heatmap[scenario]:
                heatmap[scenario][ftype] = {}
            if label not in heatmap[scenario][ftype]:
                heatmap[scenario][ftype][label] = 0
            heatmap[scenario][ftype][label] += 1
    return heatmap


def build_payload_ranking(all_data: dict) -> list:
    payload_stats = {}
    for label, data in all_data.items():
        if not data:
            continue
        for r in data.get("results", []):
            key = (r["payload_id"], r["scenario"])
            if key not in payload_stats:
                payload_stats[key] = {
                    "payload_id": r["payload_id"],
                    "scenario": r["scenario"],
                    "owasp_category": r["owasp_category"],
                    "payload_text": r["payload_text"][:100],
                    "compromised_agents": [],
                }
            if r["result"] == "FAIL":
                if label not in payload_stats[key]["compromised_agents"]:
                    payload_stats[key]["compromised_agents"].append(label)

    ranked = sorted(payload_stats.values(), key=lambda x: len(x["compromised_agents"]), reverse=True)
    return ranked


def build_timing_analysis(all_data: dict) -> dict:
    timing = {}
    for label in AGENTS:
        data = all_data.get(label)
        if not data:
            continue
        latencies = [r["response_latency_ms"] for r in data.get("results", [])]
        if latencies:
            timing[label] = {
                "min_ms": round(min(latencies), 2),
                "max_ms": round(max(latencies), 2),
                "mean_ms": round(sum(latencies) / len(latencies), 2),
                "median_ms": round(sorted(latencies)[len(latencies) // 2], 2),
            }
        else:
            timing[label] = {"min_ms": 0, "max_ms": 0, "mean_ms": 0, "median_ms": 0}
    return timing


def build_confidence_intervals(all_data: dict) -> dict:
    cis = {}
    for label in AGENTS:
        data = all_data.get(label)
        if not data:
            continue
        results = data.get("results", [])
        run_indices = sorted(set(r["run_index"] for r in results))
        if len(run_indices) < 2:
            continue
        by_run = defaultdict(list)
        for r in results:
            by_run[r["run_index"]].append(r)
        scenario_stats = {}
        all_scenarios = sorted(set(r["scenario"] for r in results))
        for scenario in all_scenarios:
            run_rates = []
            for run_idx in run_indices:
                run_results = [r for r in by_run[run_idx] if r["scenario"] == scenario]
                if run_results:
                    rate = sum(1 for r in run_results if r["result"] == "PASS") / len(run_results) * 100
                    run_rates.append(rate)
            if len(run_rates) >= 2:
                mean = sum(run_rates) / len(run_rates)
                variance = sum((r - mean) ** 2 for r in run_rates) / (len(run_rates) - 1)
                std_err = math.sqrt(variance / len(run_rates))
                margin = 1.96 * std_err
                scenario_stats[scenario] = {
                    "mean": round(mean, 1),
                    "ci_lower": round(mean - margin, 1),
                    "ci_upper": round(mean + margin, 1),
                    "runs": len(run_rates),
                }
        if scenario_stats:
            cis[label] = scenario_stats
    return cis


def compute_cohens_d(sample1, sample2):
    n1, n2 = len(sample1), len(sample2)
    if n1 < 2 or n2 < 2:
        return None
    s1, s2 = std(sample1, ddof=1), std(sample2, ddof=1)
    pooled = math.sqrt(((n1 - 1) * s1 ** 2 + (n2 - 1) * s2 ** 2) / (n1 + n2 - 2))
    if pooled == 0:
        return None
    d = (mean(sample1) - mean(sample2)) / pooled
    return round(d, 3)


def build_statistical_significance(all_data: dict) -> dict:
    sig = {}
    pair_labels = [("A", "B"), ("A", "C"), ("B", "C"), ("A", "D"), ("C", "D"), ("A", "E"), ("C", "E")]
    all_scenarios = sorted(set(
        r["scenario"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    for scenario in all_scenarios:
        sig[scenario] = {}
        for a, b in pair_labels:
            da, db = all_data.get(a), all_data.get(b)
            if not da or not db:
                continue
            ra = [r for r in da["results"] if r["scenario"] == scenario]
            rb = [r for r in db["results"] if r["scenario"] == scenario]
            if len(ra) < 2 or len(rb) < 2:
                continue
            scores_a = [1 if r["result"] == "PASS" else 0 for r in ra]
            scores_b = [1 if r["result"] == "PASS" else 0 for r in rb]
            if sum(scores_a) == len(scores_a) and sum(scores_b) == len(scores_b):
                continue
            if sum(scores_a) == 0 and sum(scores_b) == 0:
                continue
            u_stat, p_val = mannwhitneyu(scores_a, scores_b, alternative="two-sided")
            d = compute_cohens_d(scores_a, scores_b)
            sig[scenario][f"{a}_vs_{b}"] = {
                "p_value": round(float(p_val), 4),
                "cohens_d": float(d) if d is not None else None,
                "significant": bool(p_val < 0.05),
                "n_a": len(ra),
                "n_b": len(rb),
            }
    return sig


def build_per_scenario_failure_breakdown(all_data: dict) -> dict:
    breakdown = {}
    for label in AGENTS:
        data = all_data.get(label)
        if not data:
            continue
        for r in data.get("results", []):
            scenario = r["scenario"]
            if scenario not in breakdown:
                breakdown[scenario] = {}
            if label not in breakdown[scenario]:
                breakdown[scenario][label] = defaultdict(int)
            if r["failure_type"] != "none":
                breakdown[scenario][label][r["failure_type"]] += 1
    return breakdown


def build_paper_stats(all_data: dict, comparison_rows: list, owasp_rows: list,
                      ranked_payloads: list, timing: dict) -> dict:
    stats = {}

    for label in AGENTS:
        data = all_data.get(label)
        if not data:
            continue
        summary = data.get("summary", {})
        results = data.get("results", [])

        stats[f"agent_{label}"] = {
            "overall_pass_rate": summary.get("overall_pass_rate", 0),
            "overall_fail_rate": summary.get("overall_fail_rate", 0),
            "total_payloads": summary.get("total_payloads", 0),
            "total_passes": summary.get("total_passes", 0),
            "total_fails": summary.get("total_fails", 0),
            "most_vulnerable_scenario": summary.get("most_vulnerable_scenario", ""),
            "most_resistant_scenario": summary.get("most_resistant_scenario", ""),
            "timing_ms": timing.get(label, {}),
        }

        by_scenario = summary.get("by_scenario", {})
        pass_rates = [v["pass_rate"] for v in by_scenario.values()]
        if pass_rates:
            stats[f"agent_{label}"]["statistical_range"] = {
                "min_pass_rate": round(min(pass_rates), 2),
                "max_pass_rate": round(max(pass_rates), 2),
                "range": round(max(pass_rates) - min(pass_rates), 2),
            }
        else:
            stats[f"agent_{label}"]["statistical_range"] = None

        by_owasp = summary.get("by_owasp_category", {})
        lowest_owasp = min(by_owasp.items(), key=lambda x: x[1]["pass_rate"]) if by_owasp else ("", None)
        stats[f"agent_{label}"]["lowest_owasp_category"] = {
            "category": lowest_owasp[0],
            "pass_rate": lowest_owasp[1]["pass_rate"] if lowest_owasp[1] else 0,
        } if lowest_owasp[0] else None

    a_data = all_data.get("A")
    c_data = all_data.get("C")
    if a_data and c_data:
        a_rate = a_data.get("summary", {}).get("overall_pass_rate", 0)
        c_rate = c_data.get("summary", {}).get("overall_pass_rate", 0)
        if a_rate > 0:
            stats["security_improvement_a_to_c"] = {
                "agent_a_pass_rate": a_rate,
                "agent_c_pass_rate": c_rate,
                "absolute_improvement_pct": round(c_rate - a_rate, 2),
                "relative_improvement_pct": round(((c_rate - a_rate) / a_rate) * 100, 2),
            }
        else:
            stats["security_improvement_a_to_c"] = None

    if ranked_payloads:
        top = ranked_payloads[0] if ranked_payloads else None
        stats["most_effective_payload"] = {
            "payload_id": top["payload_id"] if top else "",
            "scenario": top["scenario"] if top else "",
            "compromised_agents_count": len(top["compromised_agents"]) if top else 0,
            "compromised_agents": top["compromised_agents"] if top else [],
        } if top else None

    return stats


def write_csv(filename: str, rows: list, fieldnames: list):
    path = os.path.join(RESULTS_DIR, filename)
    with open(path, "w", newline="", encoding="utf-8") as f:
        f.write(",".join(f'"{fn}"' for fn in fieldnames) + "\n")
        for row in rows:
            f.write(",".join(f'"{str(row.get(fn, ""))}"' for fn in fieldnames) + "\n")
    print(f"  Saved: {path}")


def generate_html_report(comparison_rows: list, owasp_rows: list, paper_stats: dict,
                          timing: dict, failure_heatmap: dict, ranked_payloads: list,
                          all_data: dict, git_hash: str,
                          confidence_intervals: dict = None,
                          failure_breakdown: dict = None,
                          statistical_sig: dict = None):
    def color_class(rate):
        if rate is None:
            return "color-none"
        if rate >= 70:
            return "color-green"
        elif rate >= 40:
            return "color-yellow"
        else:
            return "color-red"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sentra Controlled Experiment Report</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; color: #333; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #1a1a2e; padding-bottom: 10px; }}
h2 {{ color: #16213e; margin-top: 30px; }}
table {{ border-collapse: collapse; width: 100%; margin: 15px 0; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
th {{ background: #1a1a2e; color: white; padding: 12px; text-align: left; }}
td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
tr:hover {{ background: #f0f0f0; }}
.color-green {{ background: #d4edda !important; font-weight: bold; }}
.color-yellow {{ background: #fff3cd !important; font-weight: bold; }}
.color-red {{ background: #f8d7da !important; font-weight: bold; }}
.color-none {{ background: #e9ecef !important; }}
.meta {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin: 15px 0; }}
.footer {{ margin-top: 40px; font-size: 0.85em; color: #666; border-top: 1px solid #ddd; padding-top: 10px; }}
.summary-box {{ display: inline-block; padding: 10px 20px; margin: 5px; border-radius: 5px; font-weight: bold; }}
</style>
</head>
<body>
<h1>Sentra Controlled Experiment Report</h1>
<div class="meta">
<p><strong>Generated:</strong> {datetime.now(timezone.utc).isoformat()}</p>
<p><strong>Git Hash:</strong> {git_hash}</p>
<p><strong>Sentra Version:</strong> 1.0</p>
<p><strong>Experiment:</strong> {sum(1 for d in all_data.values() if d)} agents x 13 scenarios x 10 payloads ({sum(len(d.get('results', [])) for d in all_data.values() if d)} baseline runs)</p>
</div>

<h2>Overall Results</h2>
<table>
<tr><th>Agent</th><th>Posture</th><th>Pass Rate</th><th>Fail Rate</th><th>Passes</th><th>Fails</th><th>Min Scenario</th><th>Max Scenario</th></tr>"""

    for label in AGENTS:
        s = paper_stats.get(f"agent_{label}", {})
        rate = s.get("overall_pass_rate", 0)
        html += f"""<tr>
<td><strong>Agent {label}</strong></td>
<td>{POSTURES.get(label, label)}</td>
<td class="{color_class(rate)}">{rate}%</td>
<td>{s.get('overall_fail_rate', 0)}%</td>
<td>{s.get('total_passes', 0)}</td>
<td>{s.get('total_fails', 0)}</td>
<td>{s.get('most_vulnerable_scenario', '')}</td>
<td>{s.get('most_resistant_scenario', '')}</td>
</tr>"""

    html += """</table>

<h2>Security Improvement: Agent A to Agent C</h2>"""
    impr = paper_stats.get("security_improvement_a_to_c")
    if impr:
        html += f"""<div class="meta">
<p><strong>Absolute improvement:</strong> {impr['absolute_improvement_pct']}%</p>
<p><strong>Relative improvement:</strong> {impr['relative_improvement_pct']}%</p>
<p><strong>Agent A baseline:</strong> {impr['agent_a_pass_rate']}% -> <strong>Agent C:</strong> {impr['agent_c_pass_rate']}%</p>
</div>"""

    html += """<h2>Comparison Table (by Scenario)</h2>
<table>
<tr><th>Scenario</th><th>Agent A</th><th>Agent B</th><th>Agent C</th><th>Improvement A->C</th></tr>"""

    for row in comparison_rows:
        a_rate = row.get("agent_A_pass_rate")
        b_rate = row.get("agent_B_pass_rate")
        c_rate = row.get("agent_C_pass_rate")
        impr_val = row.get("improvement_a_to_c_pct")
        impr_str = f"{impr_val}%" if impr_val is not None else "N/A"
        html += f"""<tr>
<td>{row['scenario']}</td>
<td class="{color_class(a_rate)}">{a_rate}%</td>
<td class="{color_class(b_rate)}">{b_rate}%</td>
<td class="{color_class(c_rate)}">{c_rate}%</td>
<td>{impr_str}</td>
</tr>"""

    html += """</table>

<h2>OWASP Category Breakdown</h2>
<table>
<tr><th>OWASP Category</th><th>Agent A</th><th>Agent B</th><th>Agent C</th></tr>"""

    for row in owasp_rows:
        a_rate = row.get("agent_A_pass_rate")
        b_rate = row.get("agent_B_pass_rate")
        c_rate = row.get("agent_C_pass_rate")
        html += f"""<tr>
<td>{row['owasp_category']}</td>
<td class="{color_class(a_rate)}">{a_rate}%</td>
<td class="{color_class(b_rate)}">{b_rate}%</td>
<td class="{color_class(c_rate)}">{c_rate}%</td>
</tr>"""

    html += """</table>

<h2>Failure Type Heatmap</h2>
<table>
<tr><th>Scenario</th><th>Failure Type</th><th>Agent A</th><th>Agent B</th><th>Agent C</th></tr>"""

    for scenario in sorted(failure_heatmap.keys()):
        ftypes = failure_heatmap[scenario]
        first = True
        for ftype in sorted(ftypes.keys()):
            agents = ftypes[ftype]
            html += f"""<tr>
{"<td rowspan='" + str(len(ftypes)) + "'><strong>" + scenario + "</strong></td>" if first else ""}
<td>{ftype}</td>
<td>{agents.get('A', 0)}</td>
<td>{agents.get('B', 0)}</td>
<td>{agents.get('C', 0)}</td>
</tr>"""
            first = False

    html += """</table>

<h2>Payload Effectiveness Ranking</h2>
<table>
<tr><th>Rank</th><th>Payload ID</th><th>Scenario</th><th>OWASP</th><th>Agents Compromised</th><th>Payload (truncated)</th></tr>"""

    for i, p in enumerate(ranked_payloads[:20]):
        count = len(p["compromised_agents"])
        html += f"""<tr>
<td>{i + 1}</td>
<td>{p['payload_id']}</td>
<td>{p['scenario']}</td>
<td>{p['owasp_category']}</td>
<td>{count} ({', '.join(p['compromised_agents'])})</td>
<td style="font-size: 0.85em;">{p['payload_text'][:80]}...</td>
</tr>"""

    html += """</table>

<h2>Timing Analysis</h2>
<table>
<tr><th>Agent</th><th>Min (ms)</th><th>Max (ms)</th><th>Mean (ms)</th><th>Median (ms)</th></tr>"""

    for label in AGENTS:
        t = timing.get(label, {})
        html += f"""<tr>
<td><strong>Agent {label}</strong></td>
<td>{t.get('min_ms', 0)}</td>
<td>{t.get('max_ms', 0)}</td>
<td>{t.get('mean_ms', 0)}</td>
<td>{t.get('median_ms', 0)}</td>
</tr>"""

    html += """</table>"""

    if confidence_intervals:
        html += """
<h2>Confidence Intervals (95%) — Multi-Run Analysis</h2>
<p>Mean pass rate across randomized runs with 95% confidence interval.</p>
<table>
<tr><th>Scenario</th><th>Agent A Mean</th><th>Agent A 95% CI</th><th>Agent B Mean</th><th>Agent B 95% CI</th><th>Agent C Mean</th><th>Agent C 95% CI</th></tr>"""
        all_ci_scenarios = sorted(set(
            s for ci in confidence_intervals.values() for s in ci.keys()
        ))
        for scenario in all_ci_scenarios:
            html += "<tr>"
            html += f"<td><strong>{scenario}</strong></td>"
            for label in AGENTS:
                ci = confidence_intervals.get(label, {}).get(scenario)
                if ci:
                    html += f"<td>{ci['mean']}%</td><td>({ci['ci_lower']}% – {ci['ci_upper']}%)</td>"
                else:
                    html += "<td>—</td><td>—</td>"
            html += "</tr>"
        html += "</table>"

    if statistical_sig:
        html += """
<h2>Statistical Significance (Mann-Whitney U Test)</h2>
<table>
<tr><th>Scenario</th><th>Comparison</th><th>p-value</th><th>Cohen's d</th><th>Significant (p<0.05)</th></tr>"""
        for scenario in sorted(statistical_sig.keys()):
            first = True
            for comp, stats in statistical_sig[scenario].items():
                d_str = str(stats["cohens_d"]) if stats["cohens_d"] is not None else "—"
                sig_mark = "Yes" if stats.get("significant") else "No"
                html += f"""<tr>
{"<td rowspan='" + str(len(statistical_sig[scenario])) + "'><strong>" + scenario + "</strong></td>" if first else ""}
<td>{comp}</td>
<td>{stats['p_value']}</td>
<td>{d_str}</td>
<td>{sig_mark}</td>
</tr>"""
                first = False
        html += "</table>"

    if failure_breakdown:
        html += """
<h2>Per-Scenario Failure Type Breakdown</h2>"""
        all_failure_scenarios = sorted(failure_breakdown.keys())
        for scenario in all_failure_scenarios:
            html += f"""
<details style="margin: 10px 0;">
<summary style="cursor: pointer; font-weight: bold; color: #16213e;"><strong>{scenario}</strong></summary>
<table>
<tr><th>Agent</th><th>Failure Type</th><th>Count</th></tr>"""
            for label in AGENTS:
                ftypes = failure_breakdown[scenario].get(label, {})
                if ftypes:
                    first = True
                    for ftype, count in sorted(ftypes.items()):
                        html += "<tr>"
                        if first:
                            html += f"<td rowspan='{len(ftypes)}'><strong>Agent {label}</strong></td>"
                            first = False
                        html += f"<td>{ftype}</td><td>{count}</td>"
                        html += "</tr>"
                else:
                    html += f"<tr><td><strong>Agent {label}</strong></td><td colspan='2'>(no failures)</td></tr>"
            html += "</table></details>"

    all_payload_ids = sorted(set(
        r["payload_id"]
        for label in AGENTS
        if all_data.get(label)
        for r in all_data[label].get("results", [])
    ))
    if all_payload_ids:
        html += """
<h2>Per-Payload Results</h2>
<details>
<summary style="cursor: pointer; font-weight: bold; color: #16213e;">Click to expand full payload table</summary>
<table>
<tr><th>Payload ID</th><th>Scenario</th><th>Agent A</th><th>Agent B</th><th>Agent C</th></tr>"""
        for pid in all_payload_ids:
            row_vals = {}
            for label in AGENTS:
                data = all_data.get(label)
                if data:
                    match = [r for r in data["results"] if r["payload_id"] == pid]
                    if match:
                        row_vals[label] = match[-1]["result"]
                    else:
                        row_vals[label] = "—"
                else:
                    row_vals[label] = "—"
            scenario = ""
            for label in AGENTS:
                data = all_data.get(label)
                if data:
                    match = [r for r in data["results"] if r["payload_id"] == pid]
                    if match:
                        scenario = match[-1]["scenario"]
                        break
            color = lambda v: "background: #d4edda;" if v == "PASS" else ("background: #f8d7da;" if v == "FAIL" else "")
            html += f"<tr><td>{pid}</td><td>{scenario}</td>"
            for label in AGENTS:
                v = row_vals.get(label, "—")
                html += f"<td style='{color(v)}'>{v}</td>"
            html += "</tr>"
        html += "</table></details>"

    html += """
<div class="footer">
<p><strong>Citation:</strong> Results generated using Sentra v1.0 experiment harness.</p>
<p><strong>Methodology:</strong> Each of the 13 attack scenarios was tested with 10 unique payload variants (130 total per agent). PASS = agent successfully resisted the attack; FAIL = agent was compromised. Color coding: green >= 70%, yellow = 40-69%, red < 40%.</p>
</div>
</body>
</html>"""

    path = os.path.join(RESULTS_DIR, "experiment_report.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  Saved: {path}")


def generate_markdown_report(comparison_rows: list, owasp_rows: list, paper_stats: dict,
                              timing: dict, ranked_payloads: list, git_hash: str):
    md = f"""# Sentra Controlled Experiment Report

**Generated:** {datetime.now(timezone.utc).isoformat()}
**Git Hash:** {git_hash}
**Sentra Version:** 1.0
**Experiment:** {len([k for k in paper_stats if k.startswith('agent_')])} agents × 13 scenarios × 10 payloads (1950 baseline runs)

---

## Overall Results

| Agent | Posture | Pass Rate | Fail Rate | Passes | Fails | Min Scenario | Max Scenario |
|-------|---------|-----------|-----------|--------|-------|-------------|-------------|
"""
    for label in AGENTS:
        s = paper_stats.get(f"agent_{label}", {})
        md += f"| Agent {label} | {POSTURES.get(label, label)} | {s.get('overall_pass_rate', 0)}% | {s.get('overall_fail_rate', 0)}% | {s.get('total_passes', 0)} | {s.get('total_fails', 0)} | {s.get('most_vulnerable_scenario', '')} | {s.get('most_resistant_scenario', '')} |\n"

    md += "\n## Security Improvement: Agent A -> Agent C\n\n"
    impr = paper_stats.get("security_improvement_a_to_c")
    if impr:
        md += f"- Absolute improvement: {impr['absolute_improvement_pct']}%\n"
        md += f"- Relative improvement: {impr['relative_improvement_pct']}%\n"
        md += f"- Agent A baseline: {impr['agent_a_pass_rate']}% -> Agent C: {impr['agent_c_pass_rate']}%\n"

    md += "\n## Comparison Table (by Scenario)\n\n"
    md += "| Scenario | Agent A | Agent B | Agent C | Improvement A->C |\n"
    md += "|----------|---------|---------|---------|------------------|\n"
    for row in comparison_rows:
        a = row.get("agent_A_pass_rate", "")
        b = row.get("agent_B_pass_rate", "")
        c = row.get("agent_C_pass_rate", "")
        i = row.get("improvement_a_to_c_pct", "N/A")
        md += f"| {row['scenario']} | {a}% | {b}% | {c}% | {i} |\n"

    md += "\n## OWASP Category Breakdown\n\n"
    md += "| OWASP Category | Agent A | Agent B | Agent C |\n"
    md += "|----------------|---------|---------|---------|\n"
    for row in owasp_rows:
        a = row.get("agent_A_pass_rate", "")
        b = row.get("agent_B_pass_rate", "")
        c = row.get("agent_C_pass_rate", "")
        md += f"| {row['owasp_category']} | {a}% | {b}% | {c}% |\n"

    md += "\n## Payload Effectiveness Ranking (Top 10)\n\n"
    md += "| Rank | Payload ID | Scenario | OWASP | Agents Compromised |\n"
    md += "|------|-----------|----------|-------|--------------------|\n"
    for i, p in enumerate(ranked_payloads[:10]):
        count = len(p["compromised_agents"])
        agents = ", ".join(p["compromised_agents"])
        md += f"| {i+1} | {p['payload_id']} | {p['scenario']} | {p['owasp_category']} | {count} ({agents}) |\n"

    md += "\n## Timing Analysis\n\n"
    md += "| Agent | Min (ms) | Max (ms) | Mean (ms) | Median (ms) |\n"
    md += "|-------|----------|----------|-----------|-------------|\n"
    for label in AGENTS:
        t = timing.get(label, {})
        md += f"| Agent {label} | {t.get('min_ms', 0)} | {t.get('max_ms', 0)} | {t.get('mean_ms', 0)} | {t.get('median_ms', 0)} |\n"

    md += """
---

**Citation:** Results generated using Sentra v1.0 experiment harness.

**Methodology:** Each of the 13 attack scenarios was tested with 10 unique payload variants (130 total per agent). PASS = agent successfully resisted the attack; FAIL = agent was compromised.
"""

    path = os.path.join(RESULTS_DIR, "experiment_report.md")
    with open(path, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"  Saved: {path}")


def main():
    print("\n" + "=" * 60)
    print("  Sentra Experiment Analysis & Report Generator")
    print("=" * 60 + "\n")

    git_hash = get_git_hash()
    print(f"  Git hash: {git_hash}")

    all_data = {}
    for label in AGENTS:
        all_data[label] = load_results(label)
        if all_data[label]:
            print(f"  Agent {label}: {len(all_data[label].get('results', []))} records loaded")
        else:
            print(f"  Agent {label}: not found")

    available = [label for label, data in all_data.items() if data is not None]
    if not available:
        print("  Error: No results found. Run experiment_runner.py first.")
        return

    comparison_rows = build_comparison_table(all_data)
    owasp_rows = build_owasp_breakdown(all_data)
    failure_heatmap = build_failure_heatmap(all_data)
    ranked_payloads = build_payload_ranking(all_data)
    timing = build_timing_analysis(all_data)
    confidence_intervals = build_confidence_intervals(all_data)
    failure_breakdown = build_per_scenario_failure_breakdown(all_data)
    statistical_sig = build_statistical_significance(all_data)
    paper_stats = build_paper_stats(all_data, comparison_rows, owasp_rows, ranked_payloads, timing)
    paper_stats["statistical_significance"] = statistical_sig

    paper_stats["experiment_metadata"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "git_hash": git_hash,
        "sentra_version": "1.0",
        "agents_tested": available,
    }

    os.makedirs(RESULTS_DIR, exist_ok=True)

    write_csv("comparison_table.csv", comparison_rows,
              ["scenario", "agent_A_pass_rate", "agent_B_pass_rate", "agent_C_pass_rate",
               "improvement_a_to_c_pct"])

    write_csv("owasp_breakdown.csv", owasp_rows,
              ["owasp_category", "agent_A_pass_rate", "agent_B_pass_rate", "agent_C_pass_rate"])

    stats_path = os.path.join(RESULTS_DIR, "paper_stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(paper_stats, f, indent=2)
    print(f"  Saved: {stats_path}")

    generate_html_report(comparison_rows, owasp_rows, paper_stats, timing,
                          failure_heatmap, ranked_payloads, all_data, git_hash,
                          confidence_intervals, failure_breakdown, statistical_sig)

    generate_markdown_report(comparison_rows, owasp_rows, paper_stats, timing,
                              ranked_payloads, git_hash)

    print("\n  Done. Generated files:")
    print(f"    {RESULTS_DIR}/comparison_table.csv")
    print(f"    {RESULTS_DIR}/owasp_breakdown.csv")
    print(f"    {RESULTS_DIR}/paper_stats.json")
    print(f"    {RESULTS_DIR}/experiment_report.html")
    print(f"    {RESULTS_DIR}/experiment_report.md")
    print()


if __name__ == "__main__":
    main()
