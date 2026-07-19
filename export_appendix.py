"""
Export appendix material for IEEE paper.

Reads payloads.py and generates:
  - appendix_scenarios.tex  — LaTeX table of all 13 scenarios
  - appendix_scenarios.csv   — CSV version for supplementary material
"""

import csv
import os

from payloads import PAYLOAD_LIBRARY

APPENDIX_DIR = "results"


def esc(text):
    return text.replace("%", "\\%").replace("_", "\\_").replace("&", "\\&").replace("#", "\\#")


def export_scenarios_latex():
    rows = []
    rows.append(r"\begin{table}[ht]")
    rows.append(r"\centering")
    rows.append(r"\caption{Attack Scenarios Mapped to OWASP LLM Top 10 Categories}")
    rows.append(r"\label{tab:appendix_scenarios}")
    rows.append(r"\begin{tabular}{cllc}")
    rows.append(r"\toprule")
    rows.append(r"\# & Scenario & OWASP Category & Payloads \\")
    rows.append(r"\midrule")
    for i, (name, data) in enumerate(sorted(PAYLOAD_LIBRARY.items()), 1):
        desc = data["description"].split(".")[0]
        rows.append(
            f"{i} & {esc(name)} & {data['owasp_category']} ({esc(data['owasp_label'])}) "
            f"& {len(data['payloads'])} \\\\"
        )
    rows.append(r"\bottomrule")
    rows.append(r"\end{tabular}")
    rows.append(r"\end{table}")
    return "\n".join(rows)


def export_scenarios_csv():
    path = os.path.join(APPENDIX_DIR, "appendix_scenarios.csv")
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["scenario", "owasp_category", "owasp_label", "description", "payload_count"])
        for name, data in sorted(PAYLOAD_LIBRARY.items()):
            desc = data["description"].replace('"', "'").replace("\n", " ")
            writer.writerow([name, data["owasp_category"], data["owasp_label"],
                             desc, len(data["payloads"])])
    print(f"  Saved: {path}")


def main():
    print("\n" + "=" * 60)
    print("  Sentra Experiment — Appendix Generator")
    print("=" * 60 + "\n")

    tex = export_scenarios_latex()
    tex_path = os.path.join(APPENDIX_DIR, "appendix_scenarios.tex")
    with open(tex_path, "w") as f:
        f.write(tex + "\n")
    print(f"  Saved: {tex_path}")

    export_scenarios_csv()

    print(f"\n  Done.\n")


if __name__ == "__main__":
    main()
