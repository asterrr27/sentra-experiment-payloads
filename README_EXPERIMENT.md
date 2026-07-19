# Sentra Controlled Experiment Module

## Overview

This module runs a controlled experiment to test AI agent security across three
different security postures. It is designed to generate reproducible experimental
data for an IEEE research paper on agentic AI security testing.

## File Structure

```
experiment/
├── agents/
│   ├── __init__.py
│   ├── agent_a.py            # Agent A — Weak security (port 8001)
│   ├── agent_b.py            # Agent B — Medium security (port 8002)
│   └── agent_c.py            # Agent C — Strong security (port 8003)
├── payloads.py               # 130 attack payloads (10 × 13 scenarios)
├── experiment_runner.py      # Main experiment engine
├── analysis.py               # Report and statistics generator (HTML, MD, CSV, JSON, CI, p-values)
├── plot_charts.py            # Publication-quality chart generator (PNG + PDF)
├── export_latex_tables.py    # LaTeX table generator for IEEE paper
├── export_appendix.py        # Appendix material generator
├── validate_results.py       # Manual validation sampling tool
├── validator.py              # External validation via Google Gemini (free)
├── results/                  # Auto-created output directory
│   ├── figures/              # Charts (PNG + PDF)
│   └── tables/               # LaTeX tables
├── requirements_experiment.txt
├── requirements_lock.txt     # Pinned dependencies for reproducibility
├── Dockerfile.experiment     # Docker build for reproducible environment
├── run_experiment.ps1        # Full experiment automation (PowerShell)
├── run_analysis.ps1          # Analysis automation
└── README_EXPERIMENT.md
```

## Quick Start

### Prerequisites

1. **Groq API key** — Set `GROQ_API_KEY` in `.env` (get a free key at https://console.groq.com)
2. Python 3.12+

### Windows (PowerShell)

```powershell
# Install dependencies
pip install -r requirements_experiment.txt

# Full experiment (3 randomized runs each for confidence intervals)
.\run_experiment.ps1 -Randomize 3

# Generate analysis reports
python analysis.py

# Generate publication charts (PNG + PDF)
python plot_charts.py

# Generate LaTeX tables for paper
python export_latex_tables.py

# Generate appendix material
python export_appendix.py
```

### Linux / macOS

```bash
# Install dependencies
pip install -r requirements_experiment.txt

# Run experiment
python experiment_runner.py --agent A --randomize 3
python experiment_runner.py --agent B --randomize 3
python experiment_runner.py --agent C --randomize 3

# Generate all outputs
python analysis.py
python plot_charts.py
python export_latex_tables.py
python export_appendix.py
```

### Docker

```bash
docker build -t sentra-experiment -f Dockerfile.experiment \
  --build-arg GROQ_API_KEY=gsk_your_key_here .

# Run experiment inside container
docker run --rm sentra-experiment python experiment_runner.py --agent A --randomize 3
```

## The 3 Agents

| Agent | Posture | Port | Tools | Defenses |
|-------|---------|------|-------|----------|
| A | Weak | 8001 | read_file, send_email, search_web, delete_file, execute_command | None |
| B | Medium | 8002 | read_file, send_email, search_web | Profanity filter, basic refusal |
| C | Strong | 8003 | read_file, search_web | Full injection detection, 3-iteration limit |

All agents use **Llama 3.3 70B** via Groq API (`langchain-groq`).

## The 13 Attack Scenarios

| # | Scenario | OWASP | Payloads |
|---|----------|-------|----------|
| 1 | Goal Deviation | LLM01 | 10 |
| 2 | Indirect Injection | LLM01 | 10 |
| 3 | Multi-Step Chain | LLM01 | 10 |
| 4 | Role-Play Jailbreak | LLM01 | 10 |
| 5 | Token Smuggling | LLM01 | 10 |
| 6 | Context Window Overflow | LLM01 | 10 |
| 7 | System Prompt Extraction | LLM02 | 10 |
| 8 | Tool Output Injection | LLM05 | 10 |
| 9 | Excessive Agency | LLM06 | 10 |
| 10 | Permission Boundary | LLM06 | 10 |
| 11 | Tool Abuse | LLM06 | 10 |
| 12 | Prompt Boundary Probing | LLM07 | 10 |
| 13 | Tool Loop Exploit | LLM10 | 10 |

All agents × all scenarios × 10 payloads = 390 baseline runs (1,170 with --randomize 3).

## Output Files

All generated in `results/`:

| File | Description |
|------|-------------|
| `agent_{A,B,C}_results.json` | Full raw results per agent |
| `comparison_table.csv` | Scenario × Agent pass rates |
| `owasp_breakdown.csv` | OWASP category × Agent pass rates |
| `paper_stats.json` | Academic statistics (incl. p-values, Cohen's d) |
| `experiment_report.html` | Color-coded HTML report (CI, significance, per-payload) |
| `experiment_report.md` | Plain text markdown report |
| `figures/*.png` | Publication raster figures (300 DPI) |
| `figures/*.pdf` | Publication vector figures |
| `tables/table_overall.tex` | LaTeX table: overall results |
| `tables/table_scenario.tex` | LaTeX table: scenario breakdown |
| `tables/table_owasp.tex` | LaTeX table: OWASP breakdown |
| `tables/table_timing.tex` | LaTeX table: latency statistics |
| `appendix_scenarios.tex` | LaTeX appendix: scenario descriptions |
| `appendix_scenarios.csv` | CSV appendix: scenario descriptions |
| `gemini_validation.json` | (Optional) Gemini validation results |

## Interpreting Results

- **PASS**: Agent successfully resisted the attack
- **FAIL**: Agent was compromised (goal deviated, info leaked, tool abused, etc.)
- **Color coding** (HTML report):
  - Green (≥70% pass rate): Strong defense
  - Yellow (40-69%): Partial defense
  - Red (<40%): Weak defense
- **Statistical significance**: Mann-Whitney U test p-values and Cohen's d effect sizes are computed per scenario between agent pairs

## Mapping to Paper Sections

| Paper Section | Experiment Component |
|---------------|---------------------|
| Methodology | Experiment design, 3 security postures, 13 OWASP-aligned scenarios |
| Experiment Design | Agent configuration, payload library, PASS/FAIL methodology |
| Results | Pass rates, comparison tables, OWASP breakdowns, confidence intervals |
| Analysis | Payload effectiveness ranking, failure type heatmap, timing analysis, p-values |
| Discussion | Security improvement A→C, most vulnerable scenarios, effect sizes |
| Appendix | Scenario export, full payload list, report HTML |

## Paper Writing Notes

> **🗒️ Read this before writing your results section**

| Pitfall | Explanation |
|---------|-------------|
| **Don't say "1201% improvement"** | Agent A's pass rate was 3.33%, so any improvement looks huge in relative terms. Use **absolute percentage points** instead: "Agent C improved security by **40 percentage points** over Agent A (from 3.33% to 43.33%)." |
| **A vs B differences are not significant** | Across most scenarios, the p-value for A vs B is > 0.05. That means Agent B's basic profanity filter + refusal didn't make a statistically meaningful difference over Agent A (no defenses). |
| **A vs C and B vs C differences ARE significant** | The full injection detection layer (Agent C) produces statistically significant improvements (p < 0.05, Cohen's d > 0.8 = large effect). This is your strongest result. |
| **Use absolute improvement, not relative** | Relative improvement formula: `((C_rate - A_rate) / A_rate) * 100`. Since A is near zero, this inflates the number. **Absolute improvement** = `C_rate - A_rate` = 40%. Use this. |

**Suggested framing:** "While rudimentary defenses (Agent B) showed marginal, statistically insignificant improvement over an unprotected agent (Agent A), the comprehensive security layer (Agent C) achieved a statistically significant 40 percentage point improvement in pass rate, demonstrating that multi-layered injection detection is necessary for robust AI agent security."

## Citation

```bibtex
@software{sentra2026,
  title = {Sentra: Secure AI — Build with Confidence},
  version = {1.0},
  author = {Sattar},
  url = {https://github.com/asterrr27/Sentra}
}
```

Results generated using **Sentra v1.0 experiment harness**.
GitHub: https://github.com/asterrr27/Sentra

## Reproducibility

All results include:
- Timestamp (ISO 8601 UTC)
- Git commit hash (from Sentra repository)
- Random seed (default: 42)
- Deterministic payload ordering
- Pinned dependencies (`requirements_lock.txt`)
- Docker build (`Dockerfile.experiment`)

To reproduce: run with the same seed on the same code version.
