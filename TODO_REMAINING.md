# Remaining Tasks (7)

## 1. Run Gemma-4-31b-it via validator.py
- `python validator.py --api-key YOUR_GEMINI_KEY --sample 130`
- Already set up with `google.genai` library and `gemma-4-31b-it` model
- Output: `results/gemini_validation.json`
- ~5 min runtime (130 payloads × 0.3s delay + API latency)

## 2. (Optional) Run GPT-4o-mini via GitHub Models
- Requires GitHub classic PAT (no billing)
- Need to create a new validator script for GitHub Models API
- ~130 payloads, free tier sufficient

## 3. Create integrate_gemini.py
- Converts `results/gemini_validation.json` → `results/agent_G_results.json`
- Must match the agent results format (390 records, same structure)
- Needed for analysis.py to include Gemma as Agent D

## 4. Re-run all generators
```powershell
python analysis.py
python plot_charts.py
python export_latex_tables.py
python export_appendix.py
```

## 5. Open-source payloads
- Push `payloads.py` (130 attacks, 13 scenarios, 6 OWASP categories) to GitHub
- Vital for reproducibility — required at top venues

## 6. Write manuscript
- Create .pdf paper: abstract, intro, methodology, results, discussion, related work, conclusion
- Use the generated figures (results/figures/*.pdf) and tables (results/tables/*.tex)

## 7. Submit to venue
- IEEE S&P, CCS, USENIX Security, or ACSAC/EuroS&P
