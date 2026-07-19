import json, os
base = os.path.join(os.environ['USERPROFILE'], 'experiment', 'results')
for f in ['agent_A_results.json', 'agent_B_results.json', 'agent_C_results.json']:
    path = os.path.join(base, f)
    if os.path.exists(path):
        d = json.load(open(path))
        meta = d.get('experiment_metadata', {})
        runs = meta.get('randomize_runs', 1)
        summary = d.get('summary', {})
        count = len(d.get('results', []))
        rate = summary.get('overall_pass_rate', 0)
        print(f'{f:30s} {count:4d} records, randomize={runs}, pass={rate}%')
