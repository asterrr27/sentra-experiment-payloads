import json
d = json.load(open("results/agent_A_results.json"))
print(f"Records: {len(d['results'])}")
