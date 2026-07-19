import json
d = json.load(open("results/agent_A_results.json"))
s = d["summary"]
print(f"Pass rate: {s['overall_pass_rate']}% ({s['total_passes']}/{s['total_payloads']})")
print(f"Vulnerable: {s['most_vulnerable_scenario']}")
for r in d["results"][:5]:
    print(f"  {r['scenario']:30s} {r['result']:4s} {r['failure_type']:20s} {r['payload_id']}")
