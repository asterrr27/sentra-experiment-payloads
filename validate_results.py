"""
Validator — Manual Review Tool.

For each agent (A, B, C), samples 10 random PASS and 10 random FAIL
results for human inspection to verify PASS/FAIL accuracy.

Usage:
    python validate_results.py
    python validate_results.py --sample 5
"""

import argparse
import json
import os
import random

RESULTS_DIR = "results"
AGENTS = ["A", "B", "C", "D", "E"]
AGENT_POSTURES = {"A": "Weak", "B": "Medium", "C": "Strong", "D": "Gemma-4-31b", "E": "GPT-4o-mini"}
SAMPLE_SIZE = 10


def load_results(agent_label):
    path = os.path.join(RESULTS_DIR, f"agent_{agent_label}_results.json")
    if not os.path.exists(path):
        print(f"  Warning: {path} not found")
        return None
    with open(path) as f:
        return json.load(f)


def truncate(text, max_len=200):
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def print_sample(records, label, posture):
    print(f"\n{'=' * 70}")
    print(f"  Agent {label} ({posture}) — {len(records)} samples")
    print(f"{'=' * 70}")
    print(f"{'Payload ID':12s} {'Scenario':28s} {'Result':6s} {'Failure Type':20s} Response")
    print(f"{'-' * 12} {'-' * 28} {'-' * 6} {'-' * 20} {'-' * 40}")
    for r in records:
        print(f"{r['payload_id']:12s} {r['scenario']:28s} {r['result']:6s} {r['failure_type']:20s} {truncate(r['agent_response'], 60)}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Manual validation review tool"
    )
    parser.add_argument("--sample", type=int, default=SAMPLE_SIZE,
                        help=f"Samples per result type (default: {SAMPLE_SIZE})")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    args = parser.parse_args()

    random.seed(args.seed)

    print(f"\n{'=' * 70}")
    print(f"  Sentra Experiment — Manual Validation Tool")
    print(f"  Sampling {args.sample} PASS + {args.sample} FAIL per agent")
    print(f"{'=' * 70}")

    for label in AGENTS:
        data = load_results(label)
        if not data:
            continue

        results = data.get("results", [])
        posture = AGENT_POSTURES[label]

        passes = [r for r in results if r["result"] == "PASS"]
        fails = [r for r in results if r["result"] == "FAIL"]

        print(f"\n  Agent {label} ({posture}): {len(passes)} PASS, {len(fails)} FAIL out of {len(results)} total")

        if len(passes) < args.sample:
            print(f"  Warning: Only {len(passes)} PASS records available (requested {args.sample})")
        if len(fails) < args.sample:
            print(f"  Warning: Only {len(fails)} FAIL records available (requested {args.sample})")

        sample_pass = random.sample(passes, min(args.sample, len(passes)))
        sample_fail = random.sample(fails, min(args.sample, len(fails)))

        print_sample(sample_pass, label, posture + " (PASS)")
        print_sample(sample_fail, label, posture + " (FAIL)")

    print(f"\n  Review complete. Verify that PASS/FAIL classifications look correct.\n")


if __name__ == "__main__":
    main()
