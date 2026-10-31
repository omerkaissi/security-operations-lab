"""Compare completed detector results with separately authored scenario labels."""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys
from .core import strict_json

RULES = {"signin_failure_then_success", "unexpected_protected_role", "large_export"}


def candidate(item, expected=False):
    if not isinstance(item, dict) or item.get("rule_id") not in RULES or item.get("rule_version") not in (("1.0", "1.1") if item.get("rule_id") == "signin_failure_then_success" else ("1.0",)):
        raise ValueError("invalid candidate rule/version")
    anchor_key = "success_event_id" if item["rule_id"] == "signin_failure_then_success" else "anchor_event_id"
    anchor = item.get(anchor_key)
    evidence = item.get("evidence_event_ids")
    if not isinstance(anchor, str) or not anchor or not isinstance(evidence, list) or not evidence or any(not isinstance(e, str) or not e for e in evidence) or len(set(evidence)) != len(evidence) or anchor not in evidence:
        raise ValueError("invalid candidate anchor/evidence")
    return (item["rule_id"], item["rule_version"], anchor, tuple(evidence))


def display(key):
    return {"rule_id": key[0], "rule_version": key[1], "anchor_event_id": key[2], "evidence_event_ids": list(key[3])}


def evaluate(result, labels):
    if not isinstance(result, dict) or result.get("status") != "complete" or not isinstance(result.get("alerts"), list):
        raise ValueError("evaluation requires complete detector output")
    if not isinstance(labels, dict) or not isinstance(labels.get("scenarios"), list) or not labels["scenarios"]:
        raise ValueError("labels must contain scenarios")
    owners, scenarios, expected = {}, {}, []
    for scenario in labels["scenarios"]:
        if not isinstance(scenario, dict):
            raise ValueError("invalid scenario")
        name, truth, ids, candidates = (scenario.get(k) for k in ("scenario_id", "security_truth", "event_ids", "expected_candidates"))
        if not isinstance(name, str) or not name or name in scenarios or truth not in ("malicious", "benign") or not isinstance(ids, list) or not ids or not isinstance(candidates, list):
            raise ValueError("invalid scenario metadata")
        scenarios[name] = truth
        for event_id in ids:
            if not isinstance(event_id, str) or not event_id or event_id in owners:
                raise ValueError("duplicate or overlapping scenario event membership")
            owners[event_id] = name
        for item in candidates:
            expected.append((name, candidate(item, True)))
    input_ids = result.get("input_event_ids")
    if not isinstance(input_ids, list) or any(not isinstance(x, str) or not x for x in input_ids) or len(set(input_ids)) != len(input_ids) or set(input_ids) != set(owners):
        raise ValueError("detector input event IDs must exactly match scenario membership")
    for name, key in expected:
        if owners.get(key[2]) != name or any(event_id not in owners for event_id in key[3]):
            raise ValueError("expected candidate has an orphan or ambiguous anchor/evidence")
    actual = [candidate(alert) for alert in result["alerts"]]
    expected_count = Counter(key for _, key in expected)
    actual_count = Counter(actual)
    matched = expected_count & actual_count
    missing, extra = expected_count - actual_count, actual_count - expected_count
    predicted = {owners[key[2]] for key in actual if key[2] in owners}
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for name, truth in scenarios.items():
        key = ("tp" if name in predicted else "fn") if truth == "malicious" else ("fp" if name in predicted else "tn")
        counts[key] += 1
    precision_denominator = counts["tp"] + counts["fp"]
    recall_denominator = counts["tp"] + counts["fn"]
    return {"status": "complete", "scope": "authored synthetic scenarios only", "scenario_count": len(scenarios),
            "candidate_conformance": {"expected": sum(expected_count.values()), "observed": len(actual), "matched": sum(matched.values()),
                                      "missing": [display(k) for k in sorted(missing) for _ in range(missing[k])],
                                      "extra": [display(k) for k in sorted(extra) for _ in range(extra[k])]},
            "scenario_security": {**counts, "precision": counts["tp"] / precision_denominator if precision_denominator else None,
                                  "recall": counts["tp"] / recall_denominator if recall_denominator else None},
            "limitations": ["Scenario truth is authored and not detector evidence.", "Scenario-level counts are not production accuracy.", "Unmatched candidate anchors appear in extra candidates and not scenario counts."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results")
    parser.add_argument("labels")
    parser.add_argument("--output")
    parser.add_argument("--check", action="store_true", help="exit 1 when candidate/evidence conformance fails")
    args = parser.parse_args()
    if args.output and Path(args.output).resolve() in {Path(args.results).resolve(), Path(args.labels).resolve()}:
        print("Evaluation configuration error: output would overwrite an input", file=sys.stderr)
        return 2
    try:
        result = strict_json(Path(args.results).read_text(encoding="utf-8"))
        labels = strict_json(Path(args.labels).read_text(encoding="utf-8"))
        report = evaluate(result, labels)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(f"Evaluation input error: {exc}", file=sys.stderr)
        return 2
    try:
        output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
    except OSError as exc:
        print(f"Evaluation output error: {exc}", file=sys.stderr)
        return 1
    conformance = report["candidate_conformance"]
    return 1 if args.check and (conformance["missing"] or conformance["extra"]) else 0


if __name__ == "__main__":
    sys.exit(main())
