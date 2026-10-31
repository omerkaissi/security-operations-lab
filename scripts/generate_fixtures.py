#!/usr/bin/env python3
"""Generate authored synthetic sign-in fixtures; no detector or network access."""

import argparse
import hashlib
import json
from pathlib import Path
import random


DEFAULT_SEED = 20261030
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def build_fixtures(seed):
    # Labels are authored here for evaluation, never supplied to a future detector.
    definitions = [
        ("S01", "actor_017", "192.0.2.17", "malicious", 1,
         ["09:00:00Z", "09:02:00Z", "09:04:00Z", "09:06:00Z", "09:10:00Z", "09:15:00Z"],
         True, "Simulated unauthorized access; intent is scenario truth, not proven by logs."),
        ("S02", "actor_029", "198.51.100.29", "benign", 7,
         ["03:00:00-07:00", "10:01:00Z", "10:02:00Z", "10:03:00Z", "10:04:00Z", "10:04:30Z"],
         True, "Legitimate forgotten-password retries; intentional security false positive."),
        ("S03", "actor_041", "203.0.113.41", "benign", 13,
         ["11:00:00Z", "11:01:00Z"],
         False, "Ordinary single retry."),
        ("S04", "actor_053", "192.0.2.53", "malicious", 15,
         ["12:00:00Z", "12:01:00Z", "12:02:00Z", "12:03:00Z", "12:04:00Z"],
         False, "Simulated unauthorized access below the rule threshold; intentional miss."),
    ]
    events = []
    scenarios = []
    for scenario_id, actor, address, truth, first_id, times, candidate, explanation in definitions:
        event_ids = []
        for index, stamp in enumerate(times):
            event_id = "evt_{:03d}".format(first_id + index)
            event_ids.append(event_id)
            events.append({
                "schema_version": "1.0",
                "event_id": event_id,
                "timestamp": "2026-01-15T" + stamp,
                "actor_id": actor,
                "event_type": "sign_in",
                "outcome": "success" if index == len(times) - 1 else "failure",
                "source": "identity_audit",
                "source_ip": address,
                "session_id": "session_{:03d}".format(first_id + index),
            })
        scenarios.append({
            "scenario_id": scenario_id,
            "security_truth": truth,
            "authored_explanation": explanation,
            "event_ids": event_ids,
            "expected_candidates": [{
                "rule_id": "signin_failure_then_success",
                "rule_version": "1.0",
                "success_event_id": event_ids[-1],
                "evidence_event_ids": event_ids,
            }] if candidate else [],
        })
    random.Random(seed).shuffle(events)
    labels = {
        "label_version": "1.0",
        "synthetic": True,
        "seed": seed,
        "input_path": "data/events/signins.jsonl",
        "counting_unit": "scenario",
        "matching_method": "Exact rule_id, success_event_id and ordered evidence_event_ids; no extra candidates.",
        "status": "authored expectations; detector has not been run",
        "scenarios": scenarios,
    }
    return events, labels


def generate(output_dir, seed):
    events, labels = build_fixtures(seed)
    event_path = output_dir / "data" / "events" / "signins.jsonl"
    label_path = output_dir / "data" / "labels" / "signins.json"
    event_path.parent.mkdir(parents=True, exist_ok=True)
    label_path.parent.mkdir(parents=True, exist_ok=True)
    # Explicit byte writes keep LF line endings stable across platforms.
    event_path.write_bytes(("\n".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")) for event in events
    ) + "\n").encode("utf-8"))
    label_path.write_bytes((json.dumps(labels, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return {
        "seed": seed,
        "events": len(events),
        "scenarios": len(labels["scenarios"]),
        "files": [{
            "path": str(path.relative_to(output_dir)),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        } for path in (event_path, label_path)],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output-dir", type=Path, default=PROJECT_ROOT,
                        help="Destination root; overwrites only the two generated fixture files.")
    args = parser.parse_args()
    try:
        result = generate(args.output_dir.resolve(), args.seed)
    except OSError as exc:
        parser.exit(1, "Fixture generation failed: {}\n".format(exc))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
