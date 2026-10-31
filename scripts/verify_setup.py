#!/usr/bin/env python3
"""Check authored Checkpoint 01 fixtures; this is not detector evaluation."""

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SEED = 20261030
FIXTURES = ("data/events/signins.jsonl", "data/labels/signins.json")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc(stamp):
    value = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    require(value.tzinfo is not None, "Missing timezone")
    return value.astimezone(timezone.utc)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="reports/runs/setup_verification.json")
    args = parser.parse_args()
    checks = []
    for name in ("schema/event.schema.json", "config/policy.json", "config/context.json", FIXTURES[1]):
        json.loads((ROOT / name).read_text(encoding="utf-8"))
    checks.append("Schema, policy, context and labels parse as JSON (not full JSON Schema validation).")

    events = [json.loads(line) for line in (ROOT / FIXTURES[0]).read_text(encoding="utf-8").splitlines()]
    labels = json.loads((ROOT / FIXTURES[1]).read_text(encoding="utf-8"))
    by_id = {event["event_id"]: event for event in events}
    require(len(events) == len(by_id) == 19, "Expected 19 unique authored events")
    require(set(by_id) == {"evt_{:03d}".format(n) for n in range(1, 20)}, "Fixture ID inventory differs")
    require(sum(e["outcome"] == "success" for e in events) == 4, "Expected four successes")
    require(sum(e["outcome"] == "failure" for e in events) == 15, "Expected fifteen failures")
    require(len({e["actor_id"] for e in events}) == 4, "Expected four actors")
    checks.append("19 unique events, four actors, four successes and fifteen failures.")

    expected_keys = {"schema_version", "event_id", "timestamp", "actor_id", "event_type", "outcome", "source", "source_ip", "session_id"}
    ranges = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    for event in events:
        require(set(event) == expected_keys, "Unexpected event fields (possible label leakage)")
        require(event["schema_version"] == "1.0" and event["event_type"] == "sign_in", "Wrong fixture schema/type")
        require(event["source"] == "identity_audit", "Wrong source")
        for key in ("event_id", "actor_id", "session_id"):
            require(re.fullmatch(r"[A-Za-z0-9_-]{1,96}", event[key]) is not None, "Bad identifier")
        utc(event["timestamp"])
        require(any(ipaddress.ip_address(event["source_ip"]) in network for network in ranges), "Non-documentation IP")
    require(utc(by_id["evt_007"]["timestamp"]).isoformat() == "2026-01-15T10:00:00+00:00", "Offset fixture drift")
    chronological = sorted(events, key=lambda event: (utc(event["timestamp"]), event["event_id"]))
    require(events != chronological, "Expected intentionally shuffled inputs")
    checks.append("Initial sign-in field shape, timezone parsing, offset conversion, example IP ranges and shuffled order checked.")

    expected_membership = {"S01": list(range(1, 7)), "S02": list(range(7, 13)), "S03": [13, 14], "S04": list(range(15, 20))}
    require(len(labels["scenarios"]) == 4, "Expected four scenario records")
    require({s["scenario_id"] for s in labels["scenarios"]} == set(expected_membership), "Scenario inventory differs")
    all_labeled = []
    for scenario in labels["scenarios"]:
        ids = ["evt_{:03d}".format(n) for n in expected_membership[scenario["scenario_id"]]]
        require(scenario["event_ids"] == ids, "Scenario membership differs from authored matrix")
        require(len({by_id[e]["actor_id"] for e in ids}) == 1, "Mixed-actor scenario")
        all_labeled.extend(ids)
        expected_candidates = [{"rule_id": "signin_failure_then_success", "rule_version": "1.0", "success_event_id": ids[-1], "evidence_event_ids": ids}] if scenario["scenario_id"] in ("S01", "S02") else []
        require(scenario["expected_candidates"] == expected_candidates, "Expected labels drifted")
        require(by_id[ids[-1]]["outcome"] == "success", "Scenario does not end in success")
        expected_truth = "malicious" if scenario["scenario_id"] in ("S01", "S04") else "benign"
        require(scenario["security_truth"] == expected_truth, "Intent labels drifted")
    require(sorted(all_labeled) == sorted(by_id), "Missing, duplicated or orphaned labeled event")
    require((utc(by_id["evt_005"]["timestamp"]) - utc(by_id["evt_001"]["timestamp"])).total_seconds() == 600, "Failure boundary drift")
    require((utc(by_id["evt_006"]["timestamp"]) - utc(by_id["evt_005"]["timestamp"])).total_seconds() == 300, "Success boundary drift")
    checks.append("Authored scenario membership, truth, expected evidence references and exact 600/300-second fixtures match the matrix; no detector executed.")

    commands = []
    with tempfile.TemporaryDirectory(prefix="secops-cp01-") as temporary:
        base = Path(temporary)
        for destination, seed in (("a", SEED), ("b", SEED), ("c", SEED + 1)):
            command = [sys.executable, str(ROOT / "scripts/generate_fixtures.py"), "--seed", str(seed), "--output-dir", str(base / destination)]
            result = subprocess.run(command, text=True, capture_output=True)
            require(result.returncode == 0, "Isolated fixture generation failed: " + result.stderr)
            json.loads(result.stdout)
            commands.append({"command": "{} scripts/generate_fixtures.py --seed {} --output-dir <temporary>/{}".format(sys.executable, seed, destination), "exit_status": result.returncode})
        for relative in FIXTURES:
            require((ROOT / relative).read_bytes() == (base / "a" / relative).read_bytes() == (base / "b" / relative).read_bytes(), "Fixed-seed output differs")
        different_events = [json.loads(line) for line in (base / "c" / FIXTURES[0]).read_text().splitlines()]
        require(events != different_events, "Different seed did not change order")
        require(sorted(events, key=lambda e: e["event_id"]) == sorted(different_events, key=lambda e: e["event_id"]), "Different seed changed event semantics")
    checks.append("Two isolated fixed-seed runs match the project fixture bytes; a different seed changes ordering only.")

    report = {
        "checkpoint": "01", "verification_kind": "setup and fixture integrity only",
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "passed", "python": platform.python_version(),
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "seed": SEED, "event_count": len(events), "scenario_count": len(labels["scenarios"]),
        "expected_candidate_count": 2, "observed_detector_results": None,
        "checks": checks, "isolated_generation_commands": commands,
        "fixture_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in FIXTURES},
        "python_baseline_met": sys.version_info >= (3, 12),
        "limitations": ["This report records the interpreter used; it does not discover other installed interpreters.", "This script does not inspect Git state.", "Not a complete runtime schema validator, detector test suite or measured security evaluation."],
    }
    target = Path(args.output)
    if not target.is_absolute():
        target = ROOT / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print("Setup verification failed: {}".format(exc), file=sys.stderr)
        sys.exit(1)
