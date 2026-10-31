"""Author fictional multi-rule fixtures and separate expected outcomes offline."""
import json
from pathlib import Path
import random

ROOT = Path(__file__).resolve().parents[1]


def role(event_id, stamp, actor="actor_017", target="actor_analyst_01", new="data_export_admin", outcome="success", change=None):
    e = {"schema_version": "1.0", "event_id": event_id, "timestamp": "2026-01-15T" + stamp + "Z", "actor_id": actor,
         "event_type": "role_change", "outcome": outcome, "source": "identity_audit", "target_user_id": target,
         "previous_role": "member", "new_role": new}
    if change is not None:
        e["change_id"] = change
    return e


def export(event_id, stamp, actor, count, resource="account_activity_metadata"):
    return {"schema_version": "1.0", "event_id": event_id, "timestamp": "2026-01-15T" + stamp + "Z", "actor_id": actor,
            "event_type": "data_export", "outcome": "success", "source": "application_audit", "resource": resource, "record_count": count}


def expected(rule, anchor, evidence):
    return {"rule_id": rule, "rule_version": "1.0", "anchor_event_id": anchor, "evidence_event_ids": evidence}


def main():
    events = [json.loads(line) for line in (ROOT / "data/events/signins.jsonl").read_text().splitlines()]
    scenarios = json.loads((ROOT / "data/labels/signins.json").read_text())["scenarios"]
    additions = [
        ("R01", "benign", [role("role_001", "13:00:00", actor="actor_admin_01", change="CHG-LAB-001")], []),
        ("R02", "malicious", [role("role_002", "13:01:00")], [expected("unexpected_protected_role", "role_002", ["role_002"])]),
        ("R03", "benign", [role("role_003", "13:02:00", actor="actor_benign_01", change="CHG-UNKNOWN")], [expected("unexpected_protected_role", "role_003", ["role_003"])]),
        ("R04", "malicious", [role("role_004", "13:31:00", actor="actor_admin_01", change="CHG-LAB-001")], [expected("unexpected_protected_role", "role_004", ["role_004"])]),
        ("R05", "benign", [role("role_005", "13:03:00", outcome="failure")], []),
        ("R06", "benign", [role("role_006", "13:04:00", new="support")], []),
        ("E01", "malicious", [export("exp_001", "04:00:00", "actor_export_01", 400), export("exp_002", "04:15:00", "actor_export_01", 600)], [expected("large_export", "exp_002", ["exp_001", "exp_002"])]),
        ("E02", "benign", [export("exp_003", "02:00:00", "actor_job_01", 700), export("exp_004", "02:05:00", "actor_job_01", 800)], []),
        ("E03", "malicious", [export("exp_005", "02:06:00", "actor_job_01", 1)], [expected("large_export", "exp_005", ["exp_003", "exp_004", "exp_005"])]),
        ("E04", "malicious", [export("exp_006", "02:22:00", "actor_job_01", 1000)], [expected("large_export", "exp_006", ["exp_006"])]),
        ("E05", "benign", [export("exp_007", "05:00:00", "actor_export_02", 999)], []),
        ("E06", "benign", [export("exp_008", "06:00:00", "actor_export_03", 1000, "public_activity_catalog")], [expected("large_export", "exp_008", ["exp_008"])])]
    for name, truth, records, candidates in additions:
        events.extend(records)
        scenarios.append({"scenario_id": name, "security_truth": truth, "event_ids": [record["event_id"] for record in records], "expected_candidates": candidates})
    random.Random(20261031).shuffle(events)
    event_path = ROOT / "data/events/checkpoint03.jsonl"
    label_path = ROOT / "data/labels/checkpoint03.json"
    event_path.write_text("".join(json.dumps(item, sort_keys=True, separators=(",", ":")) + "\n" for item in events), encoding="utf-8")
    label_path.write_text(json.dumps({"label_version": "1.0", "synthetic": True, "input_path": "data/events/checkpoint03.jsonl", "scenarios": scenarios}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Wrote {len(events)} events and {len(scenarios)} separately labeled scenarios")


if __name__ == "__main__":
    main()
