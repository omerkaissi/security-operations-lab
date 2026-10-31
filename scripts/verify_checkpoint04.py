"""Verify Checkpoint 04 document links, evidence references and selected factual claims."""
import argparse
from datetime import datetime
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CASES = [ROOT / "docs/investigations/actor_017.md", ROOT / "docs/investigations/actor_029.md"]
PLAYBOOK = ROOT / "docs/phishing_response_playbook.md"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def verify_followup(document, events):
    require(document.get("synthetic") is True and document.get("artifact_version") == "1.0", "invalid follow-up metadata")
    items = document.get("records")
    require(isinstance(items, list), "missing follow-up records")
    records = {item["evidence_id"]: item for item in items}
    require(len(records) == len(items) and set(records) == {"FU029_USER", "FU029_MFA", "FU017_USER", "FU017_CHANGE"}, "invalid or duplicate follow-up IDs")
    checks = {"FU029_USER": ("investigation:actor_029", "actor_029", "fictional_user_confirmation", "owner_recognizes"),
              "FU017_USER": ("investigation:actor_017", "actor_017", "fictional_user_confirmation", "owner_denies")}
    for key, (case, actor, kind, confirmation) in checks.items():
        item = records[key]
        require((item.get("case_id"), item.get("actor_id"), item.get("type"), item.get("confirmation")) == (case, actor, kind, confirmation), f"invalid {key} assertion")
    for key, item in records.items():
        ids = item.get("event_ids")
        require(isinstance(ids, list) and ids and all(event_id in events for event_id in ids), f"unknown referenced event in {key}")
        require(all(events[event_id]["actor_id"] == item["actor_id"] for event_id in ids), f"actor mismatch in {key}")
        require(all(instant(item["recorded_at"]) >= instant(events[event_id]["timestamp"]) for event_id in ids), f"follow-up precedes event in {key}")
        case = CASES[0] if item["case_id"] == "investigation:actor_017" else CASES[1]
        require(key in case.read_text(encoding="utf-8"), f"follow-up not cited in {case.name}")
    mfa = records["FU029_MFA"]
    require(mfa["case_id"] == "investigation:actor_029" and mfa["actor_id"] == "actor_029" and mfa["event_ids"] == ["evt_012"] and mfa["session_id"] == events["evt_012"]["session_id"] and mfa["mfa_result"] == "success" and mfa["device_assessment"] == "known", "invalid MFA follow-up")
    change = records["FU017_CHANGE"]
    event = events["role_002"]
    require(change["case_id"] == "investigation:actor_017" and change["actor_id"] == "actor_017" and change["event_ids"] == ["role_002"] and change["target_user_id"] == event["target_user_id"] and change["new_role"] == event["new_role"] and change["authorization_result"] == "not_authorized", "invalid change follow-up")
    require(records["FU029_USER"]["event_ids"] == [f"evt_{i:03}" for i in range(7,13)] and records["FU017_USER"]["event_ids"] == ["evt_006"], "confirmation event references mismatch")
    return sorted(records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="reports/strengthening/investigation_evidence_check.json")
    args = parser.parse_args()
    events = [json.loads(line) for line in (ROOT / "data/events/checkpoint03.jsonl").read_text(encoding="utf-8").splitlines()]
    by_id = {event["event_id"]: event for event in events}
    require(len(by_id) == len(events), "duplicate event IDs in source file")
    result = json.loads((ROOT / "reports/checkpoint03_alerts.json").read_text(encoding="utf-8"))
    alerts = {alert["alert_id"]: alert for alert in result["alerts"]}
    require(result["status"] == "complete" and len(alerts) == len(result["alerts"]), "source alert output incomplete or duplicate IDs")
    labels = json.loads((ROOT / "data/labels/checkpoint03.json").read_text(encoding="utf-8"))
    policy = json.loads((ROOT / "config/policy.json").read_text(encoding="utf-8"))
    summary = []
    for case in CASES:
        content = case.read_text(encoding="utf-8")
        cited_events = set(re.findall(r"\b(?:evt|role|exp)_\d{3}\b", content))
        cited_alerts = set(re.findall(r"\b(?:signin_failure_then_success|unexpected_protected_role|large_export):1\.0:(?:evt|role|exp)_\d{3}\b", content))
        require(cited_events and cited_alerts, f"missing evidence references in {case.name}")
        require(cited_events <= by_id.keys(), f"unknown event IDs in {case.name}: {sorted(cited_events - by_id.keys())}")
        require(cited_alerts <= alerts.keys(), f"unknown alert IDs in {case.name}: {sorted(cited_alerts - alerts.keys())}")
        for alert_id in cited_alerts:
            require(set(alerts[alert_id]["evidence_event_ids"]) <= cited_events, f"alert evidence not fully cited in {case.name}")
        summary.append({"document": str(case.relative_to(ROOT)), "event_ids": sorted(cited_events), "alert_ids": sorted(cited_alerts)})
    for doc in [*CASES, PLAYBOOK]:
        content = doc.read_text(encoding="utf-8")
        for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", content):
            require((doc.parent / target).is_file(), f"broken local link {target} in {doc.name}")
    first = [by_id[f"evt_{i:03}"] for i in range(1, 7)]
    second = [by_id[f"evt_{i:03}"] for i in range(7, 13)]
    for items, actor in ((first, "actor_017"), (second, "actor_029")):
        require(all(e["actor_id"] == actor and e["outcome"] == "failure" for e in items[:5]), "failure sequence mismatch")
        require(items[5]["actor_id"] == actor and items[5]["outcome"] == "success", "success event mismatch")
        require(all(instant(items[i]["timestamp"]) <= instant(items[i+1]["timestamp"]) for i in range(5)), "event ordering mismatch")
    require((instant(first[4]["timestamp"]) - instant(first[0]["timestamp"])).total_seconds() == 600, "first failure span mismatch")
    require((instant(first[5]["timestamp"]) - instant(first[4]["timestamp"])).total_seconds() == 300, "first success delay mismatch")
    require((instant(second[5]["timestamp"]) - instant(second[4]["timestamp"])).total_seconds() == 30, "second success delay mismatch")
    require(first[0]["source_ip"] == "192.0.2.17" and all(e["source_ip"] == first[0]["source_ip"] for e in first), "first IP mismatch")
    require(second[0]["source_ip"] == "198.51.100.29" and all(e["source_ip"] == second[0]["source_ip"] for e in second), "second IP mismatch")
    require(len({e["session_id"] for e in first}) == 6 and len({e["session_id"] for e in second}) == 6, "session IDs mismatch")
    change = by_id["role_002"]
    require(change["timestamp"] == "2026-01-15T13:01:00Z" and change["actor_id"] == "actor_017" and change["target_user_id"] == "actor_analyst_01" and change["previous_role"] == "member" and change["new_role"] == "data_export_admin" and change["outcome"] == "success" and "change_id" not in change, "role change mismatch")
    require((instant(change["timestamp"]) - instant(first[5]["timestamp"])).total_seconds() == 3 * 3600 + 46 * 60, "case time difference mismatch")
    approval = next(item for item in policy["role_change"]["approved_changes"] if item["change_id"] == "CHG-LAB-001")
    require(approval["actor_id"] == "actor_admin_01" and approval["target_user_id"] == change["target_user_id"] and approval["new_role"] == change["new_role"] and instant(approval["valid_from"]) <= instant(change["timestamp"]) <= instant(approval["valid_until"]), "role approval comparison mismatch")
    require(next(s for s in labels["scenarios"] if s["scenario_id"] == "S02")["security_truth"] == "benign", "training truth mismatch")
    require("PAPER-MSG-01" in PLAYBOOK.read_text(encoding="utf-8"), "paper exercise marker missing")
    followup = json.loads((ROOT / "data/investigations/followup_evidence_v1.json").read_text(encoding="utf-8"))
    followup_ids = verify_followup(followup, by_id)
    report = {"checkpoint": "04", "status": "passed", "verification_kind": "document links, cited ID existence and selected source claims; self-review, not independent review", "cases": summary, "followup_evidence_ids": followup_ids,
              "checks": ["Each cited alert and event ID exists; all evidence IDs for each cited alert appear in its case.", "Document Markdown links resolve locally.", "Selected sign-in timing, actor, IP, session, role and approval details match source records.", "The separate benign scenario label and paper-only exercise marker are present.", "Follow-up IDs, event links, chronology, fictional confirmations, MFA session and role-review assertions were checked."],
              "limitations": ["Automated checks do not prove every narrative statement, interpret intent, or independently review the documents.", "Paper exercise statements are fictional assumptions, not observed logs or performed actions."]}
    target = Path(args.output)
    if not target.is_absolute(): target = ROOT / target
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        print(f"Checkpoint 04 verification failed: {exc}", file=sys.stderr)
        sys.exit(1)
