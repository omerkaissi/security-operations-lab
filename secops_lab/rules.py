"""Policy validation and the role/export rules; no evaluation labels are read."""
from collections import defaultdict
from datetime import datetime, timedelta
from .core import IDENTIFIER, ROLES, utc_timestamp

RESOURCES = {"fitness_session_metadata", "public_activity_catalog"}


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def validate_other_policy(policy):
    role = policy.get("role_change")
    export = policy.get("export")
    if not isinstance(role, dict) or set(role) != {"protected_roles", "approved_changes"}:
        raise ValueError("invalid role_change policy fields")
    roles = role["protected_roles"]
    if not isinstance(roles, list) or not roles or any(not isinstance(x, str) or x not in ROLES for x in roles) or len(set(roles)) != len(roles):
        raise ValueError("invalid protected_roles")
    if not isinstance(role["approved_changes"], list):
        raise ValueError("approved_changes must be a list")
    seen = set()
    for item in role["approved_changes"]:
        fields = {"change_id", "actor_id", "target_user_id", "new_role", "valid_from", "valid_until"}
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("invalid role approval fields")
        if any(not identifier(item[k]) for k in ("change_id", "actor_id", "target_user_id")) or not isinstance(item["new_role"], str) or item["new_role"] not in ROLES:
            raise ValueError("invalid role approval identity or role")
        if item["change_id"] in seen:
            raise ValueError("duplicate change_id")
        seen.add(item["change_id"])
        check_interval(item)
    if not isinstance(export, dict) or set(export) != {"record_threshold", "window_seconds", "approved_exports"}:
        raise ValueError("invalid export policy fields")
    for key in ("record_threshold", "window_seconds"):
        if type(export[key]) is not int or export[key] < (1 if key == "record_threshold" else 0):
            raise ValueError(f"invalid export {key}")
    if export["window_seconds"] > 86400 * 999999999:
        raise ValueError("export window exceeds supported duration")
    if not isinstance(export["approved_exports"], list):
        raise ValueError("approved_exports must be a list")
    seen = set()
    groups = defaultdict(list)
    for item in export["approved_exports"]:
        fields = {"approval_id", "actor_id", "resource", "valid_from", "valid_until", "maximum_total_records"}
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("invalid export approval fields")
        if not identifier(item["approval_id"]) or not identifier(item["actor_id"]) or not isinstance(item["resource"], str) or item["resource"] not in RESOURCES:
            raise ValueError("invalid export approval identity or resource")
        if type(item["maximum_total_records"]) is not int or item["maximum_total_records"] < 0:
            raise ValueError("invalid export approval maximum_total_records")
        if item["approval_id"] in seen:
            raise ValueError("duplicate approval_id")
        seen.add(item["approval_id"])
        check_interval(item)
        groups[(item["actor_id"], item["resource"])].append(item)
    for approvals in groups.values():
        approvals.sort(key=lambda x: instant(x["valid_from"]))
        if any(instant(a["valid_until"]) >= instant(b["valid_from"]) for a, b in zip(approvals, approvals[1:])):
            raise ValueError("overlapping export approvals for actor and resource")


def check_interval(item):
    item["valid_from"] = utc_timestamp(item["valid_from"])
    item["valid_until"] = utc_timestamp(item["valid_until"])
    if instant(item["valid_from"]) > instant(item["valid_until"]):
        raise ValueError("approval validity interval is reversed")


def role_alerts(events, policy):
    alerts = []
    for event in events:
        if event["event_type"] != "role_change" or event["outcome"] != "success" or event["new_role"] not in policy["protected_roles"]:
            continue
        comparisons = []
        for approval in sorted(policy["approved_changes"], key=lambda x: x["change_id"]):
            checks = {"change_id": event.get("change_id") == approval["change_id"],
                      "actor_id": event["actor_id"] == approval["actor_id"],
                      "target_user_id": event["target_user_id"] == approval["target_user_id"],
                      "new_role": event["new_role"] == approval["new_role"],
                      "valid_interval": instant(approval["valid_from"]) <= instant(event["timestamp"]) <= instant(approval["valid_until"])}
            comparisons.append({"approval": approval, "checks": checks, "matches": all(checks.values())})
        if any(c["matches"] for c in comparisons):
            continue
        if "change_id" not in event:
            reason = "No change ID supplied."
        elif not any(c["checks"]["change_id"] for c in comparisons):
            reason = "Change ID is unknown to policy."
        else:
            reason = "Known change ID has mismatched or out-of-interval approval dimensions."
        alerts.append({"alert_id": f"unexpected_protected_role:1.0:{event['event_id']}",
                       "rule_id": "unexpected_protected_role", "rule_version": "1.0", "anchor_event_id": event["event_id"],
                       "actor_id": event["actor_id"], "target_user_id": event["target_user_id"], "resource": None,
                       "timestamp": event["timestamp"], "new_role": event["new_role"], "change_id": event.get("change_id"),
                       "evidence_event_ids": [event["event_id"]], "approval_comparisons": comparisons,
                       "severity": "high", "confidence": "assignment observed; authorization and intent unconfirmed",
                       "priority_rationale": "A protected role can grant broad privileges.", "reason": reason,
                       "missing_context": ["independent change confirmation", "actor intent"] + (["change ID"] if "change_id" not in event else []) + (["source IP"] if "source_ip" not in event else []) + (["session ID"] if "session_id" not in event else []),
                       "next_action": "Verify the assignment and change authorization with the responsible team.", "status": "open"})
    return alerts


def export_alerts(events, policy):
    approvals = sorted(policy["approved_exports"], key=lambda x: x["approval_id"])
    used = defaultdict(int)
    windows = defaultdict(list)
    alerts = []
    for event in events:
        if event["event_type"] != "data_export" or event["outcome"] != "success":
            continue
        now = instant(event["timestamp"])
        comparisons = []
        matched = None
        for approval in approvals:
            checks = {"actor_id": event["actor_id"] == approval["actor_id"],
                      "resource": event["resource"] == approval["resource"],
                      "valid_interval": instant(approval["valid_from"]) <= now <= instant(approval["valid_until"])}
            comparison = {"approval": approval, "checks": checks, "matches": all(checks.values()),
                          "used_before_event": used[approval["approval_id"]]}
            comparisons.append(comparison)
            if comparison["matches"]:
                matched = approval
        approved = over_cap = 0
        unapproved = event["record_count"]
        if matched:
            key = matched["approval_id"]
            approved = min(event["record_count"], max(0, matched["maximum_total_records"] - used[key]))
            over_cap = event["record_count"] - approved
            unapproved = 0
            used[key] += event["record_count"]
        allocation = {"event_id": event["event_id"], "timestamp": event["timestamp"], "record_count": event["record_count"],
                      "approved": approved, "unapproved": unapproved, "over_cap": over_cap,
                      "approval_id": matched["approval_id"] if matched else None, "approval_comparisons": comparisons}
        group = (event["actor_id"], event["resource"])
        window = [item for item in windows[group] if now - instant(item["timestamp"]) <= timedelta(seconds=policy["window_seconds"])]
        window.append(allocation)
        windows[group] = window
        totals = {key: sum(item[key] for item in window) for key in ("record_count", "approved", "unapproved", "over_cap")}
        if not (totals["over_cap"] > 0 or (totals["record_count"] >= policy["record_threshold"] and totals["unapproved"] + totals["over_cap"] > 0)):
            continue
        alerts.append({"alert_id": f"large_export:1.0:{event['event_id']}", "rule_id": "large_export", "rule_version": "1.0",
                       "anchor_event_id": event["event_id"], "actor_id": event["actor_id"], "resource": event["resource"],
                       "timestamp": event["timestamp"], "window_seconds": policy["window_seconds"],
                       "window_first_event_time": window[0]["timestamp"], "window_totals": totals,
                       "evidence_event_ids": [item["event_id"] for item in window], "event_allocations": window.copy(),
                       "severity": "high", "confidence": "export volume observed; intent unconfirmed",
                       "priority_rationale": "Large or over-cap exports may expose sensitive information.",
                       "reason": "Rolling window contains unapproved volume at threshold or an exceeded approval cap.",
                       "missing_context": ["export destination", "export purpose", "earlier approval-period events may be absent"],
                       "next_action": "Review the export purpose, destination, approval usage and surrounding activity.", "status": "open"})
    return alerts
