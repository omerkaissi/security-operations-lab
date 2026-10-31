"""Strict event ingestion and the Checkpoint 02 sign-in detector."""

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import re

IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,96}\Z")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(Z|[+-][0-9]{2}:[0-9]{2})\Z")
COMMON = {"schema_version", "event_id", "timestamp", "actor_id", "event_type", "outcome", "source"}
OPTIONAL = {"session_id", "source_ip"}
EXTRA = {"sign_in": set(), "role_change": {"target_user_id", "previous_role", "new_role", "change_id"}, "data_export": {"resource", "record_count"}}
REQUIRED = {"sign_in": set(), "role_change": {"target_user_id", "previous_role", "new_role"}, "data_export": {"resource", "record_count"}}
ROLES = {"none", "member", "support", "data_export_admin", "organization_admin"}


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def bad_constant(value):
        raise ValueError(f"invalid JSON constant: {value}")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)


def utc_timestamp(value):
    if not isinstance(value, str) or not (match := TIMESTAMP.fullmatch(value)):
        raise ValueError("timestamp must include seconds and a timezone")
    offset = match.group(1)
    if offset != "Z" and (int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise ValueError("invalid timezone offset")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError) as exc:
        raise ValueError("invalid timestamp") from exc


def validate_event(event):
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    kind = event.get("event_type")
    if not isinstance(kind, str) or kind not in EXTRA:
        raise ValueError("invalid event_type")
    missing = (COMMON | REQUIRED[kind]) - event.keys()
    unknown = event.keys() - (COMMON | OPTIONAL | EXTRA[kind])
    if missing:
        raise ValueError("missing fields: " + ", ".join(sorted(missing)))
    if unknown:
        raise ValueError("unknown or disallowed fields: " + ", ".join(sorted(unknown)))
    if any(value is None for value in event.values()):
        raise ValueError("explicit null is invalid")
    if event["schema_version"] != "1.0" or event["outcome"] not in ("success", "failure"):
        raise ValueError("invalid schema_version or outcome")
    if event["source"] != ("application_audit" if kind == "data_export" else "identity_audit"):
        raise ValueError("invalid source for event_type")
    for key in ("event_id", "actor_id", "session_id", "target_user_id", "change_id"):
        if key in event and (not isinstance(event[key], str) or not IDENTIFIER.fullmatch(event[key])):
            raise ValueError(f"invalid {key}")
    normalized = dict(event)
    normalized["timestamp"] = utc_timestamp(event["timestamp"])
    if "source_ip" in event:
        if not isinstance(event["source_ip"], str):
            raise ValueError("invalid source_ip")
        try:
            normalized["source_ip"] = str(ipaddress.ip_address(event["source_ip"]))
        except ValueError as exc:
            raise ValueError("invalid source_ip") from exc
    for key in ("previous_role", "new_role"):
        if key in event and (not isinstance(event[key], str) or event[key] not in ROLES):
            raise ValueError(f"invalid {key}")
    if kind == "data_export":
        if event["resource"] not in ("account_activity_metadata", "public_activity_catalog"):
            raise ValueError("invalid resource")
        if type(event["record_count"]) is not int or event["record_count"] < 0:
            raise ValueError("record_count must be a nonnegative integer")
    return normalized


def sort_key(event):
    return (datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")),
            0 if event["event_type"] == "sign_in" and event["outcome"] == "failure" else 1,
            event["event_id"])


def load_events(path):
    variants = defaultdict(dict)
    errors = []
    duplicates = 0
    line_count = 0
    with open(path, "rb") as stream:
        for line_count, line in enumerate(stream, 1):
            try:
                event = validate_event(strict_json(line.decode("utf-8")))
            except (ValueError, TypeError, UnicodeError) as exc:
                errors.append({"line": line_count, "error": str(exc)})
                continue
            fingerprint = json.dumps(event, sort_keys=True, separators=(",", ":"))
            group = variants[event["event_id"]]
            if fingerprint in group:
                duplicates += 1
                group[fingerprint][1].append(line_count)
            else:
                group[fingerprint] = [event, [line_count]]
    if not line_count:
        errors.append({"line": None, "error": "input file is empty"})
    conflicts = []
    accepted = []
    for event_id, group in sorted(variants.items()):
        if len(group) > 1:
            lines = sorted(line for _, references in group.values() for line in references)
            conflicts.append({"event_id": event_id, "lines": lines})
        else:
            accepted.append(next(iter(group.values()))[0])
    accepted.sort(key=sort_key)
    return accepted, {"input_lines": line_count, "valid_unique_events_accepted": len(accepted),
                      "rejected_lines": sum(error["line"] is not None for error in errors),
                      "duplicate_lines": duplicates, "conflicted_ids": len(conflicts),
                      "errors": errors, "conflicts": conflicts}


def load_policy(path):
    with open(path, encoding="utf-8") as stream:
        policy = strict_json(stream.read())
    if not isinstance(policy, dict) or policy.get("policy_version") != "1.0" or policy.get("synthetic") is not True:
        raise ValueError("invalid policy version or synthetic flag")
    sign_in = policy.get("sign_in")
    expected = {"minimum_failures", "failure_window_seconds", "success_delay_seconds", "inclusive_boundaries", "reset_on_every_success"}
    if not isinstance(sign_in, dict) or set(sign_in) not in (expected, expected | {"rule_version"}):
        raise ValueError("invalid sign_in policy fields")
    if sign_in.get("rule_version", "1.0") not in ("1.0", "1.1"):
        raise ValueError("invalid sign_in rule version")
    for key in ("minimum_failures", "failure_window_seconds", "success_delay_seconds"):
        if type(sign_in[key]) is not int or sign_in[key] < (1 if key == "minimum_failures" else 0):
            raise ValueError(f"invalid sign_in policy {key}")
    if any(sign_in[key] > 86400 * 999999999 for key in ("failure_window_seconds", "success_delay_seconds")):
        raise ValueError("sign_in policy window exceeds supported duration")
    if sign_in["inclusive_boundaries"] is not True or sign_in["reset_on_every_success"] is not True:
        raise ValueError("sign_in policy must use inclusive boundaries and reset on every success")
    from .rules import validate_other_policy
    validate_other_policy(policy)
    return policy


def detect(events, policy):
    failures = defaultdict(list)
    alerts = []
    version = policy.get("rule_version", "1.0")
    for event in events:
        if event["event_type"] != "sign_in":
            continue
        actor = event["actor_id"]
        if event["outcome"] == "failure":
            failures[actor].append(event)
            continue
        sequence = failures.pop(actor, [])
        if not sequence:
            continue
        success_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
        latest = datetime.fromisoformat(sequence[-1]["timestamp"].replace("Z", "+00:00"))
        included = [failure for failure in sequence if latest - datetime.fromisoformat(failure["timestamp"].replace("Z", "+00:00")) <= timedelta(seconds=policy["failure_window_seconds"])]
        if len(included) < policy["minimum_failures"] or not timedelta(0) <= success_time - latest <= timedelta(seconds=policy["success_delay_seconds"]):
            continue
        evidence = sorted(included + [event], key=lambda e: (datetime.fromisoformat(e["timestamp"].replace("Z", "+00:00")), e["event_id"]))
        alerts.append({"alert_id": f"signin_failure_then_success:{version}:{event['event_id']}",
                       "rule_id": "signin_failure_then_success", "rule_version": version, "actor_id": actor,
                       "resource": None, "timestamp": event["timestamp"], "success_event_id": event["event_id"],
                       "failure_window_start": included[0]["timestamp"], "latest_failure_time": sequence[-1]["timestamp"],
                       "failure_count": len(included), "evidence_event_ids": [item["event_id"] for item in evidence],
                       "severity": "medium", "confidence": "pattern observed; compromise unconfirmed",
                       "priority_rationale": "Repeated failures followed by a success warrant investigation.",
                       "reason": f"{len(included)} failures followed by a success within the configured windows.",
                       "missing_context": ["MFA decisions", "device posture", "user confirmation", "session telemetry"]
                       + (["source IP missing from one or more evidence events"] if any("source_ip" not in item for item in evidence) else [])
                       + (["session ID missing from one or more evidence events"] if any("session_id" not in item for item in evidence) else []),
                       "next_action": "Review sign-in and session context and confirm the activity with the user.", "status": "open"})
    return alerts
