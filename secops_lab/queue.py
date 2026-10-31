"""Deterministic triage order and two human-readable queue formats."""
import csv
from datetime import datetime
import io

PRIORITY = {"high": 0, "medium": 1, "low": 2}
COLUMNS = ("run_status", "investigation_id", "severity", "timestamp", "alert_id", "actor_id", "resource", "confidence", "priority_rationale", "reason", "evidence_event_ids", "next_action", "status")


def prepare(alerts):
    for alert in alerts:
        alert["investigation_id"] = "investigation:" + alert["actor_id"]
    return sorted(alerts, key=lambda alert: (PRIORITY[alert["severity"]], datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00")), alert["alert_id"]))


def rows(alerts, status):
    if not alerts:
        yield {key: (status if key == "run_status" else "") for key in COLUMNS}
    for alert in alerts:
        yield {key: (status if key == "run_status" else ", ".join(alert[key]) if key == "evidence_event_ids" else alert.get(key) or "") for key in COLUMNS}


def csv_text(alerts, status):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows(alerts, status))
    return output.getvalue()


def markdown_text(alerts, status):
    def escape(value):
        return str(value).replace("|", "\\|").replace("\n", " ")
    lines = ["# Alert queue", "", f"Run status: **{status}**. Grouping by actor is a triage aid, not a finding of causation.", "",
             "| " + " | ".join(COLUMNS) + " |", "| " + " | ".join("---" for _ in COLUMNS) + " |"]
    lines.extend("| " + " | ".join(escape(row[key]) for key in COLUMNS) + " |" for row in rows(alerts, status))
    return "\n".join(lines) + "\n"
