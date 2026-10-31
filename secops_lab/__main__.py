"""Run the offline detectors and produce JSON and optional triage queues."""
import argparse
import json
from pathlib import Path
import sys
from .core import detect, load_events, load_policy
from .queue import prepare, csv_text, markdown_text
from .rules import export_alerts, role_alerts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", help="JSONL event input")
    parser.add_argument("--policy", default="config/policy.json", help="operational policy JSON")
    parser.add_argument("--output", help="write JSON to this path instead of stdout")
    parser.add_argument("--queue-csv", help="write a CSV triage queue")
    parser.add_argument("--queue-md", help="write a Markdown triage queue")
    args = parser.parse_args()
    outputs = [Path(p).resolve() for p in (args.output, args.queue_csv, args.queue_md) if p]
    if len(set(outputs)) != len(outputs) or any(p in {Path(args.events).resolve(), Path(args.policy).resolve()} for p in outputs):
        print("Configuration error: output paths must be distinct and must not overwrite inputs", file=sys.stderr)
        return 2
    try:
        policy = load_policy(args.policy)
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    try:
        events, counts = load_events(args.events)
    except (OSError, UnicodeError) as exc:
        print(f"Input error: {exc}", file=sys.stderr)
        return 2
    try:
        partial = bool(counts["errors"] or counts["conflicts"])
        status = "partial" if partial else "complete"
        alerts = prepare(detect(events, policy["sign_in"]) + role_alerts(events, policy["role_change"]) + export_alerts(events, policy["export"]))
        result = {"status": status, "input": counts, "input_event_ids": [event["event_id"] for event in events], "alerts": alerts}
        output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            Path(args.output).write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        if args.queue_csv:
            Path(args.queue_csv).write_text(csv_text(alerts, status), encoding="utf-8")
        if args.queue_md:
            Path(args.queue_md).write_text(markdown_text(alerts, status), encoding="utf-8")
        return 2 if partial else 0
    except Exception as exc:
        print(f"Execution/output failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
