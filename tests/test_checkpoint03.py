import copy
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from secops_lab.core import load_policy
from secops_lab.evaluate import evaluate
from secops_lab.queue import prepare
from secops_lab.rules import export_alerts, role_alerts
from test_checkpoint02 import ingest

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_policy(ROOT / "config/policy.json")


def role(id="r", stamp="13:00:00", actor="actor_admin_01", target="actor_analyst_01", new="data_export_admin", outcome="success", change="CHG-LAB-001"):
    item = {"schema_version": "1.0", "event_id": id, "timestamp": "2026-01-15T" + stamp + "Z", "actor_id": actor, "event_type": "role_change", "source": "identity_audit", "outcome": outcome, "target_user_id": target, "previous_role": "member", "new_role": new}
    if change is not None:
        item["change_id"] = change
    return item


def export(id, stamp, count, actor="actor_x", resource="fitness_session_metadata", outcome="success"):
    return {"schema_version": "1.0", "event_id": id, "timestamp": "2026-01-15T" + stamp + "Z", "actor_id": actor, "event_type": "data_export", "source": "application_audit", "outcome": outcome, "resource": resource, "record_count": count}


def run_role(items):
    return role_alerts(ingest(items)[0], POLICY["role_change"])


def run_export(items):
    return export_alerts(ingest(items)[0], POLICY["export"])


class RoleTests(unittest.TestCase):
    def test_approved_boundaries_and_every_dimension(self):
        for stamp in ("13:00:00", "13:30:00"):
            self.assertEqual(run_role([role(stamp=stamp)]), [])
        for item in (role(stamp="12:59:59"), role(stamp="13:30:01"), role(actor="wrong"), role(target="wrong"), role(new="organization_admin")):
            with self.subTest(item=item):
                alert = run_role([item])[0]
                self.assertIn("Known change ID", alert["reason"])
                self.assertFalse(alert["approval_comparisons"][0]["matches"])
        self.assertIn("No change ID", run_role([role(change=None)])[0]["reason"])
        self.assertIn("unknown", run_role([role(change="unknown")])[0]["reason"])
        self.assertEqual(run_role([role(outcome="failure"), role(id="r2", new="member")]), [])


class ExportTests(unittest.TestCase):
    def test_threshold_isolation_failed_duplicates_and_window(self):
        for amount, hits in ((999, 0), (1000, 1), (1001, 1)):
            self.assertEqual(len(run_export([export("a", "03:00:00", amount)])), hits)
        self.assertEqual(run_export([export("a", "03:00:00", 500), export("b", "03:15:01", 500)]), [])
        alerts = run_export([export("b", "03:15:00", 500), export("a", "03:00:00", 500)])
        self.assertEqual(alerts[0]["evidence_event_ids"], ["a", "b"])
        self.assertEqual(run_export([export("a", "03:00:00", 500), export("b", "03:01:00", 500, actor="other")]), [])
        self.assertEqual(run_export([export("a", "03:00:00", 500), export("b", "03:01:00", 500, resource="public_activity_catalog")]), [])
        self.assertEqual(run_export([export("a", "03:00:00", 500), export("b", "03:01:00", 900, outcome="failure")]), [])
        self.assertEqual(run_export([export("a", "03:00:00", 500), export("a", "03:00:00", 500)]), [])

    def test_cap_interval_and_cumulative_even_outside_window(self):
        approved = [export("a", "02:00:00", 800, actor="actor_job_01"), export("b", "02:15:00", 700, actor="actor_job_01")]
        self.assertEqual(run_export(approved), [])
        over = run_export(approved + [export("c", "02:15:00", 1, actor="actor_job_01")])
        self.assertEqual(over[-1]["anchor_event_id"], "c")
        self.assertEqual(over[-1]["window_totals"]["over_cap"], 1)
        self.assertEqual(over[-1]["event_allocations"][-1]["approval_comparisons"][0]["used_before_event"], 1500)
        # A longer approval outlives the rolling window; earlier usage still consumes its cap.
        policy = copy.deepcopy(POLICY["export"])
        policy["approved_exports"][0]["valid_until"] = "2026-01-15T03:00:00Z"
        events, _ = ingest([export("a", "02:00:00", 1500, actor="actor_job_01"), export("b", "02:16:00", 1, actor="actor_job_01")])
        over = export_alerts(events, policy)
        self.assertEqual(over[0]["window_totals"]["over_cap"], 1)
        self.assertEqual(over[0]["window_totals"]["record_count"], 1)
        self.assertEqual(over[0]["evidence_event_ids"], ["b"])
        wrong_resource = run_export([export("a", "02:01:00", 1000, actor="actor_job_01", resource="public_activity_catalog")])
        self.assertEqual(wrong_resource[0]["window_totals"]["unapproved"], 1000)
        outside = run_export([export("a", "02:15:01", 1000, actor="actor_job_01")])
        self.assertEqual(outside[0]["window_totals"]["unapproved"], 1000)

    def test_same_time_order_and_no_coalescing(self):
        items = [export("b", "03:00:00", 500), export("a", "03:00:00", 500), export("c", "03:00:00", 1)]
        alerts = run_export(items)
        self.assertEqual([a["anchor_event_id"] for a in alerts], ["b", "c"])
        self.assertEqual(alerts[0]["evidence_event_ids"], ["a", "b"])
        self.assertEqual(alerts, run_export(list(reversed(items))))


class PolicyTests(unittest.TestCase):
    def test_invalid_policy_stops_all_detection(self):
        source = json.loads((ROOT / "config/policy.json").read_text())
        variants = []
        for field, value in (("record_threshold", True), ("window_seconds", -1)):
            p = copy.deepcopy(source); p["export"][field] = value; variants.append(p)
        p = copy.deepcopy(source); p["role_change"]["approved_changes"][0]["valid_until"] = "bad"; variants.append(p)
        p = copy.deepcopy(source); p["export"]["approved_exports"].append(dict(p["export"]["approved_exports"][0], approval_id="EXP-2")); variants.append(p)
        p = copy.deepcopy(source); p["export"]["approved_exports"][0]["maximum_total_records"] = True; variants.append(p)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "policy.json"
            for value in variants:
                path.write_text(json.dumps(value))
                result = subprocess.run([sys.executable, "-m", "secops_lab", "data/events/checkpoint03.jsonl", "--policy", str(path)], cwd=ROOT, text=True, capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("Configuration error", result.stderr)


class EvaluationTests(unittest.TestCase):
    def test_complete_run_matches_separate_authored_labels(self):
        result = subprocess.run([sys.executable, "-m", "secops_lab", "data/events/checkpoint03.jsonl"], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        labels = json.loads((ROOT / "data/labels/checkpoint03.json").read_text())
        report = evaluate(data, labels)
        self.assertEqual(report["candidate_conformance"]["expected"], 9)
        self.assertEqual(report["candidate_conformance"]["matched"], 9)
        self.assertEqual(report["candidate_conformance"]["extra"], [])
        self.assertEqual(report["candidate_conformance"]["missing"], [])
        self.assertEqual(report["scenario_security"], {"tp": 6, "fp": 3, "tn": 6, "fn": 1, "precision": 6 / 9, "recall": 6 / 7})
        grouped = [a for a in data["alerts"] if a["actor_id"] == "actor_017"]
        self.assertEqual(len(grouped), 2)
        self.assertEqual(len({a["investigation_id"] for a in grouped}), 1)
        self.assertEqual(result.stdout, subprocess.run([sys.executable, "-m", "secops_lab", "data/events/checkpoint03.jsonl"], cwd=ROOT, text=True, capture_output=True).stdout)

    def test_partial_overlap_extras_and_zero_denominator(self):
        labels = {"scenarios": [{"scenario_id": "s", "security_truth": "benign", "event_ids": ["x"], "expected_candidates": []}]}
        with self.assertRaises(ValueError): evaluate({"status": "partial", "input_event_ids": ["x"], "alerts": []}, labels)
        duplicate = copy.deepcopy(labels); duplicate["scenarios"].append(dict(duplicate["scenarios"][0], scenario_id="other"))
        with self.assertRaises(ValueError): evaluate({"status": "complete", "input_event_ids": ["x"], "alerts": []}, duplicate)
        with self.assertRaises(ValueError): evaluate({"status": "complete", "input_event_ids": ["unrelated"], "alerts": []}, labels)
        report = evaluate({"status": "complete", "input_event_ids": ["x"], "alerts": []}, labels)
        self.assertIsNone(report["scenario_security"]["precision"])
        self.assertIsNone(report["scenario_security"]["recall"])
        alert = {"rule_id": "large_export", "rule_version": "1.0", "anchor_event_id": "unknown", "evidence_event_ids": ["unknown"]}
        self.assertEqual(len(evaluate({"status": "complete", "input_event_ids": ["x"], "alerts": [alert]}, labels)["candidate_conformance"]["extra"]), 1)

    def test_conflict_excludes_all_versions_and_marks_all_outputs_partial(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            csv_path = Path(temp) / "queue.csv"
            records = [export("clash", "03:00:00", 1000), export("clash", "03:00:00", 1100)]
            path.write_text("".join(json.dumps(item) + "\n" for item in records))
            proc = subprocess.run([sys.executable, "-m", "secops_lab", str(path), "--queue-csv", str(csv_path)], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 2)
            output = json.loads(proc.stdout)
            self.assertEqual(output["input"]["conflicts"], [{"event_id": "clash", "lines": [1, 2]}])
            self.assertEqual(output["input"]["valid_unique_events_accepted"], 0)
            self.assertEqual(output["alerts"], [])
            with csv_path.open() as stream:
                row = list(csv.DictReader(stream))[0]
            self.assertEqual(row["run_status"], "partial")
            self.assertEqual(row["alert_id"], "")

    def test_non_utf8_line_is_rejected_without_losing_valid_events(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            path.write_bytes((json.dumps(export("e", "03:00:00", 1000)) + "\n").encode() + b"\xff\n")
            proc = subprocess.run([sys.executable, "-m", "secops_lab", str(path)], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 2)
            data = json.loads(proc.stdout)
            self.assertEqual(data["status"], "partial")
            self.assertEqual(data["input"]["errors"][0]["line"], 2)
            self.assertEqual(len(data["alerts"]), 1)

    def test_partial_queue_explicit_and_priority(self):
        with tempfile.TemporaryDirectory() as temp:
            event_path = Path(temp) / "events.jsonl"
            event_path.write_text(json.dumps(export("e", "03:00:00", 1000)) + "\ninvalid\n")
            csv_path, md_path = Path(temp) / "queue.csv", Path(temp) / "queue.md"
            proc = subprocess.run([sys.executable, "-m", "secops_lab", str(event_path), "--queue-csv", str(csv_path), "--queue-md", str(md_path)], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads(proc.stdout)["status"], "partial")
            with csv_path.open() as stream:
                self.assertEqual(list(csv.DictReader(stream))[0]["run_status"], "partial")
            self.assertIn("**partial**", md_path.read_text())
        alerts = [{"severity": "medium", "timestamp": "2026-01-01T00:00:00Z", "alert_id": "m", "actor_id": "a"}, {"severity": "high", "timestamp": "2026-01-01T00:00:01Z", "alert_id": "h", "actor_id": "a"}]
        self.assertEqual([a["alert_id"] for a in prepare(alerts)], ["h", "m"])


if __name__ == "__main__":
    unittest.main()
