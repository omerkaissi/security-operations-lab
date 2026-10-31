from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from secops_lab.core import detect, load_events, load_policy, validate_event

ROOT = Path(__file__).resolve().parents[1]
POLICY = load_policy(ROOT / "config/policy.json")["sign_in"]
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def event(event_id, seconds=0, outcome="failure", actor="actor_a", **changes):
    item = {"schema_version": "1.0", "event_id": event_id, "timestamp": (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z"),
            "actor_id": actor, "event_type": "sign_in", "outcome": outcome, "source": "identity_audit"}
    item.update(changes)
    return item


def ingest(lines):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "input.jsonl"
        path.write_text("\n".join(line if isinstance(line, str) else json.dumps(line) for line in lines) + ("\n" if lines else ""), encoding="utf-8")
        return load_events(path)


def run_rule(items):
    events, counts = ingest(items)
    assert not counts["errors"] and not counts["conflicts"]
    return detect(events, POLICY)


class ValidationTests(unittest.TestCase):
    def test_invalid_fields_timestamps_and_null(self):
        mutations = [
            {"timestamp": "2026-01-01T00:00:00"}, {"timestamp": "2026-02-30T00:00:00Z"},
            {"timestamp": "2026-01-01T00:00:00+01:60"}, {"timestamp": None},
            {"event_id": "bad space"}, {"source_ip": "not an ip"}, {"unknown": "x"},
            {"source": "application_audit"}, {"session_id": None}, {"outcome": []},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_event(dict(event("a"), **mutation))
        missing = event("a")
        del missing["actor_id"]
        with self.assertRaises(ValueError):
            validate_event(missing)

    def test_other_event_shapes_and_integer_types(self):
        export = event("x", event_type="data_export", source="application_audit", resource="fitness_session_metadata", record_count=1)
        self.assertEqual(validate_event(export)["record_count"], 1)
        for count in (True, 1.0, -1, "1"):
            with self.subTest(count=count), self.assertRaises(ValueError):
                validate_event(dict(export, record_count=count))
        role = event("r", event_type="role_change", target_user_id="target", previous_role="member", new_role="support")
        self.assertEqual(validate_event(role)["new_role"], "support")
        with self.assertRaises(ValueError):
            validate_event(dict(role, resource="fitness_session_metadata"))

    def test_invalid_lines_visible_empty_and_duplicate_keys(self):
        events, counts = ingest([event("ok"), "", "{broken", '{"event_id":"one","event_id":"two"}'])
        self.assertEqual(len(events), 1)
        self.assertEqual(counts["input_lines"], 4)
        self.assertEqual(counts["rejected_lines"], 3)
        self.assertEqual([e["line"] for e in counts["errors"]], [2, 3, 4])
        _, empty = ingest([])
        self.assertEqual(empty["errors"][0]["error"], "input file is empty")

    def test_normalized_duplicates_and_conflicts(self):
        first = event("same", source_ip="2001:0db8::1")
        equivalent = dict(first, timestamp="2025-12-31T19:00:00-05:00", source_ip="2001:db8::1")
        conflict = dict(first, outcome="success")
        events, counts = ingest([first, equivalent, conflict, event("other")])
        self.assertEqual([e["event_id"] for e in events], ["other"])
        self.assertEqual(counts["duplicate_lines"], 1)
        self.assertEqual(counts["conflicts"], [{"event_id": "same", "lines": [1, 2, 3]}])
        _, counts = ingest([event("same"), event("same", session_id="s")])
        self.assertEqual(counts["conflicted_ids"], 1)


class RuleTests(unittest.TestCase):
    def test_threshold_and_inclusive_windows(self):
        for n, expected in ((4, 0), (5, 1), (6, 1)):
            with self.subTest(n=n):
                self.assertEqual(len(run_rule([event(f"f{i}", i) for i in range(n)] + [event("s", n, "success")])), expected)
        failures = [event("f0", 0)] + [event(f"f{i}", 600) for i in range(1, 5)]
        self.assertEqual(len(run_rule(failures + [event("s", 900, "success")])), 1)
        self.assertEqual(len(run_rule(failures + [event("s", 901, "success")])), 0)
        failures[0] = event("f0", -1)
        self.assertEqual(len(run_rule(failures + [event("s", 900, "success")])), 0)

    def test_latest_failure_anchors_window(self):
        failures = [event(f"f{i}", i) for i in range(5)] + [event("latest", 605)]
        self.assertEqual(run_rule(failures + [event("s", 606, "success")]), [])

    def test_reset_ties_actors_and_distinct_sequences(self):
        items = [event(f"f{i}") for i in range(5)] + [event("s1", outcome="success"), event("s2", outcome="success")]
        self.assertEqual([a["success_event_id"] for a in run_rule(list(reversed(items)))], ["s1"])
        items = [event(f"a{i}", i) for i in range(4)] + [event("reset", 5, "success")] + [event("a4", 6), event("s", 7, "success")]
        self.assertEqual(run_rule(items), [])
        items = [event(f"a{i}", i, actor="a" if i < 3 else "b") for i in range(5)] + [event("s", 6, "success", actor="a")]
        self.assertEqual(run_rule(items), [])
        items = [event(f"a{i}", i) for i in range(5)] + [event("s1", 5, "success")] + [event(f"b{i}", 6+i) for i in range(5)] + [event("s2", 11, "success")]
        self.assertEqual([a["success_event_id"] for a in run_rule(items)], ["s1", "s2"])

    def test_multiple_ips_do_not_split_and_evidence_order(self):
        items = [event(f"f{i}", i, source_ip=f"192.0.2.{i+1}") for i in range(5)] + [event("s", 4, "success")]
        alert = run_rule(items)[0]
        self.assertEqual(alert["evidence_event_ids"], ["f0", "f1", "f2", "f3", "f4", "s"])
        self.assertEqual(run_rule(items), run_rule(list(reversed(items))))
        self.assertIn("session ID missing from one or more evidence events", alert["missing_context"])
        self.assertIn("source IP missing from one or more evidence events", alert["missing_context"])


class CliTests(unittest.TestCase):
    def cli(self, *args):
        return subprocess.run([sys.executable, "-m", "secops_lab", *map(str, args)], cwd=ROOT, text=True, capture_output=True)

    def test_authored_fixture_exact_candidates(self):
        result = self.cli("data/events/signins.jsonl")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        labels = json.loads((ROOT / "data/labels/signins.json").read_text())
        expected = [c for scenario in labels["scenarios"] for c in scenario["expected_candidates"]]
        actual = [{k: a[k] for k in ("rule_id", "rule_version", "success_event_id", "evidence_event_ids")} for a in output["alerts"]]
        self.assertEqual(actual, expected)
        self.assertEqual(output["input"]["valid_unique_events_accepted"], 19)
        self.assertEqual(result.stdout, self.cli("data/events/signins.jsonl").stdout)

    def test_partial_and_invalid_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events"
            path.write_text("\n".join(json.dumps(e) for e in [event(f"f{i}", i) for i in range(5)] + [event("s", 6, "success")]) + "\nnot-json\n")
            result = self.cli(path)
            self.assertEqual(result.returncode, 2)
            output = json.loads(result.stdout)
            self.assertEqual(output["status"], "partial")
            self.assertEqual(len(output["alerts"]), 1)
            self.assertEqual(output["input"]["errors"][0]["line"], 7)
            bad_policy = Path(directory) / "policy.json"
            invalid = json.loads((ROOT / "config/policy.json").read_text())
            invalid["sign_in"]["minimum_failures"] = True
            bad_policy.write_text(json.dumps(invalid))
            result = self.cli(path, "--policy", bad_policy)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("Configuration error", result.stderr)

    def test_unreadable_input_and_output_failure(self):
        result = self.cli("no-such-events.jsonl")
        self.assertEqual(result.returncode, 2)
        self.assertIn("Input error", result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            result = self.cli("data/events/signins.jsonl", "--output", directory)
            self.assertEqual(result.returncode, 1)
            self.assertIn("Execution/output failure", result.stderr)


if __name__ == "__main__":
    unittest.main()
