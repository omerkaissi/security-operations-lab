import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StrictEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.result = json.loads((ROOT / 'reports/checkpoint03_alerts.json').read_text())
        self.labels = json.loads((ROOT / 'data/labels/checkpoint03.json').read_text())

    def run_evaluation(self, result=None, labels=None, check=True, output=None):
        with tempfile.TemporaryDirectory() as directory:
            result_path = Path(directory) / 'result.json'
            label_path = Path(directory) / 'labels.json'
            result_path.write_text(json.dumps(self.result if result is None else result))
            label_path.write_text(json.dumps(self.labels if labels is None else labels))
            command = [sys.executable, '-m', 'secops_lab.evaluate', str(result_path), str(label_path)]
            if check: command.append('--check')
            if output: command.extend(['--output', output])
            return subprocess.run(command, cwd=ROOT, text=True, capture_output=True)

    def test_match_removed_extra_and_default_reporting(self):
        self.assertEqual(self.run_evaluation().returncode, 0)
        missing = copy.deepcopy(self.result)
        missing['alerts'].pop()
        result = self.run_evaluation(missing)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(json.loads(result.stdout)['candidate_conformance']['missing']), 1)
        self.assertEqual(self.run_evaluation(missing, check=False).returncode, 0)
        extra = copy.deepcopy(self.result)
        extra['alerts'].append(copy.deepcopy(extra['alerts'][0]))
        result = self.run_evaluation(extra)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(len(json.loads(result.stdout)['candidate_conformance']['extra']), 1)

    def test_wrong_evidence_counts_as_missing_and_extra(self):
        result = copy.deepcopy(self.result)
        sign = next(a for a in result['alerts'] if a['rule_id'] == 'signin_failure_then_success')
        sign['evidence_event_ids'].pop(0)
        proc = self.run_evaluation(result)
        self.assertEqual(proc.returncode, 1)
        report = json.loads(proc.stdout)['candidate_conformance']
        self.assertEqual((len(report['missing']), len(report['extra'])), (1, 1))

    def test_partial_and_incompatible_are_errors(self):
        partial = copy.deepcopy(self.result); partial['status'] = 'partial'
        self.assertEqual(self.run_evaluation(partial).returncode, 2)
        incompatible = copy.deepcopy(self.labels); incompatible['scenarios'][0]['event_ids'].pop()
        self.assertEqual(self.run_evaluation(labels=incompatible).returncode, 2)
        malformed = copy.deepcopy(self.result); malformed['alerts'] = 'not a list'
        self.assertEqual(self.run_evaluation(malformed).returncode, 2)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.json'; path.write_text('{')
            result = subprocess.run([sys.executable, '-m', 'secops_lab.evaluate', str(path), str(ROOT / 'data/labels/checkpoint03.json'), '--check'], cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)

    def test_output_failure_is_execution_error(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.run_evaluation(output=directory).returncode, 1)


if __name__ == '__main__':
    unittest.main()
