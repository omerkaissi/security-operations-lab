# Security Operations Lab

An offline security-operations lab for a fictional application. Identities, events, approvals, follow-up records and labels are synthetic; the lab does not access health data, real accounts or networks. It is a portfolio exercise, not production SOC experience.

The standard-library Python CLI validates JSONL, normalizes UTC, reports duplicates/conflicts, and applies three rules: repeated sign-in failures then success, protected-role assignment, and large or over-cap export. JSON alerts and CSV/Markdown queues retain evidence, priority rationale, confidence and unknowns. Actor groups are triage aids, not proof of causation. See the [detection catalog](docs/detection_catalog.md).

## Run the baseline and strict checks

Python 3.12+ is required; the recorded lab runs used Python 3.13.18. From the project root, if `.venv` is absent, check `python3 --version`, then create a local environment with `python3 -m venv --without-pip .venv`. No packages or network are required. Run:

```sh
mkdir -p reports/runs
.venv/bin/python scripts/verify_setup.py
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m secops_lab data/events/checkpoint03.jsonl --output reports/runs/baseline_alerts.json --queue-csv reports/runs/baseline_queue.csv --queue-md reports/runs/baseline_queue.md
.venv/bin/python -m secops_lab.evaluate reports/runs/baseline_alerts.json data/labels/checkpoint03.json --check --output reports/runs/baseline_evaluation.json
.venv/bin/python scripts/verify_checkpoint04.py --output reports/runs/investigation_check.json
```

`reports/runs/` is ignored and keeps the recorded baseline fixtures and reports intact. The detector reads only events and operational policy. The separate evaluator reads labels after detection. Strict evaluation exits 0 for an exact match, 1 for missing/extra candidates or output failure, and 2 for invalid/incompatible input, including partial output. Without `--check`, a report may complete with mismatches and exit 0: inspect `candidate_conformance`.

The detector returns 0 for complete input, 2 for invalid configuration/input or explicitly marked partial output, and 1 for execution/output failure. Invalid lines and conflicting IDs are visible; all versions of a conflicting ID are excluded. Multiple output files are not written transactionally, so an earlier file can remain after a later failure: check the command's exit status and regenerate all outputs after an error.

## Frozen detection experiment

The original five-failure sign-in profile remains the default, version 1.0. The opt-in version 1.1 profile lowers the threshold to four and leaves the time and reset rules intact. Its [plan](docs/strengthening_experiment.md) and [freeze](reports/strengthening/freeze.json) record the original experiment and a later resource-name migration. The migrated data was rerun for consistency, not as a new blind holdout. Fixture versions, seeds and current hashes are in the [manifest](data/strengthening_fixture_manifest.json).

On 12 self-authored holdout scenarios, baseline produced four alerts (two high, two medium), TP/FP/TN/FN **2/2/5/3**, precision **2/4** and recall **2/5**. The revised profile produced seven alerts (two high, five medium), **4/3/4/1**, precision **4/7** and recall **4/5**. Exact candidate/evidence matches were **4/4** and **7/7**, respectively. The revised rule caught two additional simulated malicious scenarios but also added one benign alert. See the [full summary](reports/strengthening/summary.json). These scenarios were authored by the experiment author and are neither independently collected nor representative of real traffic.

To reproduce the development comparison without changing recorded results:

```sh
.venv/bin/python -m secops_lab data/events/strengthening_development_v1.jsonl --output reports/runs/dev_baseline.json
.venv/bin/python -m secops_lab.evaluate reports/runs/dev_baseline.json data/labels/strengthening_development_baseline_v1.json --check
.venv/bin/python -m secops_lab data/events/strengthening_development_v1.jsonl --policy config/policy_signin_v11.json --output reports/runs/dev_revised.json
.venv/bin/python -m secops_lab.evaluate reports/runs/dev_revised.json data/labels/strengthening_development_revised_v1.json --check
```

To rerun the holdout, substitute `holdout` for `development` in the input and label paths and use new output filenames. The holdout has already been reused to verify the resource-name migration; further tuning against it cannot be treated as a blind evaluation. `scripts/summarize_strengthening.py` checks the current migration hashes and summarizes the recorded runs without rerunning the detector.

## Investigations and learning

- [Sign-in and role investigation](docs/investigations/actor_017.md): the original assessment remains open; later fictional records support a **simulated escalation** and proposed, unperformed containment.
- [Retry investigation](docs/investigations/actor_029.md): later fictional confirmation and MFA/device evidence support a **simulated benign closure**. Scenario truth is not investigation evidence.
- [Paper-only phishing walkthrough](docs/phishing_response_playbook.md), [hands-on exercise](docs/hands_on_exercise.md) and [separate suggested answers](docs/hands_on_answers.md).
- [Case study](docs/case_study.md) and [two-page PDF](output/pdf/security_operations_case_study.pdf), [demo](docs/demo_script.md), [interview notes](docs/interview_notes.md) and [claim mapping](docs/claim_mapping.md).

The original 33-event, 16-scenario baseline produced nine exact authored matches and TP/FP/TN/FN 6/3/6/1; those are not field accuracy. No real incident, outreach, containment or operational impact is claimed. The experiment and reviews are self-authored, not independent. A clean worktree of the local commit passed the setup check, 29 tests, baseline evaluation and investigation-evidence check.
