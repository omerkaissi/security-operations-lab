# Three-minute demo script

A planned script, not a recording or a claim that anyone presented it. Practice with a timer; durations are cues. State only the parts you personally reviewed, ran or changed. The owner completed the guided hands-on walkthrough; no video or presentation has been recorded.

## 0:00-0:25 - Problem and scope

“This offline fictional fitness-app lab turns sign-ins, role changes and export counts into evidence-linked triage alerts. It uses synthetic data, not real health records. A rule match is a hypothesis, not proof of compromise.”

## 0:25-1:15 - Measured comparison

Open `docs/strengthening_experiment.md` and `reports/strengthening/summary.json`. “The baseline needs five sign-in failures. An experimental four-failure profile was frozen after development and evaluated on a separate authored holdout. Baseline had four alerts and scenario counts TP 2, FP 2, TN 5, FN 3. Revised had seven alerts and TP 4, FP 3, TN 4, FN 1. Each profile's candidate and evidence expectations matched exactly. The revised profile recovers H01 and H08 but adds benign H02. These are self-authored scenarios, not real-world accuracy.”

## 1:15-2:00 - Show strict verification

```sh
mkdir -p reports/runs
.venv/bin/python -m secops_lab data/events/strengthening_development_v1.jsonl --policy config/policy_signin_v11.json --output reports/runs/demo_alerts.json
.venv/bin/python -m secops_lab.evaluate reports/runs/demo_alerts.json data/labels/strengthening_development_revised_v1.json --check
```

“The separate evaluator's `--check` returns nonzero for missing or extra candidate/evidence records. It does not prove a scenario's intent. The detector never reads the labels.”

## 2:00-2:40 - Show a completed paper decision

Open `docs/investigations/actor_029.md` and `data/investigations/followup_evidence_v1.json`. “Initially the logs could not establish why the sign-in occurred. Later fictional confirmation and MFA/device records support a simulated benign closure. The records are invented for the exercise; no user was contacted. A separate case escalates based on its own fictional follow-up, with containment proposed but not performed.”

## 2:40-3:00 - Contribution and limitations

“Codex prepared the implementation and documents. I worked through the rule with guidance, edited a scratch policy, ran the detector and tests, and explained the false-positive tradeoff. The data and labels are hand-authored, and review is not independent.”
