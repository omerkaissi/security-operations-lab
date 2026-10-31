# Claim mapping and provenance

Use this table to keep portfolio or interview statements within the available evidence. This is not an edited resume, a representation of the user's personal contribution, or an authorization to publish. Use first-person wording only for work actually performed and understood. In a guided chat walkthrough the owner edited a scratch policy, ran the detector and 29 tests, and explained the false-positive tradeoff; that conversation is not an independent verification of authorship. Codex prepared the implementation and documents in this workspace; the record does not establish an independent reviewer or model-setting change.

| Evidence-backed project statement | Source or verification | Boundary |
| --- | --- | --- |
| A fictional offline Python lab implements three rule-based detections. | [Rules](detection_catalog.md), [implementation](../secops_lab/rules.py), [sign-in detector](../secops_lab/core.py). | A lab implementation, not a deployed SOC service. |
| The loader reports malformed and conflicting records and normalizes time before analysis. | [Loader](../secops_lab/core.py), [tests](../tests/test_checkpoint02.py). | Test coverage is finite; partial output is not a clean run. |
| The recorded synthetic run produced nine exact candidate/evidence matches from 33 events. | [Alert report](../reports/checkpoint03_alerts.json), [evaluation](../reports/checkpoint03_evaluation.json). | Agreement with authored expectations is not real-world detection accuracy. |
| The 16 authored scenarios yielded TP=6, FP=3, TN=6, FN=1. | [Evaluation](../reports/checkpoint03_evaluation.json), [scenario matrix](scenario_matrix.md). | Scenario-level, hand-authored labels; not an independent sample or an alert-level confusion matrix. |
| Two paper investigations connect three alerts to 13 event IDs. | [Cases](investigations/actor_017.md), [second case](investigations/actor_029.md), [evidence check](../reports/checkpoint04_evidence_check.json). | The evidence check is self-review; actor grouping does not prove causation or intent. |
| A phishing response walkthrough was written using a fictional paper message. | [Playbook](phishing_response_playbook.md). | No real message was handled, user contacted or system changed. |
| The unit suite checks the documented rules and evaluation behavior. | [Detection tests](../tests/test_checkpoint03.py), [strict-check tests](../tests/test_strict_evaluation.py). | A passing finite suite does not establish security, operational performance or independent review. |

Avoid claims such as “handled an incident,” “protected customer health data,” “reduced SOC response time,” “deployed a SIEM,” “achieved production precision,” or “conducted an independent review.” None is supported by this lab. Resume edits, job applications and outreach require explicit user instruction.

## Strengthening pass claims

| Evidence-backed statement | Evidence | Boundary |
| --- | --- | --- |
| Compared five- and four-failure policies on frozen, separately authored development and holdout fixtures. | [Plan](strengthening_experiment.md), [freeze](../reports/strengthening/freeze.json), [summary](../reports/strengthening/summary.json). | Same author designed experiment and scenarios; no independent sample or real-world accuracy claim. |
| Holdout recall rose from 2/5 to 4/5 while false positives rose from two to three; total alerts rose from four to seven. | [Summary](../reports/strengthening/summary.json). | 12 authored scenarios only; revised priority counts do not erase false positives. |
| Strict evaluation exits nonzero on candidate/evidence mismatch. | [Evaluator](../secops_lab/evaluate.py), [tests](../tests/test_strict_evaluation.py). | Conformance is not security usefulness; output failure also exits nonzero. |
| Two fictional case follow-ups support a simulated benign closure and a simulated escalation. | [Follow-up evidence](../data/investigations/followup_evidence_v1.json), [case 1](investigations/actor_017.md), [case 2](investigations/actor_029.md). | No contact, containment or actual response occurred; authored exercise records, not labels, support the decisions. |
