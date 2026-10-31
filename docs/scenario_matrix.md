# Scenario matrix

## Authored first fixtures

These expectations were specified before the detector was implemented. The matching unit is a scenario; expected candidates identify the success event and the complete evidence set. Labels are not detector inputs. Date: 2026-01-15, with instants expressed in UTC below.

| ID | Scenario truth (separate labels) | Events | Timeline | Expected rule behavior |
| --- | --- | --- | --- | --- |
| S01 | Simulated malicious sign-in sequence | evt_001–evt_006 | Failures 09:00, 09:02, 09:04, 09:06, 09:10; success 09:15 | One candidate anchored at evt_006, evidence evt_001–evt_006; exact 10-minute/5-minute inclusive boundaries |
| S02 | Benign password retries | evt_007–evt_012 | Failures 10:00–10:04; success 10:04:30 | One candidate anchored at evt_012, evidence evt_007–evt_012; a deliberate security false positive |
| S03 | Benign ordinary retry | evt_013–evt_014 | Failure 11:00; success 11:01 | No candidate |
| S04 | Simulated malicious attempt below threshold | evt_015–evt_019 | Four failures 12:00–12:03; success 12:04 | No candidate; deliberate security false negative at this threshold |

19 unique events, four actors, four successes and fifteen failures. The generator shuffles line order with seed 20261030. `evt_007` represents 10:00 UTC as `03:00:00-07:00` to exercise timezone normalization. Inputs have opaque identifiers; semantic truth appears only in labels.

The Checkpoint 02 detector exactly matched the authored candidates and evidence. Compared with the four separate scenario truth labels, the observed scenario-level security counts are TP=1, FP=1, TN=1, FN=1. These hand-authored cases do not support a real-world performance claim; see PROGRESS.md.

## Coverage roadmap

| Area | Required cases | Checkpoint |
| --- | --- | --- |
| Sign-ins | Four/five/six failures; exactly and just outside 10 and 5 minutes; same timestamp; repeated successes; reset on nonqualifying success | 02 — tested |
| Isolation | Separate actors; multiple IPs; no cross-actor accumulation | 02 — tested |
| Input quality | Identical IDs, equivalent UTC IDs, conflicting IDs, shuffled input, invalid date, missing timezone/field, blank/malformed line, unknown fields, empty file | 02 — tested |
| Roles | Approved actor/target/role/interval, missing/unknown ID, expired/mismatched approval, failed change, unprotected role | 03 — tested |
| Exports | 999/1000/1001 records, 15-minute boundary and just outside, burst, actor/resource isolation, failed/duplicate events | 03 — tested |
| Export approvals | Allowed job, wrong resource, outside interval, aggregate above cap, unrelated activity by the same account | 03 — tested |
| Reproduction | Stable alert/evidence identities, end-to-end expected matches, truthful partial-output counts | 02–03 |
| Analyst records | Suspicious and benign cases tied to actual generated alerts; paper-only phishing walkthrough | 04 — completed and evidence checked |

The S01 and S04 intent labels are authored simulation truth. The log pattern alone cannot establish that intent. Likewise S02's benign label must not be presented as a user confirmation observed in the logs.

## Checkpoint 03 authored additions

The combined dataset adds R01–R06 and E01–E06 to the four sign-in scenarios. R01 is an approved role change, R02 a missing change ID, R03 an unknown ID, R04 an expired known approval, R05 a failed change and R06 a nonprotected role. E01 is an unapproved 1,000-record window at the inclusive boundary; E02 is an approved aggregate of 1,500; E03 exceeds that interval cap by one; E04 is outside the job approval; E05 is a 999-record event; E06 is a benign, unapproved public-resource export that triggers. Scenario intent is authored separately from log inputs.

The observed combined run matched 9 of 9 authored candidate/evidence records with no extras or misses. Scenario counts were TP=6, FP=3, TN=6, FN=1 across 16 authored cases. See [evaluation](../reports/checkpoint03_evaluation.json); these are not field performance estimates.

## Strengthening experiment

The separate development and holdout fixtures each contain 12 authored scenarios. They use different synthetic actor/event identities and include four-, five- and six-failure patterns, benign and malicious behavior, inclusive and just-outside windows, successful protected-role assignments with valid or missing/unknown approval, and approved or threshold export activity. Dataset version 1.0, seeds and SHA-256 hashes are in [fixture manifest](../data/strengthening_fixture_manifest.json); the policy, code and fixture freeze is in [freeze record](../reports/strengthening/freeze.json). Seeds only shuffle event ordering. These sets were authored by the experiment author and are neither independent nor representative.

In development, 1.1 adds the simulated malicious `D01` and benign `D02` alerts. In holdout, 1.1 adds simulated malicious `H01` and `H08`, but also adds benign `H02`. `H05` remains a malicious miss because its success lies outside the delay. The separate labels hold these scenario truths; they do not feed the detector. Exact candidate and evidence conformance and security metrics are in the [summary](../reports/strengthening/summary.json).
