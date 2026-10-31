# Security Operations Lab — specification v1

## Outcome and scope

Build a small, offline security operations case study for a portfolio: three Python detections, a prioritized alert queue, meaningful tests, honest synthetic evaluation, two investigations and a phishing-response playbook. The setting is a fictional fitness application.

The selected Security Operations Lab directory is the authoritative source. The originally proposed `~/Projects/fitness-security-operations-lab` directory was absent during setup; no second working copy was created. Commands and program outputs use relative paths so the project can later move without code changes.

Use Python 3.12+, the standard library, unittest, JSON Lines events, JSON policy/results and CSV/Markdown analyst output. No cloud services, containers, dashboards, LLM APIs, credentials, real health records or extra detections in version one. The project virtual environment provides Python 3.13.18, meeting the target; Python 3.9.6 was a temporary setup-only fallback.

## Authoritative data contracts

- Schema: `schema/event.schema.json`, version `1.0`.
- Field meanings: `docs/data_dictionary.md`.
- Operational thresholds/approvals: `config/policy.json`.
- Optional investigation context: `config/context.json`.
- Detector input: `data/events/*.jsonl`; scenario labels and expected results belong only in `data/labels/`.
- Every fixture and policy identity is invented. IPs use documentation ranges; domains use `.example`; resource names refer to imaginary metadata, not actual health records.

The loader must enforce types and allowed fields, reject timestamps without timezones and impossible dates, normalize to UTC, reject booleans as record counts, and reject malformed/blank JSONL lines visibly. A nonempty file is required. Missing optional investigative context does not invalidate an otherwise valid event.

Validate before deduplication. Compare normalized semantic content, including all accepted fields, for repeated event IDs. Equal content is a duplicate and counts once; an explicit null is invalid, not equivalent to omission. Conflicting content for one ID is a visible error; exclude all versions of the conflicting ID from analysis. Report input lines, valid unique events accepted, rejected lines, duplicate lines and conflicted IDs. Preserve line references for errors. Deterministically sort normalized events by `(timestamp, sign_in_outcome_rank, event_id)`, with sign-in failures ranked 0 and all other events ranked 1. This gives a defined zero-delay sign-in ordering.

Exit contract: 0 for a complete run, 2 for CLI/configuration/input errors, 1 for unexpected execution/output failure. Input errors produce explicitly marked partial output from any remaining valid events, with nonzero exit status. Invalid configuration stops detection entirely. Do not report malformed input as a clean run.

## Rule 1 — repeated failures followed by success

Rule ID `signin_failure_then_success`, version `1.0`. For a given actor, process valid deduplicated sign-ins in the deterministic ordering above. On a success S:

1. Consider only failures since that actor's preceding success (or start of data).
2. Let F be the most recent such failure. Include every failure in `[F − 10 minutes, F]`.
3. Fire once for S if there are at least five included failures and `0 ≤ S − F ≤ 5 minutes`.
4. Link every included failure ID and S's ID. Evidence order is normalized chronological order, then event ID. The success ID uniquely identifies the candidate for this rule version.
5. Clear that actor's accumulated failure sequence on **every** success, whether it fired or not. Repeated successes cannot reuse a consumed failure sequence; a new sequence can alert again.

All time/count endpoints are inclusive. Same-time failures precede successes; multiple same-time successes are ordered by event ID and only the first can use the preceding failures. Source IP and session are context, not grouping keys. Separate actors never combine. Use the latest-failure-anchored window, not an arbitrary earlier window.

Suggested initial severity: medium, confidence: pattern observed; compromise unconfirmed. A legitimate user retrying a password may correctly trigger the rule and still be a security false positive. This is a hypothesis for investigation, not proof of credential theft. Missing MFA, device posture, user confirmation and session telemetry limit the conclusion. Optional contextual ATT&CK mapping must describe what the behavior supports; it is not proof of T1110.

## Rule 2 — unexpected protected-role assignment

Consider only successful `role_change` events assigning a protected role. A supplied change ID must match a separate policy approval on **actor, target, new role and inclusive UTC validity interval**. Every dimension must match. Never trust the ID alone or evaluation labels.

No matching approval: investigation candidate, high potential impact. Distinguish missing evidence/unknown ID from a known expired or mismatched approval. Neither establishes malicious intent. Failed changes and nonprotected role assignments do not fire. Approved administrative assignments do not fire. Include all approval comparisons in evidence. Consider T1098 only with a clear explanation of the simulated account-change behavior.

## Rule 3 — large export

Aggregate successful exports by actor **and resource** over an inclusive 15-minute rolling window; the initial lab threshold is at least 1,000 records. Failed exports and duplicate events contribute nothing.

A narrowly scoped export approval must match actor, resource and inclusive interval and enforce the approval's aggregate maximum volume. A scheduled account is not globally exempt. Counts outside the interval, another resource or excess approved volume remain investigable. The implemented window, alert coalescing and over-cap handling are specified in docs/detection_catalog.md.

Volume alone is not evidence of data theft or a specific exfiltration technique. Include the counted events, actual volume, window and approval comparisons.

## Alerts, queue and evaluation

Alerts need stable IDs, rule/version, actor/resource, UTC times, severity, separate confidence, priority rationale, evidence IDs, reason, missing context, proposed next action and status. Produce JSON plus a transparent CSV/Markdown queue. Correlate related alerts into investigations without losing individual rule evidence. Keep automated observations separate from analyst judgments.

Evaluate two distinct questions: specification conformance and security usefulness. For the initial sign-in fixtures, the unit is one scenario and the exact match is `(rule_id, success_event_id, evidence_event_ids)`. Expected candidates are manually specified separately from events. Before metrics for the full lab, define cross-rule matching and scenario/alert counts. Report false positives and false negatives on these authored scenarios only; handle zero denominators explicitly. Preserve the benign password-retry alert instead of changing its label to improve metrics.

Required tests later: below/at/above thresholds; exact/just-outside windows; separate actors/resources; duplicate and shuffled records; conflicts; missing fields; malformed/timezone-free timestamps; failed operations; policy approvals; repeatability; a manually labeled end-to-end run.

## Checkpoints and acceptance

| Checkpoint | Deliverables | Completion evidence |
| --- | --- | --- |
| 01 | Environment, scope, working rules, schema, policy, scenario matrix, first fixtures | Actual environment, parse/integrity and reproducibility checks; Git/Python limitations explicit |
| 02 | Validation, normalization, sign-in rule, alert output, tests | Successful CLI example and unittest results; true candidate and benign explanation |
| 03 | Role/export rules, queue, errors and evaluation | Full meaningful tests and actual matching/count reports |
| 04 | Two investigations, phishing playbook with invented paper walkthrough | Every cited alert/event exists; evidence distinguished from inference |
| 05 | README, two-page case study, three-minute demo, interview notes, GitHub handoff and claim mapping | Clean reproduction, self-review and honest final limitations |

Current authorization: **Checkpoint 05 strengthening pass**: the user authorized the bounded experiment, completed fictional investigation exercises, strict evaluator, hands-on walkthrough, and release preparation. The experiment plan and versioned profile are in docs/strengthening_experiment.md. Publication, pushing, licensing, outreach and resume edits still require explicit instruction. A checkpoint boundary is for explanation, not repetitive edit approval. Do not imply that review is independent or invent user participation.

Complete v1 only after all three rules, tests, honest evaluation, traceable queue, investigations, playbook and reproducible portfolio evidence exist. Do not claim production SOC work, incidents, operational impact or real-world detection accuracy. Prepare accurate resume suggestions only from completed evidence; preserve existing employers and format.

## Git and publication

Use one normal Git repository and small verified local commits when workspace permissions allow. Inspect existing state and staged changes; do not change global Git identity or force-push. No remote creation, publication, license choice or outreach is authorized. Publication will require explicit user instruction and a visibility choice.

Before publication, inspect intended tracked files and history for secrets/private notes, reproduce the README from a fresh checkout and write `docs/github_handoff.md` with real branch/remote/revision values. Do not claim a Git checkpoint exists while metadata writes are blocked. The private source starter is a planning reference, not a publication artifact.
