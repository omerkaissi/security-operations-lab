# Investigation 01: sign-in sequence and protected-role assignment

**Case:** `investigation:actor_017` · **Disposition:** open; authorization and compromise unconfirmed · **Work type:** fictional, offline analysis. This is a paper investigation of existing synthetic records, not an incident response performed on a real account.

## Scope and source records

The [Checkpoint 03 alert output](../../reports/checkpoint03_alerts.json) groups `signin_failure_then_success:1.0:evt_006` and `unexpected_protected_role:1.0:role_002` under the same actor. The grouping is an actor-based triage aid. It does not establish that the sign-in caused the later role assignment or that both actions came from the same person or session. Source events are in [checkpoint03.jsonl](../../data/events/checkpoint03.jsonl); relevant operational approval is in [policy.json](../../config/policy.json). All times below are UTC on 2026-01-15.

## Observations

| Time | Event | Observation from the fictional event or alert |
| --- | --- | --- |
| 09:00 | `evt_001` | Failed sign-in for `actor_017`. |
| 09:02 | `evt_002` | Failed sign-in for the same actor. |
| 09:04 | `evt_003` | Failed sign-in for the same actor. |
| 09:06 | `evt_004` | Failed sign-in for the same actor. |
| 09:10 | `evt_005` | Fifth failed sign-in in the alert's failure window. |
| 09:15 | `evt_006` | Successful sign-in; the success is exactly five minutes after the latest failure. |
| 13:01 | `role_002` | Successful role change by `actor_017`, changing `actor_analyst_01` from `member` to `data_export_admin`; the event has no change ID. |

The sign-in records all contain the documentation address `192.0.2.17` and distinct session IDs. The event schema does not establish whether those IDs represent the same underlying device or a continuous session. The alert includes all six sign-in events, with the first and last failures exactly ten minutes apart. The role alert's policy comparison shows that `CHG-LAB-001` has the same target and role and covers 13:01, but names `actor_admin_01`, and `role_002` supplies no change ID. It is therefore not a matching approval under the policy.

## Analyst assessment and unknowns

The two patterns justify a closer look because a successful sign-in followed repeated failures and a protected role was later assigned without a matching approval in the supplied policy. An ordinary retry sequence plus a separately authorized administrative action is also possible. The 3 hours 46 minutes between the successful sign-in and role change, shared actor ID, and missing change ID do not alone prove a common session, unauthorized access, or malicious intent.

The dataset contains no MFA decisions, device posture, user confirmation or session telemetry that would explain the sign-in. The role event lacks IP, session ID and change ID; the supplied policy may not capture every real-world change record. No independent change confirmation or actor intent is available. The fictional context lists `actor_017` as a customer-support human account with expected role `member`, but that inventory alone does not prove the assignment was unauthorized. No actual health records or exported records are present.

## Proposed follow-up and disposition

1. Preserve the cited event and alert records and check their timestamps and source integrity in a real investigation; here the existing files are the only evidence.
2. Seek independent confirmation of the sign-in and verify the actor, target, role and validity period against the authoritative change record through an approved channel. Review MFA, device and session telemetry if available.
3. If independent evidence indicates unauthorized access or an unapproved privileged assignment, escalate and consider proportionate containment under the relevant incident process. Record who authorized any action and reassess access after verification.

These are proposed actions, not steps performed. Keep the case **open / indeterminate** until independent evidence supports a disposition. The separate training labels describe simulated malicious intent; those labels are evaluation truth, not event evidence or an actual user confirmation.

## Synthetic follow-up exercise: simulated escalation

The initial open / indeterminate assessment above remains the historical assessment. Separate [fictional follow-up evidence](../../data/investigations/followup_evidence_v1.json) supplies the following exercise-only records; no real user or change owner was contacted.

| Time (UTC) | Paper evidence | What it supports |
| --- | --- | --- |
| 13:20 | `FU017_USER` | A stipulated verified-channel owner statement denies initiating the successful sign-in `evt_006`. |
| 13:25 | `FU017_CHANGE` | A fictional change owner reports that the specific `role_002` assignment was not authorized. |

**Simulated owner and priority:** `fictional_analyst_01`, high triage priority because the fictional protected assignment affects privileged access. **Assessment:** the two authored records support escalation for suspected unauthorized access and an unapproved role change. They do not show that `evt_006` caused `role_002`, prove who acted, or establish data theft. Alternatives include a mistaken owner statement, incomplete change records or a separately compromised administrative pathway.

**Simulated decision at 13:30 UTC:** escalate the paper case to the fictional incident lead. Proposed containment, subject to approval and impact assessment, is to restrict the affected account's sessions and remove or suspend the unapproved role assignment while preserving evidence. None of those actions was performed. Before a fictional eventual closure, require independent verification of identity and session scope, a documented and approved role/access review, confirmation that any authorized containment and recovery completed, and documented resolution of potential affected activity. Unknowns include the real session behind the role event, full scope and destination of any activity, and the identity or intent of the operator. The case remains escalated / open in the exercise.
