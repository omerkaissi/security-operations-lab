# Investigation 02: repeated sign-in failures and success

**Case:** `investigation:actor_029` · **Analyst disposition:** open / indeterminate from available logs · **Work type:** fictional, offline analysis.

## Scope and observations

The [Checkpoint 03 alert output](../../reports/checkpoint03_alerts.json) contains `signin_failure_then_success:1.0:evt_012` with evidence in [checkpoint03.jsonl](../../data/events/checkpoint03.jsonl). All normalized times are UTC on 2026-01-15.

| Normalized time | Event | Observed outcome |
| --- | --- | --- |
| 10:00 | `evt_007` | Failure; recorded as 03:00 with a −07:00 offset. |
| 10:01 | `evt_008` | Failure. |
| 10:02 | `evt_009` | Failure. |
| 10:03 | `evt_010` | Failure. |
| 10:04 | `evt_011` | Failure. |
| 10:04:30 | `evt_012` | Success, 30 seconds after the latest failure. |

The six events use `actor_029`, documentation IP `198.51.100.29` and distinct session IDs. The five failures satisfy the configured threshold within the latest-failure-anchored window, and the success is within the inclusive delay. The alert is therefore consistent with the specified rule. The available events do not identify the human using the account or show why the attempts failed.

## Assessment and limitations

Legitimate forgotten-password retries and unauthorized attempts are both compatible with this pattern. The log does not include an MFA decision, device posture, user confirmation or enough session telemetry to distinguish those explanations. Distinct session IDs and a shared IP do not independently establish a single continuous session or the actor's intent.

The separately authored [training labels](../../data/labels/checkpoint03.json) describe this sequence as benign forgotten-password retries. That is an artificial exercise answer, not confirmation observed in the event data. **For the authored evaluation**, the candidate is a security false positive; **for an analyst using only these records**, the case remains indeterminate. Do not rewrite the label or claim a real user confirmed it.

## Proposed follow-up and disposition

Preserve the event sequence and ask for independent user confirmation through an approved channel; compare available MFA, device and session records if they exist. If those sources support ordinary retries, document the evidence and resolve the alert as benign; if they instead support unauthorized access, escalate and consider containment under the applicable process. Those are conditional, proposed steps. None were performed and no actual user was contacted. The paper case remains open pending independent evidence.

## Synthetic follow-up exercise: simulated benign closure

The original assessment above remains the historical initial assessment. The following records were authored later as separate [fictional follow-up evidence](../../data/investigations/followup_evidence_v1.json), not taken from scenario labels. No real person was contacted.

| Time (UTC) | Paper evidence | What it supports |
| --- | --- | --- |
| 10:15 | `FU029_USER` | A stipulated verified-channel account-owner statement attributes the retries and successful sign-in to the fictional owner. |
| 10:18 | `FU029_MFA` | A fictional authentication-context record associates `evt_012` and `session_012` with successful MFA on a known device. |

**Simulated owner and priority:** `fictional_analyst_02`, medium triage priority from the original alert. **Assessment:** together the fictional confirmation and authentication context support benign forgotten-password retries; a stolen account or inaccurate confirmation remains an alternative in principle, but no such additional evidence is stipulated. **Simulated decision at 10:20 UTC:** close this paper alert as benign with `FU029_USER` and `FU029_MFA` cited; this is an exercise disposition, not an action performed in an operational system. The initial log-only case was indeterminate, while these newly authored records supply the closure basis. Remaining unknowns include complete device and session history. Reopen the paper case if credible contradictory session or identity evidence is introduced. No account, case system or user was contacted or changed.
