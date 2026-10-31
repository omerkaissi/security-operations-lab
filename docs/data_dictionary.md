# Event data dictionary — schema 1.0

One JSON object per nonblank JSONL line. Every record is fictional. The common `schema_version` is the string `1.0`. The formal artifact is `schema/event.schema.json`; the Checkpoint 02 runtime loader validates these documented event shapes. JSON Schema's `format` annotation alone is not a complete timestamp validator.

| Field | Type | Requirement and meaning |
| --- | --- | --- |
| schema_version | string | Required; exactly `1.0` |
| event_id | string | Required, 1–96 ASCII letters/digits/underscore/hyphen; unique semantic event identity |
| timestamp | string | Required ISO 8601 date/time with seconds, optional 1–6 fractional digits, and `Z` or explicit `±HH:MM` offset; valid calendar date required |
| actor_id | string | Required identifier of account performing the operation |
| event_type | enum | Required: `sign_in`, `role_change`, `data_export` |
| outcome | enum | Required: `success` or `failure` |
| source | enum | `identity_audit` for sign-ins/role changes; `application_audit` for exports |
| session_id | string | Optional correlation identifier; missing is an investigative limitation |
| source_ip | string | Optional valid IPv4/IPv6 address; fixtures use documentation addresses |
| target_user_id | string | Required only for role changes; account whose role is assigned |
| previous_role | enum | Required only for role changes; prior observed role |
| new_role | enum | Required only for role changes; requested/assigned role according to outcome |
| change_id | string | Optional only for role changes; purported approval reference, never proof by itself |
| resource | enum | Required only for exports; `fitness_session_metadata` or `public_activity_catalog` |
| record_count | integer | Required only for exports, ≥0; reject booleans, strings, fractions and negative numbers |

Role values: `none`, `member`, `support`, `data_export_admin`, `organization_admin`. IDs use the same syntax as event_id. Explicit nulls, unknown keys and fields attached to the wrong event type are invalid. Failure events represent attempts; `record_count` on a failed export is the requested amount and contributes zero to aggregation.

Runtime numeric validation is deliberately stricter than JSON Schema's mathematical `integer` type: a JSON literal such as `1.0` parses as a Python float and must be rejected by the loader even though some schema validators accept it as an integer value. A `true` literal must also be rejected.

`synthetic` appears in policy/labels/context and the enclosing documentation rather than as a signal on each event. Event records contain no scenario ID, maliciousness, expected alert, priority answer or disposition. Operational context likewise carries no scenario truth. Optional missing IP/session/change approval evidence must be surfaced to an analyst; missing mandatory fields are validation errors.

Normalize instants to UTC before ordering, comparing IDs or evaluating windows. Do not assume a local timezone. Preserve adequate line/event context in validation errors. Equivalent offset representations normalize to the same instant. See PROJECT_SPEC.md for duplicate/conflict handling and deterministic tie order.

The original fixtures contain sign-ins only. The separate Checkpoint 03 fixtures exercise all three implemented rules; see the detection catalog and recorded results.
