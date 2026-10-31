# Fictional phishing response: playbook and paper walkthrough

This is an offline exercise for the fictional application. It describes decisions an analyst could make; no message was received, no link was visited, no mailbox was searched, no user was contacted, and no account or system was changed. The illustrative message below is a paper artifact, not an event or alert in the lab dataset. It has no asserted connection to either investigation.

## Response playbook

1. **Receive and preserve.** Record the report source and time, recipient, original message and headers if available, and a case identifier. Preserve a copy and chain of custody appropriate to the environment; avoid opening attachments or visiting the link. Treat displayed sender names as claims. Access may require an authorized secure workflow.
2. **Triage.** Compare the sender, reply-to, destination domain, message wording and request against trusted internal information. Consider whether the message requests credentials, a payment or an unexpected action. An urgency cue or a suspicious-looking domain is a reason to investigate, not alone proof of compromise. Record what is known and what is missing.
3. **Assess exposure.** Determine whether the recipient merely received the message, opened an attachment, visited a destination, entered credentials or approved a prompt. Seek confirmation through an independently verified channel. Do not request passwords, tokens or MFA codes. Review relevant message, sign-in and endpoint evidence only within the responder's authorized scope.
4. **Choose a response.** If evidence suggests credential submission or account misuse, escalate according to the incident process and consider session revocation, credential reset and MFA recovery under authorized procedures. If a dangerous attachment may have run, consider isolating the device and preserving evidence under the endpoint-response process. Consider message quarantine or blocking only after verification and authorization. Availability, false positives and business impact matter.
5. **Close or continue.** Document evidence, scope, decisions, owners, times and remaining unknowns. Resolve as benign only when supported; otherwise keep the case open or escalate. Share a concise, non-sensitive awareness lesson through approved channels if appropriate.

## Paper-only walkthrough

### Invented intake artifact

The following is a constructed exercise prompt, not an observed lab message. `PAPER-MSG-01` is an exercise identifier, **not** an event ID or alert ID. No live address or URL is intended.

- Claimed sender: `Account Support <support@account-access.example>`.
- Claimed recipient: `member17@pulse-lab.example`.
- Subject: “Action needed to keep your account access.”
- Body summary: asks the recipient to sign in urgently at `hxxps://account-access.example/verify` and warns of account suspension.
- Exercise intake: a fictional recipient reports receiving the message; the prompt supplies no evidence about opening the link or entering information.

The `.example` domain and disabled `hxxps` representation are fictional placeholders. The claimed sender and urgency justify investigation, but the prompt supplies no verified sender authentication, delivery headers, policy baseline or recipient action.

### Walkthrough decisions

| Step | Paper observation or hypothetical branch | Proposed response | Decision limit |
| --- | --- | --- | --- |
| 1 | Only the constructed intake artifact is available. | Preserve the supplied artifact and request original headers through the appropriate authorized process. | No message handling or preservation was actually performed. |
| 2 | The message asks for a sign-in under time pressure and uses a domain different from the fictional recipient domain. | Compare the destination and sender with trusted account-service records and inspect headers without visiting the link. | A domain difference or urgency is not conclusive proof of phishing. |
| 3 | The prompt says nothing about a click or credential entry. | Ask the fictional recipient via an independently verified channel whether any interaction occurred; do not ask for secrets. | No confirmation or outreach occurred. |
| 4A | **Hypothetical:** reliable evidence later shows credentials were entered. | Escalate; consider revoking sessions, resetting credentials and reviewing sign-in/MFA records under the authorized process. | This branch is conditional; none of these actions or findings occurred. |
| 4B | **Hypothetical:** a trusted source verifies the message and no suspicious activity is found. | Record the evidence and consider benign closure under the applicable process. | The exercise provides no such verification, so this branch is not the current disposition. |
| 5 | Current exercise evidence is insufficient to verify the message or interaction. | Keep the paper case open pending verification and record the unresolved facts. | No incident, compromise, delivery scope or business impact is established. |

**Paper disposition:** suspicious message requiring verification; interaction and compromise unknown. This disposition is an exercise judgment about the invented prompt, not a finding from the lab alert dataset. No real response, notification, remediation or external communication occurred.
