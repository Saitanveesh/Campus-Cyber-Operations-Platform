# Security Model

## Non-negotiable controls

- Passive monitoring and host control are separate privilege domains.
- Live state is current-session-only.
- Every worker has explicit health and freshness state.
- Remote-control actions require an enrolled/authorized endpoint and an explicit permission check.
- Secrets are never hard-coded in source or committed to the repository.
- Evidence exports are hashed and attributable to a session and incident.
- External tool output is treated as untrusted input and parsed defensively.
- A missing tool reduces capability; it does not silently substitute synthetic telemetry.

## Roles

- Observer: read-only telemetry
- Analyst: investigate alerts and incidents
- Responder: execute approved containment/evidence actions
- Lab Administrator: manage enrolled lab endpoints and remote sessions
- Platform Administrator: configuration, policy and platform lifecycle

## Response action policy

Every response request must include:

- operator identity
- target endpoint identity
- action type
- reason / incident id
- authorization decision
- start/end timestamp
- result

The platform will not implement unauthenticated or opportunistic takeover of arbitrary network-visible hosts.

## Detection language

Use `indicator`, `suspected`, `likely`, and `confidence` when evidence is incomplete. Use definitive malware/attack labels only when a deterministic rule, trusted signature, verified artifact, or equivalent evidence supports them.

## Fail-closed UI

If the API, sensor, session, capture backend or required worker becomes invalid, affected live fields are cleared or explicitly marked unavailable. Historical values must never remain on screen as though they are current.
