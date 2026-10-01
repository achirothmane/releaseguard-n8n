# n8n production workflow safety: evidence before 100% traffic

A workflow is not production-safe merely because it imports, activates, or returns HTTP 200.

For business-critical n8n automations, a release can be wrong in ways that ordinary uptime checks do not catch: invalid fields, contradictory values, latency regression, intermittent errors, or a Candidate that looks healthy only because the sample is too small.

ReleaseGuard makes the release decision from explicit evidence.

## The safety model

The protected request path is:

`request → admission → Stable/Candidate execution → validation → observation → decision`

The release controller can return:

- **PROMOTE** — evidence supports increasing Candidate exposure.
- **HOLD** — more or better evidence is required.
- **ROLLBACK** — measured regression crosses the configured boundary.

ReleaseGuard does not ask an LLM to decide whether a release is safe. The decision is deterministic from configured policy and measured observations.

## Evidence before promotion

Useful production gates include:

- Minimum request samples.
- Error-rate budgets.
- Wilson confidence bounds.
- Absolute and relative p95 latency limits.
- JSON Schema validation.
- Cross-field business invariants.
- Dwell time at the current stage.
- A separate fresh confirmation batch.
- A live Stable baseline.

At 100% Candidate traffic, ReleaseGuard can still send a small percentage of read-only control probes to Stable. This keeps the baseline observable instead of comparing the Candidate only with historical data.

## Fail closed when reality is unclear

Incomplete, stale, or contradictory observations should not silently become success.

ReleaseGuard can pause Candidate admission when metrics are unusable or Stable itself is unhealthy. If rollback cannot be confirmed, it rejects behind a local safety fence rather than claiming that a safe state was restored.

## Scope matters

ReleaseGuard v0.1 is for synchronous read-only JSON transformations such as enrichment, classification, extraction, normalization, and scoring.

It does not provide generic compensation for irreversible side effects. If a workflow already sent a message, charged a payment, or mutated an external system, routing future requests to Stable does not undo that effect.

## Use the open-source core or the packaged production path

The repository contains the core implementation and validation evidence.

The **ReleaseGuard Production Pack** adds a tested release bundle, production policy presets, deployment checklist, rollback drill, incident runbook, configuration examples, and release evidence:

https://othmaneachir.gumroad.com/l/releaseguard-n8n-production

See also:

- [Canary deployment for n8n workflows](n8n-canary-deployment.md)
- [Automatic rollback for n8n workflows](n8n-automatic-rollback.md)
