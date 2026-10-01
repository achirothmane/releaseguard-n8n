# n8n canary deployment: roll out workflow changes gradually

A production n8n workflow can fail even when the webhook still returns HTTP 200. The response can be slow, structurally valid but semantically wrong, or only fail for a subset of requests. A canary deployment limits how much traffic reaches the new Candidate while you collect evidence.

ReleaseGuard uses a Stable workflow and a Candidate workflow. The Candidate receives progressively more protected traffic only when the current stage passes deterministic gates.

## Recommended rollout

A typical release progresses through:

`Stable → 5% → 25% → 50% → 100%`

At every stage, ReleaseGuard evaluates measured executions rather than assuming that a successful import or activation means the release is safe.

The gate can consider:

- Candidate error rate.
- Candidate p95 latency.
- JSON Schema validity.
- Cross-field business invariants.
- Minimum sample count.
- Confidence bounds.
- Dwell time.
- Fresh confirmation batches.
- Stable health.

If evidence is insufficient, the correct outcome is HOLD, not PROMOTE.

## Why random traffic splitting is not enough

A simple n8n Switch or IF node can send 5% of requests to a Candidate. That solves traffic splitting, but not release safety.

A production canary also needs durable state and clear answers to questions such as:

- What happens when two evaluators try to promote at the same time?
- What happens when a request was admitted to Candidate just before rollback?
- What happens when metrics are incomplete?
- What happens when Stable is also unhealthy?
- What happens when a Candidate returns valid JSON with the wrong business meaning?

ReleaseGuard keeps the routing revision, observations, decision evidence, and alert outbox in PostgreSQL so those decisions can be made transactionally.

## Before sending real traffic

Use separate published production webhook URLs for Stable and Candidate. Configure the release policy and output contract, run the Setup Doctor, and perform the rollback drill in staging.

ReleaseGuard v0.1 is intentionally scoped to synchronous read-only JSON transformations. Put it before irreversible CRM writes, messages, payments, or other side effects. It does not undo effects already executed downstream.

## Reproduce the implementation

The open-source repository contains the workflows, service, PostgreSQL schema, tests, and validation evidence.

For teams that want the tested release bundle plus production rollout presets, deployment checklist, rollback drill, incident runbook, and configuration examples:

**ReleaseGuard Production Pack:** https://othmaneachir.gumroad.com/l/releaseguard-n8n-production

See also:

- [Automatic rollback for n8n workflows](n8n-automatic-rollback.md)
- [Production workflow safety for n8n](n8n-production-workflow-safety.md)
