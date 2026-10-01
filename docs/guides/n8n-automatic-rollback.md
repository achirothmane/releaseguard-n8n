# n8n automatic rollback: stop a bad workflow release

Automatic rollback is useful only when the system can prove what it is rolling back from and what state is safe afterward.

ReleaseGuard treats rollback as a state transition, not just an alert or a percentage change in a workflow node.

## What can trigger rollback?

A Candidate can regress in several ways:

- Error rate rises above the configured budget.
- p95 latency exceeds an absolute or relative threshold.
- Output violates its JSON Schema.
- Output is structurally valid but violates a declared business invariant.
- Partial failures accumulate across the canary sample.
- A fresh confirmation batch fails after earlier evidence looked healthy.

When a configured rollback condition is met, ReleaseGuard commits Stable-only routing, increments the routing revision, records decision evidence, and queues an alert.

## What about the request that already hit Candidate?

For supported read-only workloads, ReleaseGuard can preserve the Candidate failure as evidence and serve a validated Stable fallback for the current request.

That matters because returning a successful fallback must not erase the fact that the Candidate failed. The failed Candidate execution still contributes to the release decision.

## What if rollback itself fails?

A release controller should not report success when it cannot prove that rollback committed.

ReleaseGuard tests rollback failure and delayed rollback explicitly. If the safety mutation cannot be confirmed, the local admission fence rejects new protected requests instead of claiming the system is safely back on Stable.

This is intentionally conservative: UNKNOWN is safer than false success.

## Why this is different from workflow version history

Version control and backups answer which workflow artifact existed before. Automatic rollback during live traffic answers a different question: should the current Candidate continue receiving requests right now?

Both are useful. ReleaseGuard complements source control by making routing decisions from observed runtime behavior.

## Try it

The repository includes adversarial HTTP/PostgreSQL tests and real n8n production-webhook integration tests covering rollback, delayed commit, invalid outputs, stale tickets, duplicate requests, and concurrent evaluators.

For a packaged production workflow with presets and a rollback drill:

**ReleaseGuard Production Pack:** https://othmaneachir.gumroad.com/l/releaseguard-n8n-production?utm_source=github&utm_medium=seo_guide&utm_campaign=releaseguard_n8n&utm_content=automatic_rollback

See also:

- [Canary deployment for n8n workflows](n8n-canary-deployment.md)
- [Production workflow safety for n8n](n8n-production-workflow-safety.md)
