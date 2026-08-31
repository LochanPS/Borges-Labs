# policy-svc — Control Plane (TypeScript / Node + Fastify)

Placeholder scaffold. Built out in ROADMAP Phase 2. Not latency-critical and
**never in the payment path** (TRD §3 boundary rule).

## Language decision: TypeScript/Node (chosen over Python/FastAPI)

The control plane authors, versions, and publishes policy bundles that the Go
decision plane consumes. TRD §4 permits Python **or** Node here; we pick Node.

**Why TypeScript wins for the long-term product:**

- **One type system from the contract out.** `/contracts` (OpenAPI 3.1 + JSON
  Schema) is the source of truth. policy-svc, the Next.js dashboard, and the TS
  SDK can all consume generated TypeScript types directly — no cross-language
  translation layer. Schema drift is the enemy of an auditable authorization
  product; sharing types structurally prevents it.
- **Perf is irrelevant here.** The hot path is Go (TRD §4). The control plane
  does CRUD, validation, hashing, signing — Python's speed disadvantage never
  bites, and its type-drift cost is real.
- **Fewer toolchains to operate.** Go (decision plane) + Node (control plane +
  dashboard + TS SDK) is two runtimes; adding Python would be three.

Python still appears — as the **python SDK** (generated from the same OpenAPI)
and the optional ComplianceAPI policy-pack demo. Those are independent of this
service's language.

## Scope (later)
Policy CRUD, validation, content-hash + Ed25519 bundle signing, versioning,
bundle propagation to decision nodes, `GET /v1/policies/active` (ROADMAP A#4),
shadow/simulate.
