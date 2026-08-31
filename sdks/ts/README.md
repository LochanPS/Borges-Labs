# TypeScript SDK

Placeholder. Built in ROADMAP Phase 4. Thin client mirroring the Python SDK:
canonicalize + HMAC-sign, call `/v1/authorize`, verify the Ed25519 decision
signature, apply `on_unavailable` fallback, expose `authorize()` + `shadow()`.
Types shared with policy-svc + dashboard, generated from `/contracts`.
