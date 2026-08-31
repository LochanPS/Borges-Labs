# Python SDK

Placeholder. Built in ROADMAP Phase 4. Thin client: canonicalize + HMAC-sign the
request, call `/v1/authorize`, verify the Ed25519 decision signature, apply
`on_unavailable = FAIL_CLOSED | FAIL_OPEN | LOCAL_CACHE`, expose
`authorize()` + `shadow()`. Models generated from `/contracts` (OpenAPI).
