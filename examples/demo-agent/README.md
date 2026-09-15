# Free demo agent

See the authorization product working end to end — a simulated AI procurement agent
that authorizes every transaction **before** the (mock) payment and enforces the verdict.

No account or backend needed for mock mode; it uses a local Ed25519 signer that returns
**real signed decisions**, so the SDK's signature verification genuinely runs.

## Run (mock — nothing to install but the SDK's one dep)

```bash
pip install cryptography          # the Python SDK's only runtime dependency
python examples/demo-agent/agent.py
```

You'll see a stream of APPROVE / DENY / REVIEW decisions with reasons, blocked payments,
and a client-side signature check. Options:

```bash
python examples/demo-agent/agent.py --count 12         # more transactions
python examples/demo-agent/agent.py --shadow           # observe-only: never blocks
```

## Run against a live service

```bash
python examples/demo-agent/agent.py \
  --base-url https://<authorize-host> \
  --api-key azn_test_...            # a test (shadow) key from the dashboard
```

## What it demonstrates

- The **3-line integration**: `client.authorize(txn).enforce()` before your payment call.
- **Deterministic, explained verdicts** (per-transaction limit, budget, vendor allowlist).
- **Shadow mode** (`--shadow`) — the adoption wedge: evaluate + log without blocking.
- **Third-party-verifiable receipts** — `verify_decision` validates the Ed25519 signature.

Prefer clicking? The dashboard **Playground** page does the same thing in the browser.
