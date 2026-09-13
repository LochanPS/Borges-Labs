# docs-site

The public docs: a landing + **7-step quickstart** page and the **/v1 API reference**,
generated from `contracts/openapi.v1.yaml` (Task 4.3). The reference is generated, not
handwritten, so it stays in sync with the contract.

## What builds

| Output | Source | How |
|---|---|---|
| `public/api.html` | `contracts/openapi.v1.yaml` | Redocly `build-docs` (self-contained Redoc) |
| `public/openapi.bundled.json` | same, external `$ref`s inlined | Redocly `bundle` |
| `public/index.html` | `src/index.html` | copied (landing + quickstart, verdicts, fail-modes) |

The build also runs `redocly lint` first and fails if the spec is invalid, and asserts
the rendered reference actually contains the contract's operations — so a broken or
stale spec breaks the build instead of shipping wrong docs.

## Commands

```bash
npm install
npm run build     # lint + bundle + build-docs + copy -> public/
npm run serve     # preview at http://localhost:4400
```

Individual steps: `npm run lint`, `npm run bundle`, `npm run build:api`.

## Staying in sync (CI)

`npm run build` is the guard: it regenerates everything from the single-source spec and
lints it. Wire it into CI on any change under `contracts/` — a contract edit that
doesn't lint, or drops an operation, fails the build.

## Notes

- `@redocly/cli` is a dev-only dependency (docs tooling); its `npm audit` advisories do
  not affect the shipped SDKs or the runtime service.
- Output (`public/`) and `node_modules/` are gitignored; the site is a build artifact.
- The quickstart's SDK snippets mirror the Python (`sdks/python`) and TypeScript
  (`sdks/ts`) SDKs; their own READMEs are the deeper reference.
