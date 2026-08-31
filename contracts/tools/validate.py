#!/usr/bin/env python3
"""Validate the frozen /v1 contract: JSON Schemas, examples, and the OpenAPI spec.

Usage:
    python contracts/tools/validate.py

Requires: jsonschema>=4.18, referencing, pyyaml, openapi-spec-validator.
Exit code is non-zero if anything fails. Wire this into CI as a contract test.
"""
import json
import pathlib
import sys

from jsonschema.validators import validator_for
from referencing import Registry, Resource

ROOT = pathlib.Path(__file__).resolve().parents[1]  # /contracts
SCHEMAS = ROOT / "schemas"
EXAMPLES = ROOT / "examples"

failures = 0


def fail(msg: str) -> None:
    global failures
    failures += 1
    print("FAIL " + msg)


def ok(msg: str) -> None:
    print("OK   " + msg)


# --- load schemas into a registry (by $id, bare filename, and canonical URL) ---
by_file = {}
registry = Registry()
for p in sorted(SCHEMAS.glob("*.json")):
    doc = json.loads(p.read_text(encoding="utf-8"))
    by_file[p.name] = doc
    res = Resource.from_contents(doc)
    if doc.get("$id"):
        registry = registry.with_resource(doc["$id"], res)
    registry = registry.with_resource(p.name, res)
    registry = registry.with_resource(f"https://contracts.trust-infra.dev/v1/{p.name}", res)

for name, doc in by_file.items():
    Cls = validator_for(doc)
    try:
        Cls.check_schema(doc)
        ok(f"schema compiles: {name}")
    except Exception as ex:  # noqa: BLE001
        fail(f"schema {name}: {ex}")


def validate_example(schema_file: str, example_file: str) -> None:
    schema = by_file[schema_file]
    data = json.loads((EXAMPLES / example_file).read_text(encoding="utf-8"))
    Cls = validator_for(schema)
    v = Cls(schema, registry=registry)
    errs = sorted(v.iter_errors(data), key=lambda e: list(e.path))
    if errs:
        fail(f"{example_file} against {schema_file}:")
        for e in errs:
            print(f"       - {list(e.path)}: {e.message}")
    else:
        ok(f"{example_file} valid against {schema_file}")


validate_example("authorize-request.schema.json", "authorize-request.example.json")
validate_example("decision.schema.json", "decision-approve.example.json")
validate_example("decision.schema.json", "decision-deny.example.json")

# --- OpenAPI 3.1 structural validation (external refs resolved from disk) ---
try:
    from openapi_spec_validator import validate as validate_openapi
    from openapi_spec_validator.readers import read_from_filename

    spec, base = read_from_filename(str(ROOT / "openapi.v1.yaml"))
    validate_openapi(spec, base_uri=base)
    ok("openapi.v1.yaml is a valid OpenAPI 3.1 document")
except ImportError:
    print("SKIP openapi validation (openapi-spec-validator not installed)")
except Exception as ex:  # noqa: BLE001
    fail(f"openapi.v1.yaml: {type(ex).__name__}: {str(ex)[:400]}")

print()
print("RESULT:", "PASS" if failures == 0 else f"FAIL ({failures})")
sys.exit(1 if failures else 0)
