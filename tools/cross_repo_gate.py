#!/usr/bin/env python3
"""Cross-repository conformance and release-evidence gate for ProofDrift."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
DRIFT_FAMILIES = {
    "provenance drift": {"missing_provenance_trusted", "provenance_conflict"},
    "capability drift": {"capability_inferred_as_observed", "tool_schema_rugpull", "broad_shell"},
    "policy drift": {"policy_digest_mismatch", "approval_scope_mismatch", "decision_request_digest_mismatch"},
    "runtime drift": {"unknown_enforcement_claim", "toctou_executable_swap", "approval_concurrent_replay"},
    "patch-impact drift": {"risky_auth_patch", "risky_db_patch", "risky_concurrency_patch"},
    "test-proof drift": {"test_weakening", "test_claim_without_observation"},
}
CRITICAL_SECURITY_CATEGORIES = {
    "tampered_receipt",
    "approval_concurrent_replay",
    "missing_provenance_trusted",
    "policy_digest_mismatch",
    "decision_request_digest_mismatch",
    "toctou_executable_swap",
    "evidence_reorder",
    "evidence_deleted_event",
}
CRITICAL_SPEC_FIXTURES = {
    "approval-replay.json",
    "bundle-corrupted-byte.json",
    "policy-digest-changed.json",
    "provenance-missing-edge.json",
}


def canonical_digest(value: object) -> str:
    raw = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def engine_schema_version() -> str:
    text = (ENGINE_ROOT / "crates" / "proofdrift-schema" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    match = re.search(r'pub const SCHEMA_VERSION: &str = "([^"]+)";', text)
    if not match:
        raise RuntimeError("could not locate proofdrift-schema SCHEMA_VERSION")
    return match.group(1)


def run_native_validator(cwd: Path, script: str) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, script],
        cwd=cwd,
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"native validator failed in {cwd}: {completed.stderr or completed.stdout}"
        )
    return {
        "status": "pass",
        "command": f"{Path(sys.executable).name} {script}",
        "summary": completed.stdout.strip(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--bench", required=True, type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--release-strict",
        action="store_true",
        help="Require benchmark ground-truth reason metadata expected after benchmark-science merge.",
    )
    args = parser.parse_args()

    spec = args.spec.resolve()
    bench = args.bench.resolve()
    native_spec = run_native_validator(spec, "contracts/tools/validate_examples.py")
    native_bench = run_native_validator(bench, "verify_corpus.py")

    schema_version = engine_schema_version()
    spec_index = load_json(spec / "contracts" / "schemas" / "index.json")
    if spec_index.get("schema_version") != schema_version:
        raise RuntimeError(
            f"schema version mismatch: engine={schema_version} spec={spec_index.get('schema_version')}"
        )
    if spec_index.get("canonicalization") != "proofdrift-json-v1":
        raise RuntimeError("unexpected spec canonicalization profile")

    schema_dir = spec / "contracts" / "schemas"
    indexed_schemas = set(spec_index.get("schemas", []))
    actual_schemas = {path.name for path in schema_dir.glob("*.schema.json")}
    if indexed_schemas != actual_schemas:
        raise RuntimeError(
            f"schema index mismatch: missing={sorted(actual_schemas - indexed_schemas)} "
            f"stale={sorted(indexed_schemas - actual_schemas)}"
        )

    valid_names = {
        path.name.removesuffix(".valid.json")
        for path in (spec / "contracts" / "examples" / "valid").glob("*.valid.json")
    }
    schema_names = {name.removesuffix(".schema.json") for name in indexed_schemas}
    if valid_names != schema_names:
        raise RuntimeError(
            f"valid example coverage mismatch: schemas_without_example={sorted(schema_names - valid_names)} "
            f"examples_without_schema={sorted(valid_names - schema_names)}"
        )

    fixture_names = {
        path.name for path in (spec / "contracts" / "fixtures").glob("*.json")
    }
    missing_fixtures = CRITICAL_SPEC_FIXTURES - fixture_names
    if missing_fixtures:
        raise RuntimeError(f"missing critical spec fixtures: {sorted(missing_fixtures)}")

    case_paths = sorted((bench / "corpus").glob("*.json"))
    cases = [load_json(path) for path in case_paths]
    if not cases:
        raise RuntimeError("benchmark corpus is empty")
    ids = [case.get("id") for case in cases]
    if len(ids) != len(set(ids)):
        raise RuntimeError("benchmark corpus contains duplicate case ids")
    for path, case in zip(case_paths, cases, strict=True):
        required = {"schema_version", "id", "category", "benign", "input", "expected", "tags"}
        if not required <= set(case):
            raise RuntimeError(f"{path.name}: missing required corpus fields")
        if case.get("schema_version") != "1":
            raise RuntimeError(f"{path.name}: unsupported corpus schema version")
        if not case.get("expected", {}).get("minimum_evidence"):
            raise RuntimeError(f"{path.name}: expected.minimum_evidence must not be empty")

    categories = {case["category"] for case in cases}
    missing_security = CRITICAL_SECURITY_CATEGORIES - categories
    if missing_security:
        raise RuntimeError(f"missing security regression categories: {sorted(missing_security)}")

    family_evidence: dict[str, list[str]] = {}
    for family, candidates in DRIFT_FAMILIES.items():
        present = sorted(categories & candidates)
        if not present:
            raise RuntimeError(f"benchmark corpus has no evidence for required family {family!r}")
        family_evidence[family] = present

    benchmark_reference = load_json(bench / "benchmark_result_reference.json")
    if benchmark_reference.get("cases") != len(cases):
        raise RuntimeError("benchmark reference case count does not match corpus")
    if benchmark_reference.get("operations") != len(cases) * benchmark_reference.get("iterations", 0):
        raise RuntimeError("benchmark reference operation count is internally inconsistent")

    ground_truth_reason_count = sum(
        1
        for case in cases
        if case.get("ground_truth_reason")
        or case.get("expected", {}).get("ground_truth_reason")
    )
    if args.release_strict and ground_truth_reason_count != len(cases):
        raise RuntimeError(
            "release-strict requires ground-truth reason metadata for every benchmark case; "
            f"found {ground_truth_reason_count}/{len(cases)}"
        )

    evidence = {
        "schema_version": "1",
        "gate": "proofdrift_cross_repo_release_gate",
        "status": "pass",
        "engine_schema_version": schema_version,
        "canonicalization": spec_index["canonicalization"],
        "spec": {
            "schemas": len(indexed_schemas),
            "valid_examples": len(valid_names),
            "critical_fixtures": sorted(CRITICAL_SPEC_FIXTURES),
            "native_validator": native_spec,
        },
        "bench": {
            "cases": len(cases),
            "categories": len(categories),
            "benign_cases": sum(1 for case in cases if case["benign"]),
            "adversarial_cases": sum(1 for case in cases if not case["benign"]),
            "corpus_digest": canonical_digest(cases),
            "required_drift_families": family_evidence,
            "critical_security_categories": sorted(CRITICAL_SECURITY_CATEGORIES),
            "ground_truth_reason_coverage": f"{ground_truth_reason_count}/{len(cases)}",
            "native_validator": native_bench,
        },
        "release_strict": args.release_strict,
    }

    rendered = json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.json_output:
        args.json_output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
