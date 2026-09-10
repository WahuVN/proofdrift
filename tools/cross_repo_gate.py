#!/usr/bin/env python3
"""Cross-repository conformance and release-evidence gate for ProofDrift."""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ENGINE_ROOT = Path(__file__).resolve().parents[1]
EXPECTED_DRIFT_CLASSES = {
    "provenance_drift",
    "capability_drift",
    "policy_drift",
    "runtime_drift",
    "patch_impact_drift",
    "test_proof_drift",
}


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise RuntimeError(f"{path}: root must be an object")
    return value


def git_commit(root: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=False, text=True, capture_output=True
    )
    if completed.returncode != 0:
        raise RuntimeError(f"cannot resolve git commit for {root}: {completed.stderr.strip()}")
    return completed.stdout.strip()


def engine_schema_version() -> str:
    text = (ENGINE_ROOT / "crates" / "proofdrift-schema" / "src" / "lib.rs").read_text(
        encoding="utf-8"
    )
    match = re.search(r'pub const SCHEMA_VERSION: &str = "([^"]+)";', text)
    if not match:
        raise RuntimeError("could not locate proofdrift-schema SCHEMA_VERSION")
    return match.group(1)


def run_json_validator(cwd: Path, script: str) -> dict:
    completed = subprocess.run(
        [sys.executable, script], cwd=cwd, check=False, text=True, capture_output=True
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"validator failed: {cwd / script}\n{completed.stderr or completed.stdout}"
        )
    text = completed.stdout.strip()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"validator did not emit JSON: {cwd / script}: {exc}") from exc
    if not isinstance(value, dict) or value.get("status") not in (None, "pass"):
        raise RuntimeError(f"validator returned a non-passing result: {cwd / script}")
    return value


def run_validator(cwd: Path, script: str) -> str:
    completed = subprocess.run(
        [sys.executable, script], cwd=cwd, check=False, text=True, capture_output=True
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"validator failed: {cwd / script}\n{completed.stderr or completed.stdout}"
        )
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True, type=Path)
    parser.add_argument("--bench", required=True, type=Path)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()

    spec = args.spec.resolve()
    bench = args.bench.resolve()
    if not spec.is_dir() or not bench.is_dir():
        raise RuntimeError("spec and bench paths must exist")

    # Run each repository's own fail-closed validators first. Cross-repo code must not
    # duplicate or silently weaken the native release policy.
    spec_validation = run_validator(spec, "contracts/tools/validate_examples.py")
    spec_conformance = run_validator(spec, "contracts/tools/validate_conformance.py")
    spec_semantics = run_json_validator(spec, "contracts/tools/validate_semantics.py")
    spec_release = run_json_validator(spec, "contracts/tools/security_release_gate.py")

    bench_corpus = run_validator(bench, "verify_corpus.py")
    bench_quality = run_json_validator(bench, "verify_quality_gate.py")
    bench_release = run_json_validator(bench, "security_release_gate.py")

    schema_version = engine_schema_version()
    spec_index = load_json(spec / "contracts" / "schemas" / "index.json")
    if spec_index.get("schema_version") != schema_version:
        raise RuntimeError(
            f"schema version mismatch: engine={schema_version} spec={spec_index.get('schema_version')}"
        )
    if spec_index.get("canonicalization") != "proofdrift-json-v1":
        raise RuntimeError("unexpected spec canonicalization profile")
    schema_ids = spec_index.get("schema_ids")
    if not isinstance(schema_ids, dict) or len(schema_ids) != len(spec_index.get("schemas", [])):
        raise RuntimeError("spec schema_ids coverage is incomplete")
    if any(not value.startswith(f"urn:proofdrift:schema:{schema_version}:") for value in schema_ids.values()):
        raise RuntimeError("spec contains non-versioned or mutable schema identity")

    manifest = load_json(bench / "benchmark_manifest.json")
    if manifest.get("benchmark_version") != "3":
        raise RuntimeError("ProofDrift engine release requires Bench v3")
    if set(manifest.get("drift_classes") or []) != EXPECTED_DRIFT_CLASSES:
        raise RuntimeError("Bench v3 does not cover the six required drift classes")
    counts = manifest.get("counts") or {}
    if counts.get("drift_pairs", 0) < 24 or counts.get("hard_controls", 0) < 18:
        raise RuntimeError("Bench v3 science surface regressed below the accepted release baseline")
    if bench_release.get("science_oracle_digest") != manifest.get("drift_suite_digest"):
        raise RuntimeError("Bench v3 science oracle digest does not match its manifest")
    if spec_release.get("schemas") != len(spec_index["schemas"]):
        raise RuntimeError("spec release evidence schema count disagrees with the index")
    if spec_semantics.get("fixture_trace_coverage") != 1.0:
        raise RuntimeError("spec semantic fixture trace coverage must remain 100%")

    evidence = {
        "schema_version": "2",
        "gate": "proofdrift_cross_repo_release_gate",
        "status": "pass",
        "commits": {
            "engine": git_commit(ENGINE_ROOT),
            "spec": git_commit(spec),
            "bench": git_commit(bench),
        },
        "engine": {
            "schema_version": schema_version,
        },
        "spec": {
            "schemas": len(spec_index["schemas"]),
            "immutable_schema_ids": len(schema_ids),
            "contract_tree_sha256": spec_release.get("contract_tree_sha256"),
            "semantic_digest": spec_semantics.get("semantic_digest"),
            "fixture_trace_coverage": spec_semantics.get("fixture_trace_coverage"),
            "validation_summary": spec_validation,
            "conformance_summary": spec_conformance,
        },
        "bench": {
            "benchmark_version": manifest.get("benchmark_version"),
            "legacy_cases": bench_release.get("legacy_cases"),
            "drift_pairs": bench_release.get("drift_pairs"),
            "hard_controls": bench_release.get("hard_controls"),
            "science_targets": bench_release.get("science_targets"),
            "drift_classes": sorted(EXPECTED_DRIFT_CLASSES),
            "drift_suite_digest": manifest.get("drift_suite_digest"),
            "quality_target_set_digest": bench_quality.get("target_set_digest"),
            "corpus_summary": bench_corpus,
        },
    }
    rendered = json.dumps(evidence, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.json_output:
        args.json_output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
