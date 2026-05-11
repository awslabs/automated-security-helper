"""Generate Pydantic v2 models from the vendored JSON Schemas.

For each schema declared in schemas/schemas.json, runs `datamodel-code-generator`
to produce a Pydantic model module under `transpiler/generated_models/`. These
models are then imported by validate.py to validate generated outputs with
proper Python type-safety + clean Pydantic ValidationError messages.

Run via:
    uv run --project agentic-coding/transpiler --extra refresh generate-models

The generated_models/ directory is committed (so CI doesn't need datamodel-code-
generator), but should only be regenerated after a corresponding schema refresh.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent          # transpiler/tools
TRANSPILER_DIR = HERE.parent                     # transpiler/
SCHEMAS_DIR = TRANSPILER_DIR / "schemas"
SCHEMAS_INDEX = SCHEMAS_DIR / "schemas.json"
MODELS_DIR = TRANSPILER_DIR / "generated_models"


def _slug_to_module(filename: str) -> str:
    """schema filename (e.g. 'mcpb-manifest.schema.json') -> module name
    ('mcpb_manifest'). Strips '.schema.json' suffix and replaces hyphens
    with underscores."""
    stem = filename.removesuffix(".json").removesuffix(".schema")
    return stem.replace("-", "_")


def main() -> int:
    if shutil.which("datamodel-codegen") is None:
        sys.stderr.write(
            "ERROR: datamodel-codegen not found.\n"
            "Run with the refresh extras enabled:\n"
            "  uv run --project agentic-coding/transpiler --extra refresh generate-models\n"
        )
        return 2

    if not SCHEMAS_INDEX.exists():
        sys.stderr.write(f"ERROR: {SCHEMAS_INDEX} not found\n")
        return 1
    index = json.loads(SCHEMAS_INDEX.read_text())

    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    init = MODELS_DIR / "__init__.py"
    if not init.exists():
        init.write_text('"""Pydantic models generated from vendored JSON Schemas."""\n')

    failures: list[str] = []
    for entry in index["schemas"]:
        filename = entry["filename"]
        schema_path = SCHEMAS_DIR / filename
        if not schema_path.exists():
            sys.stderr.write(f"  SKIP: {filename} not yet vendored — run refresh-schemas first\n")
            continue
        module_name = _slug_to_module(filename)
        out_path = MODELS_DIR / f"{module_name}.py"
        print(f"Generating {out_path.relative_to(TRANSPILER_DIR)} from {schema_path.relative_to(TRANSPILER_DIR)}")
        try:
            subprocess.run(
                [
                    "datamodel-codegen",
                    "--input", str(schema_path),
                    "--input-file-type", "jsonschema",
                    "--output", str(out_path),
                    "--output-model-type", "pydantic_v2.BaseModel",
                    "--use-schema-description",
                    "--use-field-description",
                    "--use-default-kwarg",
                    "--target-python-version", "3.11",
                    "--use-standard-collections",
                    "--use-union-operator",
                ],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            sys.stderr.write(f"  ERROR: codegen failed for {filename}: {e}\n")
            failures.append(filename)
            continue
        print(f"  -> {out_path.stat().st_size} bytes")

    print()
    if failures:
        print(f"FAILED: {len(failures)} schema(s): {failures}")
        return 1
    print("Done. Run `uv run --project agentic-coding/transpiler transpile --check` to confirm validation still passes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
