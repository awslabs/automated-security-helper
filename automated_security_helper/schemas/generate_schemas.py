# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Literal


def generate_schemas(output: Literal["file", "json", "dict"] = "file"):
    """Generate JSON schemas for the models."""
    from pathlib import Path
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    import json

    cur_file_path = Path(__file__)
    # create schemas dir if not existing
    schemas_dir = cur_file_path.parent
    resp = {}
    for model in [AshConfig, AshAggregatedResults]:
        json_schema_path = schemas_dir.joinpath(f"{model.__name__}.json").resolve()
        schema = model.model_json_schema()
        if output == "dict":
            resp[model.__name__] = schema
        elif output == "json":
            resp[model.__name__] = json.dumps(
                schema,
                indent=2,
                default=str,
                sort_keys=True,
            )
        else:
            resp = None
            new_content = (
                json.dumps(
                    schema,
                    indent=2,
                    default=str,
                    sort_keys=True,
                )
                + "\n"
            )
            # Only write if content actually changed to avoid triggering
            # pre-commit "files were modified" on unchanged schemas
            existing_content = ""
            if json_schema_path.exists():
                existing_content = json_schema_path.read_text(encoding="utf-8")
            if new_content != existing_content:
                json_schema_path.write_text(new_content, encoding="utf-8")
    return resp


def main():
    generate_schemas("file")


if __name__ == "__main__":
    main()
