# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Literal


def generate_schemas(output: Literal["file", "json", "dict"] = "file"):
    """Generate JSON schemas for the models."""
    from pathlib import Path
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.models.asharp_model import ASHARPModel
    import json

    cur_file_path = Path(__file__)
    # create schemas dir if not existing
    schemas_dir = cur_file_path.parent
    resp = {}
    for model in [AshConfig, ASHARPModel]:
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
            with open(json_schema_path, "w") as f:
                json.dump(
                    schema,
                    f,
                    indent=2,
                    default=str,
                    sort_keys=True,
                )
                # add final new line so pre-commit doesn't see changes on every run
                f.writelines("\n")
    return resp


def main():
    generate_schemas("file")


if __name__ == "__main__":
    main()
