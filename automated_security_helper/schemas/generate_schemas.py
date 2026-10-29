# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Literal

from pydantic.json_schema import GenerateJsonSchema


class StoredResultsJsonSchema(GenerateJsonSchema):
    """The results schema, which accepts the unknown keys a results load keeps.

    Ignore paths, suppressions, plugin options and plugin sections refuse an
    unknown key in a configuration file, and their schemas say
    ``additionalProperties: false``.
    A results file is loaded tolerantly instead (``utils/unknown_keys.py``): one
    written by another ASH version keeps such a key, with a warning, and the
    entry or option is not applied. The configuration stored in a results file
    is the same model, so without this the results schema would call a file
    invalid that ASH reads. For those models it says ``additionalProperties:
    true``; every other model is unchanged.
    """

    def model_schema(self, schema: Any) -> Any:
        from automated_security_helper.base.options import PluginOptionsBase
        from automated_security_helper.base.plugin_config import PluginConfigBase
        from automated_security_helper.models.core import IgnorePathWithReason

        json_schema = super().model_schema(schema)
        cls = schema.get("cls")
        if isinstance(cls, type) and issubclass(
            cls, (IgnorePathWithReason, PluginOptionsBase, PluginConfigBase)
        ):
            json_schema["additionalProperties"] = True
        return json_schema


def generate_schemas(output: Literal["file", "json", "dict"] = "file"):
    """Generate JSON schemas for the models."""
    import json
    from pathlib import Path

    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.ash_workspace_config import (
        AshWorkspaceConfig,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    cur_file_path = Path(__file__)
    # create schemas dir if not existing
    schemas_dir = cur_file_path.parent
    resp = {}
    # AshWorkspaceConfig is the workspace policy file's schema. It is a separate
    # model, not a block of AshConfig, because it lives in a separate file -- see
    # config/ash_workspace_config.py for why policy must not be readable from a
    # project's config.
    for model in [AshConfig, AshAggregatedResults, AshWorkspaceConfig]:
        json_schema_path = schemas_dir.joinpath(f"{model.__name__}.json").resolve()
        if model is AshAggregatedResults:
            schema = model.model_json_schema(schema_generator=StoredResultsJsonSchema)
        else:
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
