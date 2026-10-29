# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, List, Literal

from pydantic.json_schema import GenerateJsonSchema

#: What a results file holds where its stored configuration read a value from
#: the environment: the reference as the configuration file wrote it (``${VAR}``,
#: ``${VAR:default}``, ``!ENV ${VAR}``), never the value
#: (config_validator.record_of_config). A fixed-choice field such as
#: ``global_settings.severity_threshold`` cannot hold one, so the load reads the
#: field with its default and warns (AshAggregatedResults.validate_ash_config,
#: config/recorded_config.py). The pattern is written for every JSON Schema regex
#: engine, not only Python's, so it is not ash_config.ENV_REFERENCE_PATTERN.
ENV_REFERENCE_JSON_SCHEMA = {
    "type": "string",
    "pattern": r"^(!ENV )?\$\{\w+:?.*\}",
    "description": (
        "An environment reference, kept as the configuration file wrote it. "
        "The field is read with its default."
    ),
}


def _is_stored_config_model(cls: type) -> bool:
    """Whether ``cls`` is a model of the configuration a results file records."""
    from automated_security_helper.base.options import PluginOptionsBase
    from automated_security_helper.base.plugin_config import PluginConfigBase
    from automated_security_helper.models.core import IgnorePathWithReason

    return cls.__module__.startswith("automated_security_helper.config.") or issubclass(
        cls, (IgnorePathWithReason, PluginOptionsBase, PluginConfigBase)
    )


class StoredResultsJsonSchema(GenerateJsonSchema):
    """The results schema, which accepts what a results load keeps.

    Ignore paths, suppressions, plugin options and plugin sections refuse an
    unknown key in a configuration file, and their schemas say
    ``additionalProperties: false``.
    A results file is loaded tolerantly instead (``utils/unknown_keys.py``): one
    written by another ASH version keeps such a key, with a warning, and the
    entry or option is not applied. The configuration stored in a results file
    is the same model, so without this the results schema would call a file
    invalid that ASH reads. For those models it says ``additionalProperties:
    true``; every other model is unchanged.

    The stored configuration also keeps each value its files read from the
    environment as the reference the file wrote (``${VAR}``), and a
    fixed-choice field (a ``Literal``) cannot hold one, so the load reads it with
    the field's default and warns. For a fixed-choice field of a configuration
    model the schema admits the reference beside the choices
    (:data:`ENV_REFERENCE_JSON_SCHEMA`). A fixed-choice field of any other model
    (a SARIF level, the CycloneDX ``bomFormat``) keeps its choices alone, as the
    load does.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: One entry per model whose schema is being generated, innermost last:
        #: whether it is a model of the stored configuration. A Literal field's
        #: schema is generated inside its model's, so the last entry says whose
        #: field it is.
        self._in_stored_config: List[bool] = []

    def model_schema(self, schema: Any) -> Any:
        from automated_security_helper.base.options import PluginOptionsBase
        from automated_security_helper.base.plugin_config import PluginConfigBase
        from automated_security_helper.models.core import IgnorePathWithReason

        cls = schema.get("cls")
        is_model = isinstance(cls, type)
        self._in_stored_config.append(is_model and _is_stored_config_model(cls))
        try:
            json_schema = super().model_schema(schema)
        finally:
            self._in_stored_config.pop()
        if is_model and issubclass(
            cls, (IgnorePathWithReason, PluginOptionsBase, PluginConfigBase)
        ):
            json_schema["additionalProperties"] = True
        return json_schema

    def literal_schema(self, schema: Any) -> Any:
        json_schema = super().literal_schema(schema)
        if self._in_stored_config and self._in_stored_config[-1]:
            return {"anyOf": [json_schema, dict(ENV_REFERENCE_JSON_SCHEMA)]}
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
