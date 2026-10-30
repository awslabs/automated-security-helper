# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, List, Literal

from pydantic.json_schema import GenerateJsonSchema

#: What a results file holds where its stored configuration read a value from
#: the environment: the reference as the configuration file wrote it (``${VAR}``,
#: ``${VAR:default}``, ``!ENV ${VAR}``), never the value
#: (config_validator.record_of_config). A fixed-choice field such as
#: ``global_settings.severity_threshold`` cannot hold one, so the load reads the
#: field with its default and warns (AshAggregatedResults.validate_ash_config,
#: config/recorded_config.py). The pattern is written for every JSON Schema regex
#: engine, not only Python's, so it is not ash_config.ENV_REFERENCE_PATTERN; it
#: also ends at the closing brace, where the load's pattern reads a prefix, so a
#: string that merely starts like a reference is not admitted.
ENV_REFERENCE_JSON_SCHEMA = {
    "type": "string",
    "pattern": r"^(!ENV )?\$\{\w+(:.*)?\}$",
    "description": (
        "An environment reference, kept as the configuration file wrote it. "
        "The field is read with its default."
    ),
}


def _with_env_reference(json_schema: Any) -> Any:
    """``json_schema`` with the environment reference admitted beside it."""
    return {"anyOf": [json_schema, dict(ENV_REFERENCE_JSON_SCHEMA)]}


class ConfigFileJsonSchema(GenerateJsonSchema):
    """The configuration file's schema, which admits what the loader resolves.

    A configuration file may write any scalar as a reference to the environment
    (``${VAR}``, ``${VAR:default}``, a tagged ``!ENV ${VAR}``), and the loader
    resolves it to the variable's value before the field is validated
    (``ash_config.load_yaml_config``; ``config_sources`` for TOML). pydantic's own
    schema lists a fixed-choice field's choices alone, and a boolean or number
    field's type alone, so an editor validating a file against the published
    ``AshConfig.json`` (``config_writer.SCHEMA_COMMENT`` points every saved file
    at it) called invalid a file ASH itself reads and writes. Each such field
    admits the reference (:data:`ENV_REFERENCE_JSON_SCHEMA`) beside its own
    schema. A string field admits it already.

    The workspace policy file resolves no reference (``ash_workspace_config``),
    so its schema is pydantic's own.
    """

    def literal_schema(self, schema: Any) -> Any:
        return _with_env_reference(super().literal_schema(schema))

    def enum_schema(self, schema: Any) -> Any:
        return _with_env_reference(super().enum_schema(schema))

    def bool_schema(self, schema: Any) -> Any:
        return _with_env_reference(super().bool_schema(schema))

    def int_schema(self, schema: Any) -> Any:
        return _with_env_reference(super().int_schema(schema))

    def float_schema(self, schema: Any) -> Any:
        return _with_env_reference(super().float_schema(schema))


#: The package whose models are the stored configuration, with its subpackages.
_CONFIG_PACKAGE = "automated_security_helper.config"


def _stored_config_bases() -> tuple:
    """The base classes of stored-configuration models that live outside the
    config package: plugin sections and their options, and ignore-path entries.
    Imported on use, because the config package imports this module's siblings.
    """
    from automated_security_helper.base.options import PluginOptionsBase
    from automated_security_helper.base.plugin_config import PluginConfigBase
    from automated_security_helper.models.core import IgnorePathWithReason

    return (IgnorePathWithReason, PluginOptionsBase, PluginConfigBase)


def _is_stored_config_model(cls: type) -> bool:
    """Whether ``cls`` is a model of the configuration a results file records."""
    module = cls.__module__
    return (
        module == _CONFIG_PACKAGE
        or module.startswith(_CONFIG_PACKAGE + ".")
        or issubclass(cls, _stored_config_bases())
    )


def _fixed_choice(branch: Any) -> bool:
    """Whether ``branch`` is a fixed-choice schema: an Enum reference or an enum."""
    return isinstance(branch, dict) and ("$ref" in branch or "enum" in branch)


def _with_reference_entries(branch: Any) -> Any:
    """``branch`` of the ``output_formats`` schema with the reference admitted.

    A branch that already reads as a plain string admits a reference as it is.
    """
    if isinstance(branch, dict) and _fixed_choice(branch.get("items")):
        return {
            **branch,
            "items": {"anyOf": [branch["items"], dict(ENV_REFERENCE_JSON_SCHEMA)]},
        }
    if _fixed_choice(branch):
        return {"anyOf": [branch, dict(ENV_REFERENCE_JSON_SCHEMA)]}
    return branch


def _admit_reference_in_output_formats(json_schema: Any) -> None:
    """Admit a reference as an ``output_formats`` entry, beside the format names.

    The entries are an Enum shared with other parts of the results through one
    schema definition, so the definition itself stays as it is and the branch is
    added on this field: on each list entry and on the single-value form. The
    load admits exactly that location (recorded_config._a_choice_refused) and
    reads the whole list as its default. In serialization mode the entries are
    rendered as the strings a dump writes (the Enum is serialized as its value),
    which admit a reference already, so nothing is added there.
    """
    prop = (json_schema.get("properties") or {}).get("output_formats")
    if not isinstance(prop, dict):
        return
    if isinstance(prop.get("anyOf"), list):
        prop["anyOf"] = [_with_reference_entries(b) for b in prop["anyOf"]]
    else:
        admitted = _with_reference_entries(prop)
        if admitted is not prop:
            prop.clear()
            prop.update(admitted)


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
    environment as the reference the file wrote (``${VAR}``). A fixed-choice
    field (a ``Literal``, or an ``output_formats`` entry) cannot hold one, so the
    load drops the field and reads it with its default, with a warning
    (recorded_config.without_unreadable_references). The schema admits the
    reference where the load does, and only there:

    - a ``Literal`` field of a configuration model that HAS a default (a
      required one has nothing to fall back to: the load fails it as missing and
      refuses the file, so the schema refuses the reference too), the entries of
      a list under such a field included;
    - each ``output_formats`` entry, on that field alone, because its Enum is a
      definition shared with other parts of the results;
    - never a true/false or number field, which the load refuses as it refuses
      any other wrong value, and never a fixed-choice field of another model (a
      SARIF level, the CycloneDX ``bomFormat``).

    The schema is generated in serialization mode, because a results file is
    what ``model_dump_json`` writes: it carries every computed field (the
    workspace's ``skipped_projects``, which downstream consumers read) and no
    field a dump excludes. In pydantic's default validation mode a computed
    field is absent from the schema, so a validator given a workspace results
    file refused the key every such file carries.

    In that mode pydantic describes a field that has a serializer by the
    serializer's return annotation. ``ash_config`` is written through a wrap
    serializer annotated ``Any`` (``AshAggregatedResults._record_ash_config``:
    the record of the configuration, the same shape with each environment
    value as its reference), so the stored configuration would be described
    as "anything" and every rule above would describe nothing. A serializer
    with no return type, or ``Any``, therefore falls back to the field's own
    schema (``ser_schema``); a serializer with a real return type keeps it.
    """

    def ser_schema(self, schema: Any) -> Any:
        if schema.get("type") in ("function-plain", "function-wrap"):
            return_schema = schema.get("return_schema")
            if return_schema is None or return_schema.get("type") == "any":
                return None
        return super().ser_schema(schema)

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        #: One entry per model whose schema is being generated, innermost last:
        #: whether it is a model of the stored configuration. A Literal field's
        #: schema is generated inside its model's, so the last entry says whose
        #: field it is.
        self._in_stored_config: List[bool] = []
        #: One entry per model likewise: whether the field being generated has a
        #: default (its core schema is wrapped in a ``default`` schema). Reset on
        #: entering a nested model, whose own fields decide for themselves.
        self._under_default: List[bool] = []

    def model_schema(self, schema: Any) -> Any:
        from automated_security_helper.config.ash_config import AshConfig

        cls = schema.get("cls")
        is_model = isinstance(cls, type)
        self._in_stored_config.append(is_model and _is_stored_config_model(cls))
        self._under_default.append(False)
        try:
            json_schema = super().model_schema(schema)
        finally:
            self._in_stored_config.pop()
            self._under_default.pop()
        if is_model and issubclass(cls, _stored_config_bases()):
            json_schema["additionalProperties"] = True
        if is_model and cls is AshConfig:
            _admit_reference_in_output_formats(json_schema)
        return json_schema

    def default_schema(self, schema: Any) -> Any:
        if not self._under_default:
            return super().default_schema(schema)
        was = self._under_default[-1]
        self._under_default[-1] = True
        try:
            return super().default_schema(schema)
        finally:
            self._under_default[-1] = was

    def literal_schema(self, schema: Any) -> Any:
        json_schema = super().literal_schema(schema)
        if (
            self._in_stored_config
            and self._in_stored_config[-1]
            and self._under_default
            and self._under_default[-1]
        ):
            return {"anyOf": [json_schema, dict(ENV_REFERENCE_JSON_SCHEMA)]}
        return json_schema


def _write_if_changed(path: Path, content: str) -> bool:
    """Write ``content`` to ``path`` unless it is already there; True when written.

    The content goes to a temporary file beside ``path`` and is renamed over it,
    so a reader of the committed schema never sees a truncated or partial file:
    ``write_text`` truncates before it writes, and a run interrupted between the
    two left an empty or half-written schema at the committed path. Unchanged
    content is left alone, so pre-commit does not report an unchanged schema as
    modified.

    ``mkstemp`` creates its file readable by its owner alone, so the temporary
    file takes the mode of the schema it replaces (``0o644`` for a new one);
    without that, the rename would leave the schema unreadable to other users of
    an installed package.
    """
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    handle, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        raise
    return True


#: The ways ``generate_schemas`` can answer; anything else is refused.
OUTPUTS = ("file", "json", "dict")


def generate_schemas(output: Literal["file", "json", "dict"] = "file"):
    """Generate JSON schemas for the models.

    ``output`` is one of :data:`OUTPUTS`. Any other value is a ``ValueError``:
    the file-writing branch used to be the fallback for every unrecognized
    value, so a mistyped mode rewrote the committed schemas in the package
    directory and answered ``None``.
    """
    import json

    if output not in OUTPUTS:
        raise ValueError(f"output must be one of {', '.join(OUTPUTS)}, not {output!r}")

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
            schema = model.model_json_schema(
                schema_generator=StoredResultsJsonSchema, mode="serialization"
            )
        elif model is AshConfig:
            schema = model.model_json_schema(schema_generator=ConfigFileJsonSchema)
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
            _write_if_changed(json_schema_path, new_content)
    return resp


def main():
    generate_schemas("file")


if __name__ == "__main__":
    main()
