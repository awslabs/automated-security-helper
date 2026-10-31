# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import contextlib
import copy
import os
import stat
import uuid
from pathlib import Path
from typing import Any, List, Literal

from pydantic.json_schema import GenerateJsonSchema, JsonRef

#: An environment reference as a configuration file writes it: ``${VAR}``,
#: ``${VAR:default}``, ``!ENV ${VAR}``. Written for every JSON Schema regex
#: engine, not only Python's, so it is not ash_config.ENV_REFERENCE_PATTERN; it
#: also ends at the closing brace, where the load's pattern reads a prefix, so a
#: string that merely starts like a reference is not admitted.
ENV_REFERENCE_JSON_PATTERN = r"^(!ENV )?\$\{\w+(:.*)?\}$"


#: What a results file holds where its stored configuration read a value from
#: the environment: the reference as the configuration file wrote it, never the
#: value (config_validator.record_of_config). A fixed-choice or a number field
#: such as ``global_settings.severity_threshold`` cannot hold one, so the load
#: reads the field with its default and warns (AshAggregatedResults
#: .validate_ash_config, config/recorded_config.py).
def _reference_schema(description: str) -> dict[str, Any]:
    """The schema of an environment reference, described as ``description``
    says. Both reference schemas are built here so their type and pattern
    cannot drift apart; only the description differs."""
    return {
        "type": "string",
        "pattern": ENV_REFERENCE_JSON_PATTERN,
        "description": description,
    }


ENV_REFERENCE_JSON_SCHEMA = _reference_schema(
    "An environment reference, kept as the configuration file wrote it: the "
    "variable's value is never recorded. The field is read with its default, "
    "the model's own and not the one written inside the reference (the 600 "
    "of ${VAR:600}); a reference inside a list takes the whole list out, so "
    "the list is read with its default too. The load warns and lists the "
    "field as unreadable. ash merge and ash report refuse unless the "
    "operator supplies the field, and a command that runs a scan takes the "
    "operator's own value. A true/false field holds no reference at all."
)

#: The same reference in a configuration file, where the loader resolves it to
#: the variable's value before the field is validated (ash_config
#: .load_yaml_config; config_sources for TOML): the value, not a default, is
#: what the field reads.
CONFIG_FILE_REFERENCE_JSON_SCHEMA = _reference_schema(
    "An environment reference, resolved to the variable's value when the "
    "file is loaded."
)


def _with_env_reference(json_schema: Any) -> Any:
    """``json_schema`` with the configuration file's environment reference
    admitted beside it."""
    return {"anyOf": [json_schema, dict(CONFIG_FILE_REFERENCE_JSON_SCHEMA)]}


def _keep_property_names(
    generator: GenerateJsonSchema, schema: Any, json_schema: Any
) -> Any:
    """``json_schema`` of a dict, with its key constraint kept when it is wrapped.

    pydantic describes a dict's keys with ``propertyNames`` only when the key
    schema is a plain string with constraints or a reference to a definition.
    Once a generator wraps a fixed-choice or constrained key beside the
    environment reference (``{"anyOf": [...]}``), the key schema is neither,
    and pydantic drops it: a dict keyed by platform (opengrep's ``sha256``) then
    accepts any key in an editor. The wrapped schema is the same hint with the
    reference admitted, so it goes under ``propertyNames`` as it stands.
    """
    keys = schema.get("keys_schema")
    if keys is None or "propertyNames" in json_schema:
        return json_schema
    keys_json = dict(generator.generate_inner(keys))
    if "anyOf" in keys_json:
        keys_json.pop("title", None)
        json_schema["propertyNames"] = keys_json
    return json_schema


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
    admits the reference (:data:`CONFIG_FILE_REFERENCE_JSON_SCHEMA`, whose
    description says the loader resolves it; the results schema's
    :data:`ENV_REFERENCE_JSON_SCHEMA` says the field is read with its default)
    beside its own schema. A free string field admits it already; a string field with a
    constraint (a pattern, a length) does not, because the reference is not the
    value the constraint describes, so it admits the reference beside the
    constrained string. A ``Decimal`` field is described as a number or a numeric
    string, so it takes the reference beside that.

    The workspace policy file resolves no reference (``ash_workspace_config``),
    so its schema is pydantic's own.
    """

    def str_schema(self, schema: Any) -> Any:
        json_schema = super().str_schema(schema)
        if any(key in schema for key in ("pattern", "min_length", "max_length")):
            return _with_env_reference(json_schema)
        return json_schema

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

    def decimal_schema(self, schema: Any) -> Any:
        return _with_env_reference(super().decimal_schema(schema))

    def dict_schema(self, schema: Any) -> Any:
        return _keep_property_names(self, schema, super().dict_schema(schema))


#: The package whose models are the stored configuration, with its subpackages.
_CONFIG_PACKAGE = "automated_security_helper.config"


def _stored_config_bases() -> tuple[type, ...]:
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


#: The serializers of the results model that are declared ``-> Any`` because
#: their output has the shape of the field they serialize: the record of the
#: configuration and of the metadata with each environment value as its
#: reference, and the used suppressions in a stable order. In serialization
#: mode pydantic would describe each of these fields as "anything"; the
#: generator describes them by the field's own schema instead. A serializer
#: added to this model that reshapes its field must NOT be listed here, and one
#: that keeps the shape must be, or the field reads as "anything"
#: (tests/unit/schemas/test_generate_schemas_stored_config_references.py keeps
#: the list and the model in step).
SHAPE_KEEPING_SERIALIZERS = frozenset(
    {
        "AshAggregatedResults._record_ash_config",
        "AshAggregatedResults._record_metadata",
        "AshAggregatedResults._used_suppressions_in_order",
        # Typed ``List[str]``: the names of the ExportFormat members, which are
        # the members' JSON form, so the field's own schema (the enum, with the
        # reference admitted beside each entry) is the dump's shape; the return
        # type alone described every string as a valid format.
        "AshConfig._output_format_values",
    }
)


#: The core schema kinds that wrap another schema without changing what the
#: value is: a validator around it, or a default for it.
_WRAPPING_CORE_TYPES = frozenset(
    {"function-before", "function-after", "function-wrap", "default", "nullable"}
)


def _is_enum_core(core_schema: Any, definitions: Any = None) -> bool:
    """Whether ``core_schema`` is an ``Enum``, under any validator or default.

    An Enum used as a field's type is a shared definition, so at the field its
    core schema is a ``definition-ref`` to the enum, not the ``enum`` schema
    itself. ``definitions`` maps each core definition's ``ref`` to the
    definition (``StoredResultsJsonSchema.definitions_schema`` collects them
    from the core schema before any definition is generated), and the
    reference is followed through it. That reads the core schema alone, so the
    answer does not depend on the order pydantic generates the definitions in.
    """
    followed: set[str] = set()
    while isinstance(core_schema, dict):
        kind = core_schema.get("type")
        if kind == "enum":
            return True
        if kind == "definition-ref" and definitions:
            ref = core_schema.get("schema_ref")
            if not isinstance(ref, str) or ref in followed or ref not in definitions:
                return False
            followed.add(ref)
            core_schema = definitions[ref]
            continue
        if kind not in _WRAPPING_CORE_TYPES:
            return False
        core_schema = core_schema.get("schema")
    return False


def _serializer_name(schema: Any) -> str:
    """The qualified name of a function serializer's function, or ``""``."""
    function = schema.get("function")
    if isinstance(function, dict):
        function = function.get("function")
    return getattr(function, "__qualname__", "")


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
    field (a ``Literal``) or a number field cannot hold one, so the load drops
    the field and reads it with its default, with a warning
    (recorded_config.without_unreadable_references, _a_choice_refused). The
    schema admits the reference where the load does, and only there:

    - a ``Literal``, ``int`` or ``float`` field of a configuration model that
      HAS a default (a required one has nothing to fall back to: the load fails
      it as missing and refuses the file, so the schema refuses the reference
      too), the entries of a list under such a field included;
    - never a true/false field: the record never writes a reference there
      (config_validator.typed_from is never true for a bool, so the typed
      value is recorded) and the load refuses one as any other wrong value;
      never a fixed-choice field of another model (a SARIF level, the CycloneDX
      ``bomFormat``);
    - an ``Enum`` field likewise, and each entry of a list of ``Enum`` values
      (``output_formats``; the load drops the whole list for one reference
      entry, recorded_config._a_choice_refused). An Enum is a shared
      definition, so the reference goes beside the field's use of it
      (``default_schema``, ``list_schema``), never into the definition.
      ``output_formats`` is dumped through a serializer typed ``List[str]``,
      which would describe every string as a valid format where the load
      refuses a name that is not one; it is listed in
      :data:`SHAPE_KEEPING_SERIALIZERS` so the enum is what the schema says.

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
    as "anything" and every rule above would describe nothing. The serializers
    named in :data:`SHAPE_KEEPING_SERIALIZERS` therefore fall back to the
    field's own schema (``ser_schema``); every other serializer is described as
    pydantic describes it, so a reshaping serializer added later is never
    described by a schema its output does not match.

    Serialization mode also marks every computed field ``required``. A results
    file from a version that did not compute the field yet (a workspace block
    without ``skipped_projects``) is still a file this version loads, so a
    computed field is described and never required (``model_fields_schema``).

    A field a dump excludes (``Field(exclude=True)``) is left out, as pydantic
    leaves it out: no released results file carries one. Of the product's four
    excluded fields, ``AshConfig.extends`` and ``patch`` were excluded in the
    commit that added them, and the orchestrator's ``config_base_gate`` is not
    in the results tree; ``WorkspaceProjectResult.scanner_reasons`` was added
    unexcluded and excluded by the next day's commit, both on the unreleased
    main line, so a results file from a checkout of that one day can carry it,
    under a model whose ``extra="allow"`` keeps it and whose schema admits it
    (``additionalProperties: true``). Describing every excluded field would
    otherwise publish runtime-only fields as part of the results-file contract
    and generate the schema of a field pydantic cannot describe (a callable),
    which fails the whole generation. A version that starts writing an
    excluded field under a model that refuses unknown keys lists it here
    deliberately, with the model and the version that wrote it.

    A model that loads a field by its Python name as well as by its alias
    (``validate_by_name``: the CycloneDX models, whose ``bom-ref`` and
    ``mime-type`` a results file written before their dumps used aliases holds
    as ``bom_ref`` and ``mime_type``) is described with both names
    (``model_schema``): the alias as the dump writes it, and the Python name
    beside it with the same schema, so a file the load accepts is not refused
    by the model's ``additionalProperties: false``. A required aliased field is
    required under either name.
    """

    def model_fields_schema(self, schema: Any) -> Any:
        json_schema = super().model_fields_schema(schema)
        computed = {
            field.get("alias", field["property_name"])
            if self.by_alias
            else field["property_name"]
            for field in schema.get("computed_fields", [])
        }
        required = [
            name for name in json_schema.get("required", []) if name not in computed
        ]
        if required:
            json_schema["required"] = required
        else:
            json_schema.pop("required", None)
        return json_schema

    def ser_schema(self, schema: Any) -> Any:
        if (
            schema.get("type") in ("function-plain", "function-wrap")
            and _serializer_name(schema) in SHAPE_KEEPING_SERIALIZERS
        ):
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
        #: The core schema's shared definitions by ref, filled by
        #: :meth:`definitions_schema` before any of them is generated.
        self._core_definitions: dict[str, Any] = {}

    def definitions_schema(self, schema: Any) -> Any:
        # pydantic generates the shared definitions one after another in the
        # order it met them, and a model's fields are generated with the model,
        # so an Enum definition may not exist yet when a field that uses it is
        # reached. Recording the core definitions first lets that field be
        # recognized as an Enum whatever the order.
        for definition in schema.get("definitions", []):
            ref = definition.get("ref")
            if ref is not None:
                self._core_definitions[ref] = definition
        return super().definitions_schema(schema)

    def model_schema(self, schema: Any) -> Any:
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
        if is_model and self.by_alias and cls.model_config.get("validate_by_name"):
            self._describe_python_names(cls, json_schema)
        return json_schema

    @staticmethod
    def _describe_python_names(cls: Any, json_schema: Any) -> None:
        """Describe each aliased field of ``cls`` under its Python name too.

        The load reads either name (``validate_by_name``), so the schema admits
        either: the Python name gets a copy of the alias's schema, and a field
        the alias makes required is required under one name or the other
        instead of under the alias alone.
        """
        properties = json_schema.get("properties")
        if not isinstance(properties, dict):
            return
        required = list(json_schema.get("required", []))
        either_name = []
        for name, info in cls.model_fields.items():
            alias = info.serialization_alias or info.alias
            if not alias or alias == name or alias not in properties:
                continue
            properties.setdefault(name, copy.deepcopy(properties[alias]))
            if alias in required:
                required.remove(alias)
                either_name.append(
                    {"anyOf": [{"required": [alias]}, {"required": [name]}]}
                )
        if either_name:
            if required:
                json_schema["required"] = required
            else:
                json_schema.pop("required", None)
            json_schema.setdefault("allOf", []).extend(either_name)

    def _admits_reference(self) -> bool:
        """Whether the field being generated is a defaulted field of a stored
        configuration model: where the load reads a refused reference as the
        default."""
        return bool(
            self._in_stored_config
            and self._in_stored_config[-1]
            and self._under_default
            and self._under_default[-1]
        )

    def _beside_reference(self, json_schema: Any) -> Any:
        if self._admits_reference():
            return {"anyOf": [json_schema, dict(ENV_REFERENCE_JSON_SCHEMA)]}
        return json_schema

    def _resolves_to_enum(self, json_schema: Any) -> bool:
        """Whether the JSON schema already generated for a value is an Enum's.

        The second check after ``_is_enum_core``, which follows a reference
        through the core definitions and is the order-independent one: this one
        follows the generated ``$ref`` and can only answer for a definition
        that was generated already, so it is not relied on alone."""
        for _ in range(8):
            if not isinstance(json_schema, dict):
                return False
            ref = json_schema.get("$ref")
            if ref is None:
                return "enum" in json_schema
            try:
                resolved = self.get_schema_from_definitions(JsonRef(ref))
            except KeyError:
                return False
            if resolved is None:
                return False
            json_schema = resolved
        return False

    def int_schema(self, schema: Any) -> Any:
        return self._beside_reference(super().int_schema(schema))

    def float_schema(self, schema: Any) -> Any:
        return self._beside_reference(super().float_schema(schema))

    def default_schema(self, schema: Any) -> Any:
        if not self._under_default:
            return super().default_schema(schema)
        was = self._under_default[-1]
        self._under_default[-1] = True
        try:
            json_schema = super().default_schema(schema)
            # The value's own schema, without the default pydantic put beside
            # it; the reference is admitted beside the value, and the default
            # stays at the field.
            value_schema = {
                key: value for key, value in json_schema.items() if key != "default"
            }
            if _is_enum_core(
                schema.get("schema"), self._core_definitions
            ) or self._resolves_to_enum(value_schema):
                with_reference = self._beside_reference(value_schema)
                if "default" in json_schema:
                    with_reference = {
                        **with_reference,
                        "default": json_schema["default"],
                    }
                json_schema = with_reference
        finally:
            self._under_default[-1] = was
        return json_schema

    def list_schema(self, schema: Any) -> Any:
        json_schema = super().list_schema(schema)
        if _is_enum_core(
            schema.get("items_schema"), self._core_definitions
        ) or self._resolves_to_enum(json_schema.get("items")):
            json_schema["items"] = self._beside_reference(json_schema["items"])
        return json_schema

    def literal_schema(self, schema: Any) -> Any:
        return self._beside_reference(super().literal_schema(schema))

    def dict_schema(self, schema: Any) -> Any:
        return _keep_property_names(self, schema, super().dict_schema(schema))


def _write_if_changed(path: Path, content: str) -> bool:
    """Write ``content`` to ``path`` unless it is already there; True when written.

    The content goes to a temporary file beside ``path`` and is renamed over it,
    so a reader of the committed schema never sees a truncated or partial file:
    ``write_text`` truncates before it writes, and a run interrupted between the
    two left an empty or half-written schema at the committed path. Unchanged
    content is left alone, so pre-commit does not report an unchanged schema as
    modified.

    The mode of the written file is what ``write_text`` gave it. A schema that
    exists keeps its own mode: the temporary file takes it before the rename.
    A new schema gets ``0o666`` less the process's umask, because the temporary
    file is created with ``os.open`` and that mode. (``tempfile.mkstemp`` would
    make it readable by its owner alone, and the rename would carry that over a
    schema other users of an installed package read.)
    """
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return False
    existing_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
        if existing_mode is not None:
            os.chmod(temporary, existing_mode)
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
