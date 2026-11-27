"""Plugin config models that each break one rule of the config schema checker.

The classes here stand in for a plugin's config class (C), whose ``options`` field
holds an options class (O). None of them is registered: this module is not a plugin
package, and no ``ASH_SCANNERS`` list names any class in it. The tests load it by
file path, under a name of their own, so that a manifest stand-in can refer to its
classes as ``<that name>:<class>``.

Each broken section is proper in every way but one, so a test can say which rule
the checker reports for it and that it reports no other. ``ProperConfig`` and the
other ``Proper*`` and ``Reserved*`` sections break nothing and must give no problem.

Nothing here calls the checker. Helpers at the end build the stand-ins the manifest
and route rules read: manifests, routes, pins, generated-module text and a published
config schema, as plain namespaces and dicts.
"""

import hashlib
from collections.abc import Callable
from types import SimpleNamespace
from typing import Annotated, Any, Literal

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.utils.redacted_model import RedactedSection

#: The name every section here is configured under.
SECTION_NAME = "fixture-scanner"

#: The version a route's ``module:`` source reads from this module.
FIXTURE_TOOL_VERSION = "1.2.3"

#: The sentence an upstream route expects at the end of the field's description.
OPERATOR_SENTENCE = "Only the operator sets this."

OPTIONS_TEXT = "Options of the fixture scanner."


class _Section(ScannerPluginConfigBase):
    """The base of every broken section: a name and a switch, both described."""

    name: Annotated[
        Literal["fixture-scanner"], Field(description="The name of the section.")
    ] = "fixture-scanner"
    enabled: Annotated[bool, Field(description="Whether the fixture scanner runs.")] = (
        True
    )


# ---------------------------------------------------------------------------
# Proper models: no rule reports anything.
# ---------------------------------------------------------------------------


class ProperNested(BaseModel):
    """A nested model that refuses keys it does not declare."""

    model_config = ConfigDict(extra="forbid")

    depth: Annotated[int, Field(ge=1, description="How deep to look.")] = 1


class ProperOptions(ScannerOptionsBase):
    """Every field typed, described, defaulted and bounded; every key snake_case."""

    mode: Annotated[
        Literal["fast", "full"], Field(description="How much work to do.")
    ] = "fast"
    retries: Annotated[
        int, Field(ge=0, le=5, description="How many times to try again.")
    ] = 1
    ratio: Annotated[float, Field(gt=0, description="A positive ratio.")] = 1.0
    tags: Annotated[list[str], Field(description="Labels to attach.")] = []
    flags: Annotated[dict[str, bool], Field(description="Named switches.")] = {}
    nested: Annotated[
        ProperNested, Field(description="A nested model that is closed.")
    ] = ProperNested()


class ProperConfig(_Section):
    options: Annotated[ProperOptions, Field(description=OPTIONS_TEXT)] = ProperOptions()


class ProperTypedMapOptions(ScannerOptionsBase):
    """A map that types its values, and so takes any key by design."""

    flags: Annotated[dict[str, bool], Field(description="Named switches.")] = {}


class ProperTypedMapConfig(_Section):
    options: Annotated[ProperTypedMapOptions, Field(description=OPTIONS_TEXT)] = (
        ProperTypedMapOptions()
    )


class TypedExtras(RedactedSection):
    """A model that declares a key and types the undeclared ones."""

    model_config = ConfigDict(extra="allow")
    __pydantic_extra__: dict[str, bool]

    base: Annotated[bool, Field(description="A declared switch.")] = True


class ProperTypedExtrasOptions(ScannerOptionsBase):
    packs: Annotated[
        TypedExtras, Field(description="Named packs, each switched on or off.")
    ] = TypedExtras()


class ProperTypedExtrasConfig(_Section):
    options: Annotated[ProperTypedExtrasOptions, Field(description=OPTIONS_TEXT)] = (
        ProperTypedExtrasOptions()
    )


class ReservedNamesOptions(ScannerOptionsBase):
    """Two keys that end in an underscore because the bare name is reserved."""

    schema_: Annotated[
        str, Field(description="A key named like an attribute of pydantic's BaseModel.")
    ] = ""
    class_: Annotated[str, Field(description="A key named like a Python keyword.")] = ""


class ReservedNamesConfig(_Section):
    options: Annotated[ReservedNamesOptions, Field(description=OPTIONS_TEXT)] = (
        ReservedNamesOptions()
    )


class AliasChoicesOptions(ScannerOptionsBase):
    """A tool's own spelling is read, and the published key is the snake_case one."""

    ignore_unfixed: Annotated[
        bool,
        Field(
            validation_alias=AliasChoices("ignore_unfixed", "ignore-unfixed"),
            description="Skip findings that have no fix yet.",
        ),
    ] = False


class AliasChoicesConfig(_Section):
    options: Annotated[AliasChoicesOptions, Field(description=OPTIONS_TEXT)] = (
        AliasChoicesOptions()
    )


# ---------------------------------------------------------------------------
# P2: the schema cannot be generated.
# ---------------------------------------------------------------------------


class CallableOptions(ScannerOptionsBase):
    callback: Annotated[
        Callable[[], None] | None,
        Field(description="A value that has no JSON schema."),
    ] = None


class CallableConfig(_Section):
    options: Annotated[CallableOptions, Field(description=OPTIONS_TEXT)] = (
        CallableOptions()
    )


# ---------------------------------------------------------------------------
# P3: a model takes an undeclared key.
# ---------------------------------------------------------------------------


class OpenNested(RedactedSection):
    """Keeps undeclared keys as extras, and says so in its schema."""

    model_config = ConfigDict(extra="allow")

    a: Annotated[str, Field(description="A declared key.")] = "x"


class OpenNestedOptions(ScannerOptionsBase):
    open_nested: Annotated[
        OpenNested, Field(description="A nested model that keeps undeclared keys.")
    ] = OpenNested()


class OpenNestedConfig(_Section):
    options: Annotated[OpenNestedOptions, Field(description=OPTIONS_TEXT)] = (
        OpenNestedOptions()
    )


class DroppingNested(BaseModel):
    """Drops undeclared keys without a word: its schema says nothing about them."""

    a: Annotated[str, Field(description="A declared key.")] = "x"


class DroppingNestedOptions(ScannerOptionsBase):
    dropping_nested: Annotated[
        DroppingNested, Field(description="A nested model that drops undeclared keys.")
    ] = DroppingNested()


class DroppingNestedConfig(_Section):
    options: Annotated[DroppingNestedOptions, Field(description=OPTIONS_TEXT)] = (
        DroppingNestedOptions()
    )


class WrongTypedMapOptions(ScannerOptionsBase):
    wrong: Annotated[
        dict[str, Any],
        Field(
            description="A map whose schema types its values but whose model does not.",
            json_schema_extra={"additionalProperties": {"type": "boolean"}},
        ),
    ] = {}


class WrongTypedMapConfig(_Section):
    options: Annotated[WrongTypedMapOptions, Field(description=OPTIONS_TEXT)] = (
        WrongTypedMapOptions()
    )


# ---------------------------------------------------------------------------
# P4: a value has no type.
# ---------------------------------------------------------------------------


class AnyFieldOptions(ScannerOptionsBase):
    anything: Annotated[Any, Field(description="A value of any type.")] = None


class AnyFieldConfig(_Section):
    options: Annotated[AnyFieldOptions, Field(description=OPTIONS_TEXT)] = (
        AnyFieldOptions()
    )


class UntypedDictOptions(ScannerOptionsBase):
    bag: Annotated[dict[str, Any], Field(description="A map with untyped values.")] = {}


class UntypedDictConfig(_Section):
    options: Annotated[UntypedDictOptions, Field(description=OPTIONS_TEXT)] = (
        UntypedDictOptions()
    )


class UntypedListOptions(ScannerOptionsBase):
    listing: Annotated[list[Any], Field(description="A list with untyped items.")] = []


class UntypedListConfig(_Section):
    options: Annotated[UntypedListOptions, Field(description=OPTIONS_TEXT)] = (
        UntypedListOptions()
    )


# ---------------------------------------------------------------------------
# P5: a property has no description.
# ---------------------------------------------------------------------------


class UndescribedFieldOptions(ScannerOptionsBase):
    limit: Annotated[int, Field(ge=1)] = 1


class UndescribedFieldConfig(_Section):
    options: Annotated[UndescribedFieldOptions, Field(description=OPTIONS_TEXT)] = (
        UndescribedFieldOptions()
    )


class BareSectionConfig(ScannerPluginConfigBase):
    """Redeclares ``name`` and ``enabled`` with no description, as the scanners do."""

    name: Literal["fixture-scanner"] = "fixture-scanner"
    enabled: bool = True
    options: Annotated[ProperOptions, Field(description=OPTIONS_TEXT)] = ProperOptions()


# ---------------------------------------------------------------------------
# P6: an empty section is not valid, or a default is not.
# ---------------------------------------------------------------------------


class RequiredFieldOptions(ScannerOptionsBase):
    limit: Annotated[int, Field(ge=1, description="A value with no default.")]


class RequiredFieldConfig(_Section):
    """Its options field has no default either, so the section needs it too."""

    options: Annotated[RequiredFieldOptions, Field(description=OPTIONS_TEXT)]


class NeedsKey(BaseModel):
    """A closed nested model with a key that has no default."""

    model_config = ConfigDict(extra="forbid")

    token: Annotated[str, Field(description="A key the model requires.")]


class RequiredNestedOptions(ScannerOptionsBase):
    inner: Annotated[
        NeedsKey | None, Field(description="A nested model with a required key.")
    ] = None


class RequiredNestedConfig(_Section):
    options: Annotated[RequiredNestedOptions, Field(description=OPTIONS_TEXT)] = (
        RequiredNestedOptions()
    )


class BadDefaultOptions(ScannerOptionsBase):
    limit: Annotated[
        int, Field(ge=1, description="A value whose default is below its minimum.")
    ] = 0


class BadDefaultConfig(_Section):
    options: Annotated[BadDefaultOptions, Field(description=OPTIONS_TEXT)] = (
        BadDefaultOptions()
    )


# ---------------------------------------------------------------------------
# P7: a number has no lower bound.
# ---------------------------------------------------------------------------


class UnboundedOptions(ScannerOptionsBase):
    retries: Annotated[int, Field(description="An integer with no lower bound.")] = 1
    ratio: Annotated[float, Field(description="A number with no lower bound.")] = 1.0
    maybe: Annotated[
        int | None, Field(description="An optional integer with no lower bound.")
    ] = None


class UnboundedConfig(_Section):
    options: Annotated[UnboundedOptions, Field(description=OPTIONS_TEXT)] = (
        UnboundedOptions()
    )


# ---------------------------------------------------------------------------
# P8: the published keys do not follow one convention.
# ---------------------------------------------------------------------------


class KebabAliasOptions(ScannerOptionsBase):
    skip_dirs: Annotated[
        list[str],
        Field(
            alias="skip-dirs",
            description="Directories to skip, published in kebab case.",
        ),
    ] = []


class KebabAliasConfig(_Section):
    options: Annotated[KebabAliasOptions, Field(description=OPTIONS_TEXT)] = (
        KebabAliasOptions()
    )


class FoldCollisionOptions(ScannerOptionsBase):
    skip_dirs: Annotated[list[str], Field(description="Directories to skip.")] = []
    skipdirs: Annotated[
        list[str], Field(description="The same key without its underscore.")
    ] = []


class FoldCollisionConfig(_Section):
    options: Annotated[FoldCollisionOptions, Field(description=OPTIONS_TEXT)] = (
        FoldCollisionOptions()
    )


class TrailingUnderscoreOptions(ScannerOptionsBase):
    limit_: Annotated[
        str, Field(description="A key that ends in an underscore without a reason.")
    ] = ""


class TrailingUnderscoreConfig(_Section):
    options: Annotated[TrailingUnderscoreOptions, Field(description=OPTIONS_TEXT)] = (
        TrailingUnderscoreOptions()
    )


class KebabFirstChoiceOptions(ScannerOptionsBase):
    """The first alias choice is the published key, and here it is kebab case."""

    ignore_unfixed: Annotated[
        bool,
        Field(
            validation_alias=AliasChoices("ignore-unfixed", "ignore_unfixed"),
            description="Skip findings that have no fix yet.",
        ),
    ] = False


class KebabFirstChoiceConfig(_Section):
    options: Annotated[KebabFirstChoiceOptions, Field(description=OPTIONS_TEXT)] = (
        KebabFirstChoiceOptions()
    )


class ByNameAliasOptions(ScannerOptionsBase):
    """Publishes an alias, and reads the field by its name."""

    model_config = ConfigDict(validate_by_alias=False, validate_by_name=True)

    skip_dirs_list: Annotated[
        list[str],
        Field(
            alias="skip_dirs",
            serialization_alias="skip_dirs_list",
            description="Directories to skip.",
        ),
    ] = []


class ByNameAliasConfig(_Section):
    options: Annotated[ByNameAliasOptions, Field(description=OPTIONS_TEXT)] = (
        ByNameAliasOptions()
    )


# Root models, for the root check of P8: the keys of the config outside its plugin
# sections.


class ProperRoot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    output_dir: Annotated[str, Field(description="Where results are written.")] = "out"
    max_workers: Annotated[int, Field(ge=1, description="How many to run at once.")] = 1


class KebabRoot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mcp_resource_management: Annotated[
        bool,
        Field(alias="mcp-resource-management", description="A root key in kebab case."),
    ] = False


class KebabSegment(BaseModel):
    """A segment of plugin sections: its keys are plugin names."""

    cfn_lint: Annotated[
        bool, Field(alias="cfn-lint", description="A plugin name in kebab case.")
    ] = True


class SegmentedRoot(BaseModel):
    """Its ``scanners`` segment holds plugin names, which the root check leaves alone."""

    model_config = ConfigDict(extra="forbid")

    output_dir: Annotated[str, Field(description="Where results are written.")] = "out"
    scanners: Annotated[
        KebabSegment, Field(description="Scanner sections by name.")
    ] = KebabSegment()


# ---------------------------------------------------------------------------
# P1: the scanner class and its manifest agree on the config.
# ---------------------------------------------------------------------------


class ProperScanner(ScannerPluginBase[ProperConfig]):
    """Declares its config class, whose options class is its own."""


class UndeclaredScanner(ScannerPluginBase):
    """Declares no config class."""


class GenericOptionsConfig(_Section):
    """Does not redeclare ``options``, so it types them with the generic base."""


class GenericOptionsScanner(ScannerPluginBase[GenericOptionsConfig]):
    """Its config types options with the generic ScannerOptionsBase."""


class NoNameConfig(ScannerPluginConfigBase):
    """Has no ``name`` default, which is the key a scanner is configured under."""

    options: Annotated[ProperOptions, Field(description=OPTIONS_TEXT)] = ProperOptions()


class NoNameScanner(ScannerPluginBase[NoNameConfig]):
    """Its config class has no name default."""


# ---------------------------------------------------------------------------
# P10: route stand-ins.
# ---------------------------------------------------------------------------


class BareOptions(ScannerOptionsBase):
    """Declares nothing of its own: it only redeclares ``offline`` with a description."""

    offline: Annotated[bool, Field(description="Run this scanner offline.")] = False


class OwnFieldOptions(ScannerOptionsBase):
    own_setting: Annotated[
        str, Field(description="A setting of the scanner's own.")
    ] = ""


class GeneratedRoot(BaseModel):
    """The root class of a generated module: it keeps one key of the tool's schema."""

    model_config = ConfigDict(extra="forbid")

    level: Annotated[str | None, Field(description="A key of the tool's own file.")] = (
        None
    )


class EmptyRoot(BaseModel):
    """A root class that kept no key at all."""

    model_config = ConfigDict(extra="forbid")


class UpstreamOptions(ScannerOptionsBase):
    tool_config: Annotated[
        GeneratedRoot | None,
        Field(description=f"The tool's own configuration. {OPERATOR_SENTENCE}"),
    ] = None


class EmptyRootOptions(ScannerOptionsBase):
    tool_config: Annotated[
        EmptyRoot | None,
        Field(description=f"The tool's own configuration. {OPERATOR_SENTENCE}"),
    ] = None


class UnconfinedOptions(ScannerOptionsBase):
    """Its tool_config description does not say that only the operator sets it."""

    tool_config: Annotated[
        GeneratedRoot | None, Field(description="The tool's own configuration.")
    ] = None


GENERATED_BODY = "class GeneratedRoot:\n    pass\n"


def manifest(**overrides: Any) -> SimpleNamespace:
    """A manifest for ``ProperScanner``, read by the attribute names the rules use.

    It names the scanner class and the options class in this module, and has no
    route (``tool_config`` is None) and no provisioned tool pin.
    """
    fields: dict[str, Any] = {
        "name": SECTION_NAME,
        "entry_points": SimpleNamespace(scanner=f"{__name__}:ProperScanner"),
        "options_model": f"{__name__}:ProperOptions",
        "provisioning": SimpleNamespace(tool_pins=()),
        "tool_config": None,
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def route(**overrides: Any) -> SimpleNamespace:
    """A proper ``ash`` route whose version is a constant of this module."""
    fields: dict[str, Any] = {
        "kind": "ash",
        "read_at": "owner/tool@v1.2.3",
        "version": FIXTURE_TOOL_VERSION,
        "version_source": f"module:{__name__}:FIXTURE_TOOL_VERSION",
        "unpinned_reason": "",
        "no_options_reason": "",
        "reason": "The tool publishes no schema for its config file.",
        "pin": "",
        "option": "tool_config",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def upstream_route(**overrides: Any) -> SimpleNamespace:
    """A proper ``upstream`` route: it names ``pin()`` and reads the tool's tag."""
    fields: dict[str, Any] = {"kind": "upstream", "pin": "fixture-pin", "reason": ""}
    fields.update(overrides)
    return route(**fields)


def pin(**overrides: Any) -> SimpleNamespace:
    """A pin of a tool's own schema file, with the fields the route rule reads."""
    fields: dict[str, Any] = {
        "tool": "fixture-tool",
        "repository": "owner/tool",
        "tag": "v1.2.3",
        "commit": "c" * 40,
        "path": "schema/tool.json",
        "sha256": "a" * 64,
        "module": "fixture.generated.tool",
        "root_class": "GeneratedRoot",
    }
    fields.update(overrides)
    return SimpleNamespace(**fields)


def tool_pin(tool: str = "fixture-tool", version: str = "v1.2.3") -> SimpleNamespace:
    """What a scanner's provisioning lists for a tool it installs at a pinned version."""
    return SimpleNamespace(tool=tool, version=version)


def generated_source(
    source_sha: str | None = None,
    *,
    body: str = GENERATED_BODY,
    body_sha: str | None = None,
) -> str:
    """The text of a generated module: a header of ``#`` lines, then the body.

    The header records the pinned file's hash and the hash of the body below it,
    each overridable to build a module that disagrees with its pin or with itself.
    """
    source = pin().sha256 if source_sha is None else source_sha
    digest = (
        hashlib.sha256(body.encode("utf-8")).hexdigest()
        if body_sha is None
        else body_sha
    )
    header = [
        "# generated by datamodel-codegen: tool config model, DO NOT EDIT",
        "# pin: fixture-pin",
        f"# source sha256: {source}",
        "# generator: datamodel-code-generator 0.98.0",
        "# generator python: 3.12",
        "# overlay sha256: none",
        f"# body sha256: {digest}",
        "# regenerate: run the generator for this pin",
    ]
    return "\n".join(header) + "\n" + body


def proper_section() -> dict[str, Any]:
    """The section of the published config schema that ``ProperConfig`` should have."""
    return {
        "$ref": "#/$defs/ProperConfig",
        "description": "Configure the options for the fixture scanner.",
    }


def published_schema(sections: dict[str, Any] | None = None) -> dict[str, Any]:
    """The part of the published config schema that the published rule reads.

    The root refers to the config definition, whose ``scanners`` property refers to
    the segment that holds one section per scanner. ``sections`` are those sections;
    by default the one that ``ProperConfig`` should have.
    """
    held = {SECTION_NAME: proper_section()} if sections is None else sections
    return {
        "$ref": "#/$defs/AshConfig",
        "$defs": {
            "AshConfig": {
                "type": "object",
                "properties": {"scanners": {"$ref": "#/$defs/ScannerConfigSegment"}},
            },
            "ScannerConfigSegment": {"type": "object", "properties": held},
        },
    }
