# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin manifest: the kernel fields every scanner declares as data.

A manifest is what the rest of ASH needs to know about a plugin BEFORE it runs
any of the plugin's code: its identity, its maturity tier, whether it loads by
default, the aliases it answers to, the classes it provides, the model its
configuration section is validated against, and the paths it owns. The
per-scanner descriptors that need the scanner class
(:class:`~automated_security_helper.base.scanner_facets.ScannerFacets`,
:class:`~automated_security_helper.base.scanner_operational_facets.ScannerOperationalFacets`)
stay on the class; the manifest is the half that must be readable without
importing it.

Why this module imports nothing from ASH beyond ``base.plugin_provisioning`` (itself
standard-library only, and the home of each plugin's provisioning declarations): importing a plugin
package runs its ``@ash_scanner_plugin`` registrations, so answering "which
module provides scanner X" by importing the plugin loads the very scanner the
answer is meant to say is not loaded. A manifest is a frozen pydantic value
built from literals; ``automated_security_helper.plugin_manifests`` holds one
data module per plugin package, and ``tests/unit/plugin_manifests`` proves in a
fresh interpreter that importing every one of them imports no plugin module.
Entry points and the options model are therefore dotted ``module:Class``
STRINGS, resolved by the tests (and by a kernel, later) and never by the
manifest.

Two axes, not one (design decision 5): ``tier`` is maturity (``supported``,
``alpha``, ``deprecated``) and ``default_enabled`` is loading. A maintained
integration that is opt-in is ``supported`` and not default-enabled; calling it
alpha would misstate its maturity to express that it is opt-in.

``deprecated`` is the retirement shape (design decision 7): the manifest names
its target in ``superseded_by``, and the target lists the deprecated name among
its ``aliases``. The manifest only DECLARES the retirement; whether and when a
scanner is actually retired stays a separate decision, so no code here changes
what a name runs.

``schema_version`` is on every manifest from the first one. A manifest written
for a newer schema than this code knows is refused with a sentence saying so
(:func:`parse_scanner_manifest`), never read as far as the fields happen to
match.
"""

from __future__ import annotations

import copy
import importlib
import re
import threading
from enum import Enum
from typing import Any, Literal, Mapping, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from automated_security_helper.base.plugin_provisioning import (
    NO_PROVISIONING,
    Provisioning,
)

#: The manifest schema this code reads and writes.
MANIFEST_SCHEMA_VERSION = 1

#: The release that stops accepting the pre-rename "community" spellings. They are
#: aliases for one release: accepted, mapped to the alpha spelling, and warned about.
COMMUNITY_ALIASES_DROPPED_IN = "3.9.0"

#: The version a manifest declares for a plugin that ships inside the ASH wheel
#: and so is versioned with it.
BUNDLED_VERSION = "bundled"

_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_REF = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*"
)
_MODULE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_VERSION = re.compile(r"\d+(?:\.\d+)*(?:[A-Za-z0-9.+-]*)")

_WARNED_COMMUNITY_ALIASES: set[str] = set()
# Workspace mode builds engines on several threads, so the check-then-add below
# is taken under a lock to keep the warning to once per process.
_WARNED_LOCK = threading.Lock()


def warn_community_alias(old: str, new: str) -> None:
    """Say once per process that the "community" spelling *old* is now *new*."""
    with _WARNED_LOCK:
        if old in _WARNED_COMMUNITY_ALIASES:
            return
        _WARNED_COMMUNITY_ALIASES.add(old)
    # Imported here: the log module is not needed to read a manifest.
    from automated_security_helper.utils.log import ASH_LOGGER

    ASH_LOGGER.warning(
        f"'{old}' is deprecated: the community tier is now called alpha, so use "
        f"'{new}'. The old spelling is accepted until ASH "
        f"{COMMUNITY_ALIASES_DROPPED_IN} and is removed in that release.",
        extra={"markup": False},
    )


class ManifestSchemaError(ValueError):
    """A manifest this code refuses to read, with the reason as prose."""


class PluginTier(str, Enum):
    """The maturity tier, declared in the manifest and nowhere else."""

    #: Maintained and promoted.
    SUPPORTED = "supported"
    #: Shipped, not yet promoted.
    ALPHA = "alpha"
    #: Retiring; ``superseded_by`` names the target.
    DEPRECATED = "deprecated"

    @classmethod
    def _missing_(cls, value: object) -> "PluginTier | None":
        """``"community"``, this tier's spelling before the rename, is an alias
        of ``alpha`` for one release and warns when it is read."""
        if value in ("community", "community_optin"):
            warn_community_alias(str(value), cls.ALPHA.value)
            return cls.ALPHA
        return None


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


def _refuse(self: object, *_args: object, **_kwargs: object) -> Any:
    raise TypeError(
        f"{type(self).__name__} is part of a frozen manifest and cannot be changed"
    )


class _FrozenList(list[Any]):
    """A ``list`` that refuses every in-place change.

    Still a ``list`` by ``isinstance``: it compares equal to a plain one, which is
    what a delivered value is compared with, and ``json`` and pydantic read it as
    one. What reads the exact type does not: ``yaml.safe_dump`` refuses it and a
    ``type(x) is list`` check fails, so a reader that hands the value to such code
    takes :func:`thawed` first. Rebuilt from its items when copied or
    pickled (``__reduce__``), because the default rebuild appends one item at a
    time.
    """

    __slots__ = ()

    append = extend = insert = remove = pop = clear = sort = reverse = _refuse
    __setitem__ = __delitem__ = __iadd__ = __imul__ = _refuse

    def __reduce__(self) -> tuple[type[_FrozenList], tuple[list[Any]]]:
        return (_FrozenList, (list(self),))


class _FrozenDict(dict[Any, Any]):
    """A ``dict`` that refuses every in-place change; see :class:`_FrozenList`."""

    __slots__ = ()

    __setitem__ = __delitem__ = __ior__ = _refuse
    pop = popitem = setdefault = update = clear = _refuse

    def __reduce__(self) -> tuple[type[_FrozenDict], tuple[dict[Any, Any]]]:
        return (_FrozenDict, (dict(self),))


def _freeze(value: Any) -> Any:
    """``value`` with every dict and list in it replaced by a frozen one."""
    if isinstance(value, dict):
        return _FrozenDict({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return _FrozenList(_freeze(v) for v in value)
    return value


def thawed(value: Any) -> Any:
    """``value`` as plain, editable ``dict`` and ``list`` objects, deeply."""
    if isinstance(value, dict):
        return {k: thawed(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [thawed(v) for v in value]
    return value


class EntryPoints(_Frozen):
    """The classes a plugin provides, as dotted ``module:Class`` strings."""

    #: The scanner class, for a scanner manifest.
    scanner: str
    reporters: tuple[str, ...] = ()
    converters: tuple[str, ...] = ()
    runtimes: tuple[str, ...] = ()
    event_handlers: tuple[str, ...] = ()

    @field_validator("scanner")
    @classmethod
    def _scanner_ref(cls, value: str) -> str:
        if not _REF.fullmatch(value):
            raise ValueError(f"{value!r} is not a 'package.module:Class' reference")
        return value

    @field_validator("reporters", "converters", "runtimes", "event_handlers")
    @classmethod
    def _refs(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not _REF.fullmatch(value):
                raise ValueError(f"{value!r} is not a 'package.module:Class' reference")
        return values


def _module_of(ref: str) -> str:
    return ref.split(":", 1)[0]


def _inside(module: str, package: str) -> bool:
    return module == package or module.startswith(package + ".")


def resolve_ref(ref: str) -> Any:
    """The object a ``package.module:name`` reference names, imported now.

    This is the one place a manifest's reference strings become objects. The
    manifest never calls it (reading a manifest imports no plugin); a consumer
    that needs the class or function does, at the moment it needs it, so a
    layer that must not import a plugin names the plugin by data and reaches it
    here instead of by an import statement.

    Raises:
        ValueError: *ref* is not a ``package.module:name`` reference.
        ImportError, AttributeError: the module or the name is not there.
    """
    if not _REF.fullmatch(ref):
        raise ValueError(f"{ref!r} is not a 'package.module:Class' reference")
    module, name = ref.split(":", 1)
    return getattr(importlib.import_module(module), name)


class ConfigSection(_Frozen):
    """How a plugin's section of the ASH config is built and described.

    The root config model has one field per plugin that ships a typed section;
    the field's type and its schema description come from here, so the config
    layer names no plugin.
    """

    #: ``module:Class`` of the section's config class (the plugin's config model
    #: whose ``options`` field is validated against the manifest's options
    #: model).
    model: str
    #: The section's description in the generated JSON schema.
    description: str

    @field_validator("model")
    @classmethod
    def _model_ref(cls, value: str) -> str:
        if not _REF.fullmatch(value):
            raise ValueError(f"{value!r} is not a 'package.module:Class' reference")
        return value


#: The matchers a client-supplied exclusion entry can be read by. The kind says
#: how the option's entries are matched against a finding's file, not which
#: scanner reads them: two scanners that read the same kind of entry share it.
ExclusionKind = Literal[
    "bandit", "checkov", "glob", "guarddog-path", "trivy-ignore-file"
]


class ExclusionOption(_Frozen):
    """One option of a scanner that keeps files or findings away from the scanner.

    A config delivered by an MCP client may set it; the entries are then
    re-applied after the scan as marked suppressions, so the client cannot hide a
    finding the operator's own scan would have reported.
    """

    #: The option's field name under ``scanners.<scanner>.options``.
    option: str
    kind: ExclusionKind
    #: The option's default entries, which are ASH's own.
    default: tuple[str, ...] = ()
    #: One entry is a comma-joined list of patterns for the tool (the tool is
    #: given the option as one value).
    split_commas: bool = False
    #: For a kind that matches the globs the scanner passes its tool: the
    #: ``module:function`` of the builder, ``function(anchor, entry)``, which
    #: returns those globs. Required by (and only for) the ``bandit`` kind.
    glob_builder: Optional[str] = None

    @field_validator("glob_builder")
    @classmethod
    def _builder_ref(cls, value: Optional[str]) -> Optional[str]:
        if value is not None and not _REF.fullmatch(value):
            raise ValueError(f"{value!r} is not a 'package.module:name' reference")
        return value

    @model_validator(mode="after")
    def _builder_matches_kind(self) -> "ExclusionOption":
        if (self.kind == "bandit") != (self.glob_builder is not None):
            raise ValueError(
                "the 'bandit' exclusion kind names the scanner's glob builder "
                "(glob_builder), and only that kind does"
            )
        return self


class ScannerManifest(_Frozen):
    """One scanner plugin's manifest: the fields readable without importing it."""

    #: Pinned to :data:`MANIFEST_SCHEMA_VERSION`; read newer ones through
    #: :func:`parse_scanner_manifest` for the prose refusal.
    schema_version: int
    #: The scanner's selectable name; equals the ``name`` default of its config
    #: class (a test binds the two).
    name: str
    #: A PEP 440-style version, or :data:`BUNDLED_VERSION` for a plugin versioned
    #: with the ASH wheel.
    version: str
    #: Other names this scanner answers to. A name another manifest owns can be
    #: an alias only through the retirement shape (see ``superseded_by``).
    aliases: tuple[str, ...]
    tier: PluginTier
    #: Whether the plugin loads without being listed in ``ash_plugin_modules``.
    default_enabled: bool
    #: The dotted module to list in ``ash_plugin_modules`` to load this plugin.
    plugin_module: str
    #: Required for (and only for) a ``deprecated`` manifest: the name of the
    #: scanner that serves this name now.
    superseded_by: Optional[str] = None
    entry_points: EntryPoints
    #: ``module:Class`` of the pydantic model the scanner's ``options`` are
    #: validated against.
    options_model: str
    #: Repo-relative paths (files or directories) the plugin owns. CI path
    #: filters are generated from these.
    file_ownership: tuple[str, ...]
    #: What the engine provisions for this plugin: the release pin of the tool it
    #: owns, the content databases it reads, the offline-mode environment of its
    #: tool. The engine's ``TOOL_VERSIONS``, ``CONTENT_DATABASES`` and
    #: ``OFFLINE_TOOL_ENVIRONMENT`` are iterated from these blocks, so a plugin that
    #: provisions nothing declares nothing.
    provisioning: Provisioning = NO_PROVISIONING
    #: The plugin's typed section of the ASH config, for a plugin that ships one;
    #: a plugin without it is configured through the root model's free-form
    #: plugin sections, validated against ``options_model`` when it loads.
    config_section: Optional[ConfigSection] = None
    #: The options a client-supplied config may use to exclude files or findings
    #: from this scanner (see :class:`ExclusionOption`).
    exclusion_options: tuple[ExclusionOption, ...] = ()
    #: For a plugin that does not load by default: the default of each option a
    #: client-delivered config may not set, as JSON values. The trusted config has
    #: no section for such a plugin, so a delivered value equal to the default
    #: (which changes nothing) is told from a changed one by this row. A test
    #: binds each row to the options model's own default.
    #: A frozen table either way: pydantic does not validate a default, so the
    #: empty one is built frozen here rather than passed through the validator.
    denied_option_defaults: dict[str, Any] = Field(default_factory=_FrozenDict)

    @field_validator("denied_option_defaults")
    @classmethod
    def _denied_option_defaults_are_the_manifests_own(
        cls, value: dict[str, Any]
    ) -> dict[str, Any]:
        """Deep-copied and frozen, so the values are this manifest's own and fixed.

        Validating a ``dict[str, Any]`` builds a new outer dict and keeps the
        value objects it was given, so a list default here would be the very list
        a module-level constant holds, and an in-place change to either would
        change what "the default" means for the whole process. The copy cuts that
        tie; freezing it keeps the cached manifest's own table and lists from
        being edited either (``dict`` and ``list`` subclasses that raise
        ``TypeError`` on every change and compare equal to the plain ones;
        ``model_dump`` and ``json`` give plain data). A reader that needs to edit,
        or that passes the value to code reading the exact type (``yaml.safe_dump``),
        takes :func:`thawed`.
        """
        return _freeze(copy.deepcopy(value))

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not _NAME.fullmatch(value):
            raise ValueError(
                f"{value!r} is not a scanner name (lower-case, hyphen-separated)"
            )
        return value

    @field_validator("version")
    @classmethod
    def _version(cls, value: str) -> str:
        if value != BUNDLED_VERSION and not _VERSION.fullmatch(value):
            raise ValueError(
                f"{value!r} is neither {BUNDLED_VERSION!r} nor a version number"
            )
        return value

    @field_validator("plugin_module")
    @classmethod
    def _plugin_module(cls, value: str) -> str:
        if not _MODULE.fullmatch(value):
            raise ValueError(f"{value!r} is not a dotted module path")
        return value

    @field_validator("options_model")
    @classmethod
    def _options_model(cls, value: str) -> str:
        if not _REF.fullmatch(value):
            raise ValueError(f"{value!r} is not a 'package.module:Class' reference")
        return value

    @field_validator("file_ownership")
    @classmethod
    def _file_ownership(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError("a plugin owns at least the file its scanner lives in")
        for value in values:
            if (
                not value
                or value.startswith("/")
                or "\\" in value
                or ".." in value.split("/")
            ):
                raise ValueError(
                    f"{value!r} is not a repo-relative posix path without '..'"
                )
        if len(set(values)) != len(values):
            raise ValueError("file_ownership lists a path twice")
        return values

    @model_validator(mode="after")
    def _shape(self) -> "ScannerManifest":
        if self.schema_version != MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version {self.schema_version} is not the version this "
                f"ASH reads ({MANIFEST_SCHEMA_VERSION})"
            )
        for alias in self.aliases:
            if not _NAME.fullmatch(alias):
                raise ValueError(
                    f"alias {alias!r} is not a scanner name (lower-case, "
                    "hyphen-separated)"
                )
        if len(set(self.aliases)) != len(self.aliases):
            raise ValueError("aliases lists a name twice")
        if self.name in self.aliases:
            raise ValueError(f"{self.name!r} is its own alias")
        if (self.tier is PluginTier.DEPRECATED) != (self.superseded_by is not None):
            raise ValueError(
                "a deprecated manifest names the scanner that supersedes it "
                "(superseded_by), and only a deprecated manifest does"
            )
        if self.superseded_by is not None:
            if not _NAME.fullmatch(self.superseded_by):
                raise ValueError(f"superseded_by {self.superseded_by!r} is not a name")
            if self.superseded_by == self.name:
                raise ValueError("a scanner cannot supersede itself")
        for database in self.provisioning.content_databases:
            if database.scanner != self.name:
                raise ValueError(
                    f"content database {database.name!r} is declared by "
                    f"{self.name!r} but names {database.scanner!r} as its scanner"
                )
        refs = [
            ("entry_points.scanner", self.entry_points.scanner),
            ("options_model", self.options_model),
        ]
        if self.config_section is not None:
            refs.append(("config_section.model", self.config_section.model))
        for exclusion in self.exclusion_options:
            if exclusion.glob_builder is not None:
                refs.append(
                    (
                        f"exclusion_options[{exclusion.option}].glob_builder",
                        exclusion.glob_builder,
                    )
                )
        if len({e.option for e in self.exclusion_options}) != len(
            self.exclusion_options
        ):
            raise ValueError("exclusion_options lists an option twice")
        for label, ref in refs:
            if not _inside(_module_of(ref), self.plugin_module):
                raise ValueError(
                    f"{label} {ref!r} lies outside plugin_module {self.plugin_module!r}"
                )
        return self


def parse_scanner_manifest(data: Mapping[str, Any]) -> ScannerManifest:
    """Validate a manifest read from data, refusing a newer schema in prose.

    A manifest whose ``schema_version`` is above what this code reads is not
    validated field by field: its fields may mean something else, so a clean
    parse would be a guess. The refusal says what to do instead.
    """
    declared = data.get("schema_version")
    if isinstance(declared, int) and declared > MANIFEST_SCHEMA_VERSION:
        raise ManifestSchemaError(
            f"the manifest for {data.get('name', 'a plugin')!r} declares "
            f"schema_version {declared}, but this ASH reads schema_version "
            f"{MANIFEST_SCHEMA_VERSION}. It was written for a newer ASH; upgrade "
            "ASH or use a release of the plugin written for this version."
        )
    return ScannerManifest.model_validate(dict(data))
