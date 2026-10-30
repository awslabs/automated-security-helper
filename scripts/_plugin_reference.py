# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the scanner, reporter and converter reference generators share.

Which plugins exist
-------------------
Every package under ``automated_security_helper/plugin_modules/`` declares the
plugins it contributes in ``ASH_SCANNERS``, ``ASH_REPORTERS`` and
``ASH_CONVERTERS``; those lists are what ``plugins/loader.py`` loads. The
``ash_builtin`` package is loaded on every scan. Any other package is loaded only
when the configuration names it in ``ash_plugin_modules``, so the pages say which
package to name. Iterating the packages, rather than listing them here, means a
new plugin package appears on the pages without an edit to this file.

What a plugin is configured with
--------------------------------
Each plugin class declares its config class through its ``config`` field, and
that class declares the plugin's ``name``, whether it is ``enabled`` by default
and the model of its ``options``. These are read from the declared classes, not
from an instance: an instance built without a config falls back to the shared
base config and reports no name (``ArchiveConverter`` does exactly that).

What a plugin does at run time
------------------------------
The command a scanner runs, its tool type and how ASH installs it are set in
``model_post_init``, so they need an instance. Instances are built in a throwaway
directory, the way ``core/scanner_inventory.py`` builds them for ``ash plugin
list``; nothing reads the working tree and no scan runs. A plugin that cannot be
built is still listed, with the instance-only columns marked as not determined.

Built-in and community
----------------------
``ash_builtin`` is the built-in package. A scanner from any other package under
``plugin_modules/`` is a community scanner, which is how
``core/community_scanners.py`` decides which module to suggest for a scanner
that was not loaded. Reporters and converters outside ``ash_builtin`` (the AWS
reporters) are not called community plugins; the pages name their module.

Options tables
--------------
Each options table is preceded by ``<!-- doctest: options of=<section>.<name> -->``
on the line directly above its header row. The docs checks read the marked
tables as the reference for prose tables that restate a plugin's options, so the
marker names exactly which plugin the table belongs to, and the Default column
keeps to the forms listed in ``generate_config_reference.py`` ("Default cells").
"""

from __future__ import annotations

import ast
import importlib
import inspect
import io
import pkgutil
import shlex
import tempfile
import textwrap
import tokenize
import typing
from collections.abc import Mapping
from dataclasses import dataclass, field
from unittest import mock
from pathlib import Path
from typing import Any, Optional

from pydantic import ValidationError

from _reference_docs import NO_DESCRIPTION, code, md_prose, options_marker
from generate_config_reference import (
    ENV_DEFAULT_NOTE,
    constraints_text,
    default_cell,
    env_defaults,
    per_platform_text,
    platform_defaults,
    type_text,
    unknown_keys_text,
)

PLUGIN_ROOT = "automated_security_helper.plugin_modules"
BUILTIN_PACKAGE = f"{PLUGIN_ROOT}.ash_builtin"
REGISTRY_LISTS = {
    "scanner": "ASH_SCANNERS",
    "reporter": "ASH_REPORTERS",
    "converter": "ASH_CONVERTERS",
}
#: The subpackage each plugin group is imported from, under a plugin package
#: (``ash_builtin._PLUGIN_GROUPS`` names the same four; the record of a lost
#: group is keyed by that module's dotted path, and a lost event-handler export
#: by the handlers module's path plus the attribute).
PLUGIN_GROUP_MODULES = {
    "scanner": "scanners",
    "reporter": "reporters",
    "converter": "converters",
    "event_handler": "event_handlers",
}


@dataclass
class Plugin:
    cls: type
    package: str
    kind: str
    config_cls: Optional[type]
    name: str
    #: A bool, or ``[(platform, bool)]`` when the default depends on the platform.
    enabled: Any
    options_cls: Optional[type]
    instance: Any = None
    instance_error: Optional[str] = None
    extras: dict = field(default_factory=dict)

    @property
    def builtin(self) -> bool:
        return self.package == BUILTIN_PACKAGE


def _declared_config(cls: type) -> Optional[type]:
    field_info = getattr(cls, "model_fields", {}).get("config")
    if field_info is None:
        return None
    candidates = [
        a for a in typing.get_args(field_info.annotation) if a is not type(None)
    ]
    candidates = candidates or [field_info.annotation]
    # The concrete config class is the one that declares a name default; the shared
    # base it is unioned with does not.
    for candidate in candidates:
        name_field = (getattr(candidate, "model_fields", None) or {}).get("name")
        if isinstance(getattr(name_field, "default", None), str):
            return candidate
    return None


def _options_model(config_cls: Optional[type]) -> Optional[type]:
    if config_cls is None:
        return None
    options = config_cls.model_fields.get("options")
    if options is None:
        return None
    annotation = options.annotation
    while typing.get_origin(annotation) is typing.Annotated:
        annotation = typing.get_args(annotation)[0]
    return annotation if isinstance(annotation, type) else None


def plugin_packages() -> list[str]:
    """Every package under plugin_modules, built-in first, then by name."""
    root = importlib.import_module(PLUGIN_ROOT)
    names = sorted(
        f"{PLUGIN_ROOT}.{m.name}"
        for m in pkgutil.iter_modules(root.__path__)
        if m.ispkg
    )
    return sorted(names, key=lambda n: (n != BUILTIN_PACKAGE, n))


def _under(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(prefix + ".")


def _refuse_lost_plugin_groups(package: str, module: Any, kind: str) -> None:
    """Raise when a group of ``package``'s plugins the ``kind`` page lists failed
    to import.

    ``ash_builtin`` isolates each plugin group's import and records a failure in
    ``ASH_PLUGIN_LOAD_ERRORS`` instead of raising, so the package imports with a
    shorter list and a page built from it would publish the survivors as the
    whole set, with nothing on it to say so. A group lost only to the order this
    process imported ASH's modules in loads on retry
    (``retry_failed_plugin_groups``, which ``plugins/loader.py`` calls the same
    way before it reads the lists); a group that still fails is the error the
    page would otherwise hide.

    Only a failure that can shorten THIS page's list refuses it. A record keyed
    under another group's module (a lost reporters group while the scanner page
    is built; a renamed event-handler export, keyed under the handlers module)
    cannot change what this page lists and is left to that group's own page or
    to the scan. A record keyed anywhere else is not provably about another
    group, so it refuses the page: a package that records its failures under
    other names is read strictly rather than trusted.
    """
    retry = getattr(module, "retry_failed_plugin_groups", None)
    if callable(retry):
        # For its effect only: the record of what still fails is the module's
        # own attribute, whatever the retry returns.
        retry()
    # An absent record is a clean load; a record of any other type than a mapping
    # is unreadable, an empty list or string included, so the type is checked
    # before anything is read as "nothing failed".
    errors = getattr(module, "ASH_PLUGIN_LOAD_ERRORS", None)
    if errors is None:
        errors = {}
    if not isinstance(errors, Mapping):
        raise ImportError(
            f"{package}.ASH_PLUGIN_LOAD_ERRORS is {type(errors).__name__}, not a "
            f"mapping of failed module to error text, so the page cannot tell "
            f"whether every plugin group loaded"
        )
    other_groups = [
        f"{package}.{group}"
        for page_kind, group in PLUGIN_GROUP_MODULES.items()
        if page_kind != kind
    ]
    relevant = {
        name: error
        for name, error in errors.items()
        if not any(_under(str(name), other) for other in other_groups)
    }
    if relevant:
        failed = "; ".join(
            f"{name}: {error}" for name, error in sorted(relevant.items())
        )
        raise ImportError(
            f"{package} recorded a plugin load failure the {kind} page cannot "
            f"rule out, so a page built from it could list fewer {kind}s than "
            f"ASH ships: {failed}"
        )


def discover(kind: str) -> list[Plugin]:
    """Every plugin of ``kind`` any package declares, in package then name order.

    A package that fails to import is an error, and so is a package that imported
    with the ``kind`` plugin group missing (``_refuse_lost_plugin_groups``):
    listing what survived would publish a smaller set than ASH ships with nothing
    on the page to say so.
    """
    attr = REGISTRY_LISTS[kind]
    plugins: list[Plugin] = []
    seen: set[type] = set()
    for package in plugin_packages():
        module = importlib.import_module(package)
        _refuse_lost_plugin_groups(package, module, kind)
        for cls in getattr(module, attr, None) or []:
            if cls in seen:
                continue
            seen.add(cls)
            config_cls = _declared_config(cls)
            enabled = None
            name = None
            if config_cls is not None:
                try:
                    default = config_cls()
                    enabled = bool(getattr(default, "enabled", True))
                    name = getattr(default, "name", None)
                except Exception:
                    name = config_cls.model_fields["name"].default
                enabled = platform_defaults(config_cls).get("enabled", enabled)
            plugins.append(
                Plugin(
                    cls=cls,
                    package=package,
                    kind=kind,
                    config_cls=config_cls,
                    name=name or cls.__name__,
                    enabled=enabled,
                    options_cls=_options_model(config_cls),
                )
            )
    plugins.sort(key=lambda p: (not p.builtin, p.package, p.name))
    return plugins


def instantiate(plugins: list[Plugin]) -> None:
    """Build each plugin once in a throwaway context; record the instance or why not."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig

    with tempfile.TemporaryDirectory(prefix="ash-plugin-reference-") as tmp:
        source = Path(tmp) / "source"
        output = Path(tmp) / "output"
        source.mkdir()
        output.mkdir()
        context = PluginContext(
            source_dir=source, output_dir=output, config=AshConfig()
        )
        # Built as on Linux, wherever this runs, so a page generated on Windows or
        # macOS matches the committed one. The pages say so where it matters.
        with mock.patch("platform.system", return_value="Linux"):
            for plugin in plugins:
                try:
                    plugin.instance = plugin.cls(context=context)
                except Exception as exc:  # recorded and rendered, not swallowed
                    plugin.instance_error = f"{type(exc).__name__}: {exc}"


def module_name(plugin: Plugin) -> str:
    """The package's own name: ``ash_snyk_plugins`` for ``...plugin_modules.ash_snyk_plugins``."""
    return plugin.package.rsplit(".", 1)[-1]


def _origin(plugin: Plugin) -> str:
    return "community module" if plugin.kind == "scanner" else "plugin module"


def package_short(plugin: Plugin) -> str:
    """Where a plugin comes from, for a table cell."""
    if plugin.builtin:
        return "built in"
    return f"{_origin(plugin)} {code(module_name(plugin))}"


def package_note(plugin: Plugin) -> str:
    """Where a plugin comes from and how to load it."""
    if plugin.builtin:
        return "built in, loaded on every scan"
    if plugin.kind == "scanner":
        # Said of `ash scan` only: in the long-running `ash mcp` process a community
        # scanner one call registered stays registered for the scans after it, as
        # the plugins page explains. The AWS reporters are not affected.
        return (
            f"{_origin(plugin)} {code(module_name(plugin))}, which `ash scan` loads "
            f"when `ash_plugin_modules` names {code(plugin.package)}"
        )
    return (
        f"{_origin(plugin)} {code(module_name(plugin))}, loaded when "
        f"`ash_plugin_modules` names {code(plugin.package)}"
    )


def install_text(instance: Any) -> str:
    """How ASH installs the tool a plugin runs, from what the instance declares."""
    if instance is None:
        return "not determined"
    parts = []
    if getattr(instance, "use_uv_tool", False):
        commands = list(getattr(instance, "uv_tool_install_commands", None) or [])
        specs = [_uv_tool_spec(c) for c in commands]
        parts.append(
            "`uv tool install` on first use"
            + (f" ({', '.join(specs)})" if specs else "")
        )
    table = getattr(instance, "custom_install_commands", None) or {}
    platforms = []
    kinds = []
    for target_platform in sorted(table):
        for arch in sorted(table[target_platform]):
            commands = table[target_platform][arch]
            if not commands:
                continue
            platforms.append(f"{target_platform}/{arch}")
            for command in commands:
                kinds.append(
                    _describe_custom_command(list(getattr(command, "args", []) or []))
                )
    if platforms:
        unique = []
        for k in kinds:
            if k not in unique:
                unique.append(k)
        parts.append(
            f"{'; '.join(unique)} by `ash dependencies install`, for "
            + ", ".join(platforms)
        )
    deps = getattr(instance, "dependencies", None) or {}
    packages = []
    for target_platform in deps:
        for arch in deps[target_platform]:
            for dep in deps[target_platform][arch]:
                label = f"{getattr(dep, 'package_manager', '')}: {getattr(dep, 'name', dep)}"
                if label not in packages:
                    packages.append(label)
    if packages:
        parts.append(
            "declared packages " + ", ".join(code(p) for p in sorted(packages))
        )
    return "; ".join(parts) if parts else "none declared"


#: ``uv tool install`` options that take a value, and the words the page puts
#: before the value.
_UV_VALUE_OPTIONS = {
    "--python": "with Python",
    "-p": "with Python",
    "--with": "plus",
    "--from": "from",
    "--index-url": "from index",
    "--extra-index-url": "also from index",
}


def _uv_tool_spec(command: str) -> str:
    """One ``uv tool install`` command as its package, then what its options say.

    ``uv tool install --python '>=3.10,<3.14' 'example-scanner==2.0.0'`` is
    "`example-scanner==2.0.0` with Python `>=3.10,<3.14`": the command's own quoting and
    options are not part of the package a reader looks for.
    """
    try:
        args = shlex.split(command)
    except ValueError:
        return code(command)
    if args[:3] == ["uv", "tool", "install"]:
        args = args[3:]
    packages: list[str] = []
    notes: list[str] = []
    i = 0
    while i < len(args):
        arg = args[i]
        name, eq, value = arg.partition("=")
        if name in _UV_VALUE_OPTIONS:
            if not eq and i + 1 < len(args):
                i += 1
                value = args[i]
            notes.append(f"{_UV_VALUE_OPTIONS[name]} {code(value)}")
        elif arg.startswith("-"):
            notes.append(code(arg))
        else:
            packages.append(code(arg))
        i += 1
    shown = ", ".join(packages) or "no package"
    return " ".join([shown, *notes])


def _describe_custom_command(args: list[str]) -> str:
    """One install command, without the machine-specific paths it carries."""
    if len(args) >= 3 and args[1] == "-c" and "install_pinned_tool" in args[2]:
        return (
            f"pinned, checksum-verified release of {code(args[3])}"
            if len(args) > 3
            else "pinned release"
        )
    if len(args) >= 3 and args[1] == "-c" and "install_binary_from_url" in args[2]:
        return "checksum-verified download"
    shown = []
    for arg in args:
        if arg.startswith(("--", "/")) or "\\" in arg:
            break
        shown.append(Path(arg).name if not shown else arg)
    return code(" ".join(shown)) if shown else "custom command"


def field_line_comments(model: type) -> dict[str, str]:
    """Field name -> the comment on the line that declares it, for an options model.

    ``output_format: str = "both"  # "json", "markdown", or "both"`` has no
    ``description``, and that comment is the only statement in the code of what the
    field takes. A comment on the field's own line can only be about that field,
    unlike one above it, which may head a group of fields.
    """
    found: dict[str, str] = {}
    for cls in model.__mro__:
        if cls is object or "model_fields" not in dir(cls):
            continue
        try:
            source = textwrap.dedent(inspect.getsource(cls))
            tree = ast.parse(source)
            comments = {
                tok.start[0]: tok.string.lstrip("#").strip()
                for tok in tokenize.generate_tokens(io.StringIO(source).readline)
                if tok.type == tokenize.COMMENT
            }
        except (OSError, TypeError, SyntaxError, tokenize.TokenError):
            continue
        for stmt in getattr(tree.body[0], "body", []):
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                text = comments.get(stmt.end_lineno or stmt.lineno)
                if text and stmt.target.id not in found:
                    found[stmt.target.id] = text
    return found


#: An option name no plugin declares, validated to learn what the model does with one.
_UNDECLARED_OPTION = "__ash_reference_undeclared_option__"


def options_unknown_keys_text(model: type) -> str:
    """What loading does with an option the plugin does not declare.

    Measured rather than read from ``model_config``: an options model can keep
    ``extra="allow"``, so that a results file holding an old key still loads, and
    refuse the key in a validator when a configuration is loaded.
    ``unknown_keys_text`` reads only ``extra``, and would say such a key is kept.
    """
    try:
        model.model_validate({_UNDECLARED_OPTION: None})
    except ValidationError as error:
        if _UNDECLARED_OPTION in str(error):
            return "An option not listed here refuses the configuration."
    return unknown_keys_text(model)


def options_table(plugin: Plugin, config_prefix: str, missing: list[str]) -> list[str]:
    """The table of a plugin's ``options`` keys, or a sentence saying it has none."""
    model = plugin.options_cls
    if model is None:
        return ["This plugin declares no options model.", ""]
    rows = []
    by_platform = platform_defaults(model)
    from_env = env_defaults(model)
    line_comments = field_line_comments(model)
    for name, info in model.model_fields.items():
        key = info.alias or name
        full = f"{config_prefix}.{plugin.name}.options.{key}"
        kind = type_text(info.annotation)
        bounds = constraints_text(info)
        if bounds:
            kind = f"{kind}, {bounds}"
        description = md_prose(info.description) if info.description else NO_DESCRIPTION
        if not info.description:
            missing.append(f"{full}  ({model.__module__}.{model.__name__}.{name})")
            if name in line_comments:
                description += (
                    " The comment on its line in the code: "
                    + md_prose(line_comments[name])
                    + "."
                )
        if name != key:
            description = f"{description} Also accepted as {code(name)}."
        rows.append(
            f'| <a id="{full}"></a>{code(key)} | {kind} | '
            f"{default_cell(info, by_platform.get(name), from_env.get(name))} | "
            f"{description} |"
        )
    if not rows:
        return ["This plugin has no options.", ""]
    return [
        f"Options, under {code(f'{config_prefix}.{plugin.name}.options')}. "
        + options_unknown_keys_text(model),
        "",
        options_marker(f"{config_prefix}.{plugin.name}"),
        "| Option | Type | Default | Description |",
        "|--------|------|---------|-------------|",
        *rows,
        "",
    ]


#: Where a page wants :data:`ENV_DEFAULT_NOTE`; see :func:`place_env_note`.
ENV_NOTE_SLOT = "\0env-default-note\0"


def place_env_note(lines: list[str]) -> list[str]:
    """Put the note explaining "from NAME, else value" at its slot, if the page needs it.

    A page none of whose Default cells is read from a variable gets no note, and
    the blank line after the slot goes with it.
    """
    used = any("| from `" in line for line in lines)
    out: list[str] = []
    drop_blank = False
    for line in lines:
        if line == ENV_NOTE_SLOT:
            if used:
                out.append(ENV_DEFAULT_NOTE)
            else:
                drop_blank = True
            continue
        if drop_blank and line == "":
            drop_blank = False
            continue
        drop_blank = False
        out.append(line)
    return out


def yes_no(value: Any) -> str:
    if value is None:
        return "not determined"
    if isinstance(value, list):
        return per_platform_text(value, lambda v: "yes" if v else "no")
    return "yes" if value else "no"
