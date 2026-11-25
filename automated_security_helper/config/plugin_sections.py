# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build the root config model's plugin sections from the plugin manifests.

The root model (``AshConfig``) holds one typed section per shipped plugin:
``scanners.bandit``, ``reporters.sarif``, ``converters.archive``. They used to be
written out field by field, each field typed by a class imported from the plugin
package, which made ``config`` import every plugin. Now each plugin's manifest (or,
for reporters and converters that have none yet, the rows in
``plugin_manifests.option_sections``) names its section's config class and
description as data, and this module turns those rows into pydantic field
definitions. The config layer names no plugin: a plugin joins the root model by
declaring a section, not by an edit here.

The class a section is typed with is imported when the root model is built, by
``resolve_ref`` from the manifest's ``module:Class`` string. The static imports
ran at the top of ``ash_config`` before the model's own imports; the segment
classes are built part-way down the module body instead, so a plugin's
registration side effects now happen after the imports above that point and
before the classes below it. Only the statement that names the plugin moved out of
this layer.
"""

from __future__ import annotations

import keyword
from typing import Annotated, Any, Dict, Literal, Optional, Tuple, cast

from pydantic import ConfigDict, Field

from automated_security_helper.base.plugin_manifest import resolve_ref
from automated_security_helper.config.plugin_section_names import folded_section_name
from automated_security_helper.plugin_manifests import plugin_config_sections


def build_segment(
    name: str,
    base: type,
    extra_type: type,
    kind: Literal["scanners", "reporters", "converters"],
    module: str,
) -> type:
    """The segment class of *kind*: *base* plus one typed section per plugin.

    Built as the class statement it replaces would be: the class's own
    annotations hold the extra-plugin bucket (``__pydantic_extra__``, any section
    the manifests do not name, validated as *extra_type*) beside the sections, and
    its ``model_config`` is the one the hand-written segments had. A walk over a
    model's own annotations (the redaction structural test reads them) therefore
    sees the same types it saw on the written-out class.
    """
    fields = plugin_section_fields(kind)
    shadowed = sorted(field for field in fields if hasattr(base, field))
    if shadowed:
        raise ValueError(
            f"{kind} section field(s) {shadowed} shadow an attribute of "
            f"{base.__name__} (pydantic only warns, and the plugin's section would "
            "replace a method of the model)"
        )
    namespace: Dict[str, Any] = {
        "__module__": module,
        "__qualname__": name,
        "model_config": ConfigDict(
            str_strip_whitespace=True,
            arbitrary_types_allowed=True,
            extra="allow",
        ),
        "__annotations__": {
            # ``cast``: *extra_type* is a value here, which the checker will not
            # take in a subscript of ``Dict``.
            "__pydantic_extra__": cast(Any, Dict)[str, Any | extra_type],
            **{field: annotation for field, (annotation, _) in fields.items()},
        },
        "__pydantic_extra__": {},
        **{field: default for field, (_, default) in fields.items()},
    }
    return type(base)(name, (base,), namespace)


def section_field_name(plugin_name: str) -> str:
    """The Python field name of a plugin's section: its name with ``-`` read as ``_``."""
    return plugin_name.replace("-", "_")


def plugin_section_fields(
    kind: Literal["scanners", "reporters", "converters"],
) -> Dict[str, Tuple[Any, Any]]:
    """The class-body definitions of the segment of *kind*: one typed section per plugin.

    Each entry is ``(Annotated[Config, Field(description=..., alias=...)], Config())``,
    with the alias set to the plugin's name where that differs from the Python
    field name (``cdk-nag`` for ``cdk_nag``), exactly as the sections were written
    when they were declared by hand. Rows come in schema order. ``build_segment``
    turns them into the class namespace.

    The rows are data, so what a reviewer saw in a class body is checked here, when
    the model is built, and a row that would be dropped or reshaped silently is
    refused by name: two plugins whose names give one field name (``cfn-lint`` and
    ``cfn_lint``) or one folded section name (``trivy-repo`` and ``trivyrepo``), a
    name that is not a Python identifier, and one with a leading ``_`` (pydantic
    makes that a private attribute, so the section would be missing from the model).
    A name that shadows an attribute of the segment's base class is refused by
    ``build_segment``, which knows the base.
    """
    fields: Dict[str, Tuple[Any, Any]] = {}
    folded: Dict[str, str] = {}
    for plugin_name, section in plugin_config_sections(kind):
        config_class = resolve_ref(section.model)
        field_name = section_field_name(plugin_name)
        if not field_name.isidentifier() or keyword.iskeyword(field_name):
            raise ValueError(
                f"{kind} plugin {plugin_name!r}: {field_name!r} is not usable as "
                "a config section field name (a Python identifier that is not a "
                "keyword)"
            )
        if field_name.startswith("_"):
            raise ValueError(
                f"{kind} plugin {plugin_name!r}: a section field name may not "
                f"start with '_' ({field_name!r}): pydantic keeps such a name "
                "out of the model's fields"
            )
        if field_name in fields:
            raise ValueError(
                f"{kind} plugins give the section field {field_name!r} twice "
                f"({plugin_name!r} and another plugin of the same field name)"
            )
        key = folded_section_name(plugin_name)
        if key in folded:
            raise ValueError(
                f"{kind} plugins {folded[key]!r} and {plugin_name!r} are one "
                f"section name once spellings are folded ({key!r})"
            )
        folded[key] = plugin_name
        alias: Optional[str] = plugin_name if plugin_name != field_name else None
        if alias is None:
            info = Field(description=section.description)
        else:
            info = Field(description=section.description, alias=alias)
        fields[field_name] = (Annotated[config_class, info], config_class())
    return fields
