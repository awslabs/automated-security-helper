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
``resolve_ref`` from the manifest's ``module:Class`` string. That is the same
moment the static imports ran before, so a plugin's registration side effects
happen at the same point; only the statement that names the plugin moved out of
this layer.
"""

from __future__ import annotations

from typing import Annotated, Any, Dict, Literal, Optional, Tuple

from pydantic import Field

from automated_security_helper.base.plugin_manifest import resolve_ref
from automated_security_helper.plugin_manifests import plugin_config_sections


def section_field_name(plugin_name: str) -> str:
    """The Python field name of a plugin's section: its name with ``-`` read as ``_``."""
    return plugin_name.replace("-", "_")


def plugin_section_fields(
    kind: Literal["scanners", "reporters", "converters"],
) -> Dict[str, Tuple[Any, Any]]:
    """Field definitions for ``pydantic.create_model``: one typed section per plugin.

    Each field is ``(Annotated[Config, Field(description=..., alias=...)], Config())``,
    with the alias set to the plugin's name where that differs from the Python
    field name (``cdk-nag`` for ``cdk_nag``), exactly as the sections were written
    when they were declared by hand. Rows come in schema order.
    """
    fields: Dict[str, Tuple[Any, Any]] = {}
    for plugin_name, section in plugin_config_sections(kind):
        config_class = resolve_ref(section.model)
        field_name = section_field_name(plugin_name)
        alias: Optional[str] = plugin_name if plugin_name != field_name else None
        if alias is None:
            info = Field(description=section.description)
        else:
            info = Field(description=section.description, alias=alias)
        fields[field_name] = (Annotated[config_class, info], config_class())
    return fields
