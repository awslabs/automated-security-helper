# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two plugin registries ASH ships: membership IS the externality.

ASH ships plugins in exactly two registries. :data:`CORE` holds the plugin
packages every scan loads without naming them. :data:`ALPHA` holds the opt-in
packages ASH ships but does not yet promote as supported; they load only when
``ash_plugin_modules`` (or ``--ash-plugin-modules``) names them, or when they
are installed as their own distributions -- exactly the mechanics of a custom
plugin shipped through the SDK. A plugin's maturity tier is *which member list
carries its package*, nothing else: no plugin record, manifest or facet
declares a tier, and nothing downstream can tell an ALPHA member from a custom
plugin, because the distinguishing fact is never attached to the record.

Why explicit member lists and not a derivation: the same fact used to live in
four places (an AST-derived directory map, the loader's built-in constant, a
hand list in the scanner inventory, and a per-scanner facet field) kept equal
by tests. One declaration deletes the equality tests' reason to exist, makes
promotion a one-line reviewed move between two tuples, and can express what a
directory glob cannot (a package mid-promotion, a shipped package that is
neither core nor alpha).

Importing this module is side-effect-free: the registries are tuples of module
path strings. Nothing here imports a plugin, reads a directory, or registers
anything.

Where the externality may be consulted
--------------------------------------
Only the admitted sites may read one registry's members without the other's
(``tests/unit/test_registry_externality_site_count.py`` is the fail-closed
gate; its allowlist names the admitted files). Everything else iterates the
merged plugin surface and treats every record alike. Code that needs the one
behavioral consequence of membership -- default enablement, and the
"shipped but not loaded" hint -- calls
:mod:`automated_security_helper.plugins.enablement` instead of reading the
member lists itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

_PLUGIN_MODULES_PACKAGE = "automated_security_helper.plugin_modules"


@dataclass(frozen=True)
class Registry:
    """A named, frozen member list of plugin-module paths.

    ``members`` are dotted module paths. Membership covers a module and
    everything beneath it (``ash_builtin.scanners.bandit_scanner`` is within
    the ``ash_builtin`` member).
    """

    name: str
    members: Tuple[str, ...]

    def holds(self, module: str) -> bool:
        """Whether *module* is one of this registry's members or inside one."""
        return any(
            module == member or module.startswith(member + ".")
            for member in self.members
        )


#: The packages every scan loads without naming them (A-1). Promotion to
#: supported is a reviewed one-line move of a package path from
#: :data:`ALPHA`.members into this tuple.
CORE = Registry(
    name="core",
    members=(f"{_PLUGIN_MODULES_PACKAGE}.ash_builtin",),
)

#: The opt-in packages ASH ships but does not yet promote as supported (A-2).
#: They load when named or installed, exactly as a custom SDK plugin does.
ALPHA = Registry(
    name="alpha",
    members=(
        f"{_PLUGIN_MODULES_PACKAGE}.ash_betterleaks_plugins",
        f"{_PLUGIN_MODULES_PACKAGE}.ash_ferret_plugins",
        f"{_PLUGIN_MODULES_PACKAGE}.ash_guarddog_plugins",
        f"{_PLUGIN_MODULES_PACKAGE}.ash_hadolint_plugins",
        f"{_PLUGIN_MODULES_PACKAGE}.ash_snyk_plugins",
        f"{_PLUGIN_MODULES_PACKAGE}.ash_trivy_plugins",
    ),
)

#: Every registry ASH ships, for uniform iteration. Consumers that read this
#: tuple whole (describing every shipped plugin, resolving which registry a
#: module sits in) are not consulting the externality; consulting is reading
#: one member list and not the other.
SHIPPED_REGISTRIES: Tuple[Registry, ...] = (CORE, ALPHA)


def registry_of(module: str) -> Optional[Registry]:
    """The shipped registry whose member list holds *module*, or ``None``.

    ``None`` means the module is not shipped by ASH: a custom plugin named in
    ``ash_plugin_modules`` or installed as its own distribution. Iterates every
    shipped registry uniformly.
    """
    for registry in SHIPPED_REGISTRIES:
        if registry.holds(module):
            return registry
    return None
