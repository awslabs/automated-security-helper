# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner names ASH recognizes in SARIF result tags, declared once.

Why this module exists
---------------------
Two modules in the runtime path need to answer "is this tag the name of a
scanner?", and both used to answer it from their own longhand copy of the list:
``models/flat_vulnerability.py`` in ``_extract_scanner_name_from_result`` and
``core/scanner_statistics_calculator.py`` in ``_get_scanner_name_from_result``.
Both copies were written before ``opengrep`` shipped and neither was updated, so
an opengrep finding reaching either tag fallback kept the aggregate run name
``AWS Labs - Automated Security Helper`` where a bandit finding resolved to
``bandit``. The two consumers now read one set, so a scanner cannot be recognized
by one surface and unrecognized by the other.

The omission is LATENT, not live -- stated plainly because the opposite is the
easy thing to assume from the diff
--------------------------------------------------------------------------------
Neither tag fallback is currently reachable. ``ScanResultProcessor`` calls
``sarif_utils.attach_scanner_details`` unconditionally for every SARIF container
immediately before merging it into the aggregate report, and that function sets
``scanner_name`` on every result. Its argument is ``ScanResultsContainer.scanner_name``,
whose field default is the string ``"unknown"`` and so is never falsy. The first
arm of the precedence chain therefore always wins and the tag arm is dead code.
Measured: an opengrep result carrying the real attach output resolves to
``opengrep`` with or without this change, and the extra survives a round-trip
through ``ash_aggregated_results.json`` because ``PropertyBag`` is
``extra="allow"``.

So the value here is not a behavior fix. It is that one stale set cannot become
two independently stale sets, and that adding a scanner now fails a test instead
of silently extending the staleness -- which matters on the day something makes
that fallback reachable again, since nothing in the fallback's own vicinity would
announce that it had started running.

A second, independent reason the chain's middle arm is dead, recorded here
because it is adjacent and a future reader will otherwise re-derive it:
``attach_scanner_details`` stores ``scanner_details`` as a plain ``dict``, and
``_extract_scanner_name_from_result`` reads it with
``getattr(details, "tool_name", None)``, which is always None on a dict. It would
need ``.get("tool_name")``. That is left alone deliberately -- fixing it makes a
dead branch live, which is a behavior change with its own blast radius and does
not belong in a deduplication.

What the names are, and why this spelling
-----------------------------------------
These are scanner **config names** -- ``str(self.config.name)`` -- because that
is the exact string ``sarif_utils.attach_scanner_details`` appends to a result's
tags. So the spelling is hyphenated (``cfn-nag``, ``detect-secrets``,
``npm-audit``), not the class name and not the snake_case form
``core/scanner_inventory.py`` reports for its own table. Matching against a
snake_cased set would recognize none of the three hyphenated names.

The set covers every scanner ASH ships, which is the ten in
``plugin_modules/ash_builtin/scanners`` plus the three vendored packages
(``ferret-scan``, ``snyk-code``, ``trivy-repo``) that ``load_internal_plugins()``
does not load. The vendored three are included because a vendored scanner's
result hits the same fallback as a builtin one, and because a gate that passed
only by hand-excluding three shipped scanners would be a weaker gate.

Why this is declared rather than derived from the plugin registry
----------------------------------------------------------------
Deriving it here is the obvious improvement and it is not available: importing
the scanner registry from a module the models package reaches creates a real
circular import, measured rather than assumed. A module-scope
``import automated_security_helper.plugin_modules.ash_builtin.scanners`` inside
``models/flat_vulnerability.py`` fails with::

    flat_vulnerability -> ash_builtin.scanners -> bandit_scanner
      -> utils.sarif_utils -> utils.suppression_matcher
        -> models.flat_vulnerability   (partially initialized)
    ImportError: cannot import name 'FlatVulnerability' from partially
    initialized module 'automated_security_helper.models.flat_vulnerability'

and it fails from both entry directions, so no import ordering avoids it.
``plugins.loader`` and ``core.scanner_inventory`` do import cleanly at module
scope, but neither yields config names without loading the scanner classes,
which is what closes the loop.

Two further options were rejected. A function-level deferred import would work,
but it turns a frozenset constant into a call that loads every scanner plugin on
the first finding flattened, inside a hot path that runs once per result.
Instantiating scanners to read their configs is worse still: ``describe_scanner``
shells out to probe tool versions, with a ten-second budget per scanner.

So the set is declared here and a test derives the same set from the registry and
asserts they match -- ``tests/unit/utils/test_scanner_names_registry_agreement.py``.
The test may import the registry freely because a test module is not in the
cycle. That moves the derivation to the only place that can afford it.

Failure mode this leaves open
-----------------------------
Adding a scanner and not adding its name here is caught by that test, which is
the direction that matters: the peripheral scanner lists in CI
(``.github/actions/validate-container``, ``.github/actions/validate-nix``,
``scripts/verify_workspace_policy.py``) all check ``KNOWN - observed``, so every
one of them passes when a scanner is added, which is exactly when a hardcoded set
goes stale. The test here asserts set equality, so it fails in both directions.

What it does not catch: a scanner whose config name changes without the class
being added or removed is caught (the derived name changes), but a scanner that
is never registered through ``load_internal_plugins()`` or the vendored list --
a third-party plugin installed at runtime -- is invisible to both the set and the
test. Such a scanner's findings keep the aggregate name in the tag fallback. That
is a real limit, and closing it needs the fallback to consult the live registry
rather than a static set, which is the cycle above.

This module imports nothing from ASH on purpose, mirroring
``utils/severity_ladder.py``: a leaf with no ASH imports cannot participate in
the cycle it exists to route around.
"""

from __future__ import annotations

from typing import FrozenSet

#: Scanner config names for every scanner ASH ships, as they appear in SARIF
#: result tags. Kept sorted so a diff adding one is a single line.
#:
#: Derived-and-compared by tests/unit/utils/test_scanner_names_registry_agreement.py.
#: Add a scanner to the registry without adding it here and that test fails.
SCANNER_TAG_NAMES: FrozenSet[str] = frozenset(
    {
        "bandit",
        "cdk-nag",
        "cfn-guard",
        "cfn-lint",
        "cfn-nag",
        "checkov",
        "detect-secrets",
        "ferret-scan",
        "grype",
        "npm-audit",
        "opengrep",
        "semgrep",
        "snyk-code",
        "syft",
        "trivy-repo",
    }
)
