# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The AshConfig forward reference resolves whatever the import order is.

Why this file exists
--------------------
``AshAggregatedResults.ash_config`` is annotated ``Optional["AshConfig"]`` as a
string, and ``AshConfig`` is imported in ``models/asharp_model.py`` only under
``TYPE_CHECKING``. Until a rebuild resolves that reference the model has no
validator at all, so ``model_validate_json`` raises ``PydanticUserError`` rather
than returning a model. Six production call sites deserialize through it:
``cli/merge.py``, ``cli/report.py``, ``core/orchestrator.py``,
``interactions/run_ash_scan.py`` (twice) and ``workspace/reporting.py``.

The rebuild attempted when ``asharp_model`` is imported cannot always run:
importing ``ash_config`` from there is mid-cycle
(``unified_metrics -> asharp_model -> ash_config -> reporters -> unified_metrics``)
and raises ``ImportError``. So the property under test is not "the import-time
rebuild ran" -- it is "deserialization works anyway".

Why a subprocess, and why this test is worthless without one
-----------------------------------------------------------
Forty-seven test modules in this suite carry a module-scope
``AshConfig.model_rebuild()`` / ``AshAggregatedResults.model_rebuild()`` prologue.
Any test that checks this property in-process runs after at least one of them has
already primed the rebuild for the whole interpreter, so it passes whether or not
the production code works. A guard that cannot fail is not a guard, and that is
the exact defect class this test exists to close -- so the check has to happen in
a fresh interpreter whose import order is the failing one.

The subprocess imports neither pytest nor any module under ``tests/``, so nothing
in the test suite can reach it. That is what makes it immune to those forty-seven
prologues rather than merely ordered ahead of them.

**Do not make this in-process to save the spawn.** That is the one change that
silently voids this test: it would keep passing, on broken code, forever.

Positive control
----------------
Two measurements, because a green test proves the fix works, not that the test
would notice the fix being removed.

* This file alone against unpatched ``origin/main`` (804036ba): the subprocess
  exits non-zero with ``PydanticUserError: 'AshAggregatedResults' is not fully
  defined``.
* This file added to unpatched ``origin/main`` and run inside the **full** suite,
  every one of those prologues present and executing: 6695 items collected, 2
  failed -- this test, plus a pre-existing unrelated failure in
  ``test_cdk_nag_container_deps.py``. So it fails on broken code with all the
  masks in place, not just in isolation.

The subprocess costs about 1.5s. That is the price of the property being
checkable at all; it is deliberately not marked ``slow`` and not excluded from
any CI selection, because a guard that CI skips is not a guard.
"""

import subprocess
import sys
import textwrap

# Imports run_ash_scan FIRST. That is the whole point: it pulls in
# core.unified_metrics, which is what puts asharp_model mid-cycle, and it imports
# ash_config only lazily inside functions, so nothing repairs the model later.
_POISONED_ORDER = textwrap.dedent(
    """
    import automated_security_helper.interactions.run_ash_scan  # noqa: F401
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    AshAggregatedResults.model_validate_json("{}")
    print("DESERIALIZED", AshAggregatedResults.__pydantic_complete__)
    """
)


def test_deserialization_works_when_run_ash_scan_is_imported_first():
    """A fresh interpreter in the failing import order can still deserialize."""
    proc = subprocess.run(  # nosec B603 - fixed argv, no shell, interpreter is sys.executable
        [sys.executable, "-c", _POISONED_ORDER],
        capture_output=True,
        text=True,
        # The non-zero exit IS the finding here, so it must not raise: the
        # assertion below reports it with the subprocess stderr attached.
        check=False,
    )

    assert proc.returncode == 0, (
        "AshAggregatedResults.model_validate_json failed in a process that "
        "imported run_ash_scan first. The AshConfig forward reference is "
        "unresolved on that path, so the six production deserialization sites "
        f"raise instead of returning a model.\nstderr:\n{proc.stderr}"
    )

    # Second, cheaper assertion. Deliberately checked AFTER a successful
    # deserialization rather than at import: the fix resolves the reference on
    # first use, so __pydantic_complete__ is legitimately False before then.
    # Asserting it here localizes a regression to the rebuild itself instead of
    # leaving it to surface as a PydanticUserError several frames into a reporter.
    # It reads Pydantic-internal state, so it is the assertion to drop first if a
    # Pydantic upgrade renames it -- the returncode check above is the contract.
    assert proc.stdout.split() == ["DESERIALIZED", "True"], (
        f"unexpected subprocess output: {proc.stdout!r}"
    )
