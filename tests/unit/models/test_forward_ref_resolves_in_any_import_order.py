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
rebuild ran" -- it is "deserialization works anyway, and still produces an
``AshConfig``".

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

What the subprocess checks, and why each piece is there
------------------------------------------------------
*The premise is enforced, not assumed.* The subprocess is only poisoned because
importing ``run_ash_scan`` does not pull ``config.ash_config`` into
``sys.modules``; its two ``ash_config`` imports are function-local
(``run_ash_scan.py:282`` and ``:729``) and nothing holds them there. Hoist either
one to module scope and the interpreter stops being poisoned, every check below
starts passing on unpatched code, and no signal fires. So the subprocess asserts
the absence itself, and reports it under its own exit code rather than as an
unresolved forward reference.

*The payload carries a value for the field.* ``"{}"`` leaves ``ash_config`` at its
``None`` default: Pydantic does not validate defaults without
``validate_default=True``, so it never reaches the annotation or the field
validator, and a run that deserialized ``"{}"`` proved only that *some* validator
existed. ``'{"ash_config": {}}'`` reaches both, and the test asserts on the
resulting type. That distinction matters because the outcome and the mechanism can
come apart: replacing ``Optional["AshConfig"]`` with ``Optional[Any]`` leaves
``__pydantic_complete__`` True and the payload deserializing, so the annotation is
checked too.

*Asserting the type is not enough on its own.* ``validate_ash_config``
(``asharp_model.py``) swallows every exception and falls back to
``get_default_config()``, which also returns an ``AshConfig`` -- so under an
``Optional[Any]`` annotation the deserialized value is still an ``AshConfig``.
Measured, not assumed. The annotation check is what closes that hole; the type
check is what catches the field or its validator being gutted.

*The output is sentinel-bracketed.* Comparing the whole of stdout couples this
guard to ASH emitting nothing during import, which is not a property anyone
maintains: commit ``9c4f9644`` fixed a leaked stdout log handler that broke a
neighbouring test the same way. A stray line would otherwise fail this test with a
forward-reference message about a logging bug.

Positive control
----------------
Two measurements, because a green test proves the fix works, not that the test
would notice the fix being removed.

* This file alone against unpatched ``origin/main`` (804036ba): the subprocess
  exits non-zero with ``PydanticUserError: 'AshAggregatedResults' is not fully
  defined``.
* This file added to unpatched ``origin/main`` and run inside the **full** suite,
  every one of those prologues present and executing: this test fails, alongside
  one pre-existing unrelated failure in ``test_cdk_nag_container_deps.py``. So it
  fails on broken code with all the masks in place, not just in isolation.

The subprocess costs about 1.5s. That is the price of the property being
checkable at all; it is deliberately not marked ``slow`` and not excluded from
any CI selection, because a guard that CI skips is not a guard.
"""

import subprocess  # nosec B404 — a fresh interpreter is the property under test
import sys
import textwrap

# Exit code for "the premise is gone", kept distinct from the 1 that an
# unresolved forward reference produces so the two are never confused.
_PREMISE_LOST_EXIT = 3

# Imports run_ash_scan FIRST. That is the whole point: it pulls in
# core.unified_metrics, which is what puts asharp_model mid-cycle, and it imports
# ash_config only lazily inside functions, so nothing repairs the model later.
_POISONED_ORDER = (
    textwrap.dedent(
        """
        import sys
        import typing

        import automated_security_helper.interactions.run_ash_scan  # noqa: F401

        # The premise, checked before the model is touched: nothing on this path
        # may have imported ash_config, or the forward reference is already
        # resolved and everything below passes for free.
        if "automated_security_helper.config.ash_config" in sys.modules:
            sys.exit(%d)

        from automated_security_helper.models.asharp_model import AshAggregatedResults

        model = AshAggregatedResults.model_validate_json('{"ash_config": {}}')

        annotation = AshAggregatedResults.model_fields["ash_config"].annotation
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        resolved = getattr(args[0], "__name__", None) if len(args) == 1 else None
        if resolved is None:
            # Whitespace-free so it stays one token in the comparison below.
            resolved = "".join(repr(annotation).split())

        print(
            "ASH_GUARD_BEGIN",
            resolved,
            type(model.ash_config).__name__,
            getattr(AshAggregatedResults, "__pydantic_complete__", "MISSING"),
            "ASH_GUARD_END",
        )
        """
    )
    % _PREMISE_LOST_EXIT
)


def test_deserialization_works_when_run_ash_scan_is_imported_first():
    """A fresh interpreter in the failing import order can still deserialize."""
    proc = subprocess.run(  # nosec B603 - fixed argv, no shell, interpreter is sys.executable
        [sys.executable, "-c", _POISONED_ORDER],
        capture_output=True,
        text=True,
        # The non-zero exit IS the finding here, so it must not raise: the
        # assertions below report it with the subprocess stderr attached.
        check=False,
    )

    # First, because every other check below is meaningless if this one is wrong.
    assert proc.returncode != _PREMISE_LOST_EXIT, (
        "this test no longer tests anything: importing run_ash_scan pulled "
        "automated_security_helper.config.ash_config into sys.modules, which "
        "resolves the AshConfig forward reference for free, so the checks below "
        "would pass on unpatched code. Either move the ash_config import in "
        "run_ash_scan.py back inside the functions that use it, or repoint this "
        "test at a module that still imports ash_config lazily."
    )

    assert proc.returncode == 0, (
        "AshAggregatedResults.model_validate_json failed in a process that "
        "imported run_ash_scan first. The AshConfig forward reference is "
        "unresolved on that path, so the six production deserialization sites "
        f"raise instead of returning a model.\nstderr:\n{proc.stderr}"
    )

    # Sentinel-bracketed, so anything else on stdout is ignored rather than
    # reported as a forward-reference failure.
    payload = proc.stdout.partition("ASH_GUARD_BEGIN")[2].partition("ASH_GUARD_END")[0]
    tokens = payload.split()

    assert len(tokens) == 3, (
        "the subprocess exited 0 without emitting its sentinel-bracketed result, "
        f"so nothing was measured.\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    )
    annotation_name, value_type, complete = tokens

    assert (annotation_name, value_type) == ("AshConfig", "AshConfig"), (
        "ash_config deserialized, but not as an AshConfig. The annotation "
        f"resolved to {annotation_name} and the value came back as {value_type}; "
        "both must be AshConfig. A resolved annotation with the wrong value type "
        "means the field or its validator changed. An unresolved-looking "
        "annotation (Any, or a repr) means the forward reference was replaced, "
        "which passes every other check in this file."
    )

    # Checked AFTER a successful deserialization rather than at import: the fix
    # resolves the reference on first use, so __pydantic_complete__ is
    # legitimately False before then. It reads Pydantic-internal state, so it is
    # the assertion to drop first if a Pydantic upgrade renames it -- the
    # returncode check above is the contract.
    assert complete == "True", (
        f"__pydantic_complete__ read back as {complete!r} after a successful "
        "deserialization. 'MISSING' means Pydantic renamed the attribute: that is "
        "a library change, not a defect in this repository, and this assertion is "
        "the one to drop. Anything else localizes a regression to the rebuild "
        "itself instead of leaving it to surface as a PydanticUserError several "
        "frames into a reporter."
    )
