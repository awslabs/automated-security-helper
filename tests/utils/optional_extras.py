"""Skip a unit test that needs the ``cdk`` extra, unless the run says the extra must be there.

A plain ``uv sync`` installs no optional extras. A test that needs the ``cdk`` extra skips
without it and names the command that installs it, so the default local run (``uv sync``
then ``uv run pytest``) is green.

A skip that nothing checks protects nothing: CI installed no extras when the cdk-nag tests
were first written, and a breaking cdk-nag major bump landed green. So
``ASH_REQUIRE_CDK_EXTRA`` turns the skip into a failure, the way ``ASH_REQUIRE_SYMBOLS_EXTRA``
does for the ``symbols`` extra in ``tests/unit/utils/test_symbol_suppressions.py``. CI's
unit-test step sets both (``.github/actions/run-unit-tests/action.yml``), and
``tests/unit/test_unit_test_step_gates.py`` fails if it stops setting them.
"""

from __future__ import annotations

import importlib.util
import os
import sys

import pytest

#: The top-level modules the ``cdk`` extra installs, one per distribution in
#: ``[project.optional-dependencies] cdk``: aws-cdk-lib, cdk-nag, constructs.
CDK_EXTRA_MODULES = ("aws_cdk", "cdk_nag", "constructs")

#: Set to 1, yes or true, and a missing ``cdk`` extra fails the test instead of skipping it.
REQUIRE_CDK_EXTRA_ENV = "ASH_REQUIRE_CDK_EXTRA"

_TRUE_VALUES = ("1", "YES", "TRUE")


def _required(variable: str) -> bool:
    return os.environ.get(variable, "").strip().upper() in _TRUE_VALUES


def _installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except ValueError:
        # Already in sys.modules with no __spec__, which find_spec refuses to answer for.
        # Something imported it, so it is there.
        return sys.modules.get(module) is not None


def require_cdk_extra() -> None:
    """Return if the ``cdk`` extra is installed; otherwise skip, or fail under the CI flag.

    Probed with ``find_spec``, which locates a module without running it. Importing
    ``cdk_nag`` starts a jsii kernel and extracts aws-cdk-lib into a shared per-user
    cache, which two xdist workers race on under Windows, and a probe has no reason to
    pay for that.
    """
    missing = [name for name in CDK_EXTRA_MODULES if not _installed(name)]
    if not missing:
        return
    if _required(REQUIRE_CDK_EXTRA_ENV):
        pytest.fail(
            f"{REQUIRE_CDK_EXTRA_ENV} is set but the [cdk] extra is not installed "
            f"(missing: {', '.join(missing)}). This test has to run here, not skip: "
            "install the extra with `uv sync --extra cdk`."
        )
    pytest.skip(
        f"needs the [cdk] extra (missing: {', '.join(missing)}); "
        "install it with `uv sync --extra cdk`"
    )
