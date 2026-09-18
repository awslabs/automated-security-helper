"""A partial cdk install must report MISSING, not a clean SKIPPED.

The availability probe used to read the metadata of one distribution, ``cdk_nag``, and import
nothing. Three distributions are needed before a rule can be evaluated -- ``cdk_nag`` supplies
the packs, ``aws-cdk-lib`` the App/Stack/CfnInclude the wrapper synthesizes, and ``constructs``
the base class -- so an install holding only the first passed the probe.

That state is not hypothetical and not artificial. ``pip install --no-deps cdk-nag`` produces it,
and measured on a host with NodeJS 22 on PATH it read:

    metadata version('cdk_nag')    -> 3.0.2
    metadata version('aws-cdk-lib')-> PackageNotFoundError
    import cdk_nag                 -> ModuleNotFoundError: No module named 'publication'

    _CDK_AVAILABLE                 = True
    validate_plugin_dependencies() = True
    get_installation_commands()    = no pip command at all

Every template then failed inside the wrapper, the per-file skip branch decremented the attempt
count back to zero, and the scan reported SKIPPED with exit code 0 -- which both completeness
gates accept, because SKIPPED is on their allowlist. The documented remediation was dead in the
same state: ``get_installation_commands`` appends its pip command only when ``_CDK_AVAILABLE`` is
False, so ``ash dependencies install`` exited 0 having installed nothing.

Why a metadata probe and not an import probe
--------------------------------------------
Importing ``cdk_nag`` to prove it works would catch strictly more, and was rejected on cost: this
module is imported during plugin discovery on every ASH invocation, ``ash --help`` included, and
importing cdk_nag starts a jsii kernel, which spawns a NodeJS child process. The residual gap --
all three distributions installed but importing them still fails -- is covered loudly rather than
left silent: the wrapper's import guard returns a response carrying ``failure``, the scanner
counts a failed target, and the container reports ERROR. See
``test_cdk_nag_unevaluated_is_not_skipped.py``.
"""

import re
import sys
from pathlib import Path

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    _COMPLETE_SCANNER_STATUSES,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cdk_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
    _CDK_REQUIRED_DISTRIBUTIONS,
    CdkNagScanner,
    CdkNagScannerConfig,
    _missing_cdk_distributions,
)


def _fake_metadata(present):
    """Stand in for ``importlib.metadata.version``, resolving only ``present``."""
    from importlib.metadata import PackageNotFoundError

    def _version(name):
        if name in present:
            return "9.9.9"
        raise PackageNotFoundError(name)

    return _version


@pytest.fixture
def metadata(monkeypatch):
    """Install a fake ``importlib.metadata.version`` for the probe to read.

    The probe imports ``version`` inside the function body, so patching the module attribute
    reaches it. Patching the name bound in ``cdk_nag_scanner`` would not, and a test that
    patched the wrong one would pass while measuring the real environment -- where cdk-nag is
    absent, so every assertion about "missing" would hold for the wrong reason.
    """

    def _install(*present):
        import importlib.metadata

        monkeypatch.setattr(importlib.metadata, "version", _fake_metadata(set(present)))

    return _install


# ---------------------------------------------------------------------------
# The probe itself
# ---------------------------------------------------------------------------


def test_a_partial_install_is_reported_missing(metadata):
    """cdk-nag alone is not enough, and this is the state the one-distribution probe passed."""
    metadata("cdk_nag")

    assert _missing_cdk_distributions() == ["aws-cdk-lib", "constructs"]


def test_a_missing_aws_cdk_lib_alone_is_reported_missing(metadata):
    """The reviewer's exact shape: two of three present."""
    metadata("cdk_nag", "constructs")

    assert _missing_cdk_distributions() == ["aws-cdk-lib"]


def test_a_complete_install_is_reported_available(metadata):
    """The negative control.

    Without it, a probe hardwired to report everything missing would satisfy every test above
    while making cdk-nag permanently MISSING on a correctly installed host.
    """
    metadata(*_CDK_REQUIRED_DISTRIBUTIONS)

    assert _missing_cdk_distributions() == []


def test_an_unreadable_distribution_is_reported_missing(monkeypatch):
    """Any failure to confirm presence must read as absence, not as availability.

    A malformed ``*.dist-info`` on sys.path does not raise PackageNotFoundError, and resolving
    "I could not tell" to "installed" is the same silent pass this probe exists to remove.
    """
    import importlib.metadata

    def _explode(name):
        raise OSError(f"unreadable metadata for {name}")

    monkeypatch.setattr(importlib.metadata, "version", _explode)

    assert _missing_cdk_distributions() == list(_CDK_REQUIRED_DISTRIBUTIONS)


def test_the_probe_covers_every_distribution_the_cdk_extra_installs():
    """Pins the probe against pyproject, so a fourth dependency cannot be added past it.

    The defect was a probe that named a subset of what the extra installs. Asserting the list
    has three entries would not catch a repeat, because the subset would still have three; the
    only assertion that does is one against the extra's own declaration.
    """
    pyproject = Path(__file__).parents[4] / "pyproject.toml"
    if not pyproject.is_file():
        pytest.skip("running against an installed package, not a checkout")

    if sys.version_info >= (3, 11):
        import tomllib

        declared = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        requirements = declared["project"]["optional-dependencies"]["cdk"]
    else:  # pragma: no cover - the project floor is 3.10, tomllib lands in 3.11
        pytest.skip("tomllib is unavailable")

    # Compared with '-' and '_' folded together: pyproject writes "cdk-nag" while the probe
    # reads "cdk_nag", and importlib.metadata treats the two as one name.
    def _normalize(name):
        return re.split(r"[<>=!~;\[ ]", name, maxsplit=1)[0].strip().replace("_", "-")

    assert {_normalize(item) for item in requirements} == {
        _normalize(item) for item in _CDK_REQUIRED_DISTRIBUTIONS
    }, (
        "the availability probe and the cdk extra have diverged; a distribution the extra "
        "installs but the probe does not check is a partial install that reads as available"
    )


# ---------------------------------------------------------------------------
# What the scanner does with the probe's answer
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner(tmp_path):
    """A scanner with a real context.

    ``CdkNagScanner`` cannot be constructed without one: ``PluginContext`` carries the
    forward reference to ``AshConfig`` that pydantic needs resolved.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config

    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    return CdkNagScanner(context=context, config=CdkNagScannerConfig())


def test_validate_plugin_dependencies_refuses_a_partial_install(
    scanner, monkeypatch, caplog
):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", ["aws-cdk-lib"])

    with caplog.at_level("WARNING"):
        assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependencies_satisfied is False
    # ``caplog.messages`` rather than ``caplog.text``. The latter includes each record's
    # source filename, which here is "cdk_nag_scanner.py" -- so a negative assertion about
    # cdk-nag against ``caplog.text`` can never hold and measures the wrong surface.
    warned = " ".join(caplog.messages)
    assert "aws-cdk-lib" in warned
    assert "cdk_nag" not in warned and "cdk-nag" not in warned, (
        "the warning must name what is absent; telling an operator cdk-nag is missing when "
        f"`pip list` shows it reads as an ASH bug and stops them reading further: {warned!r}"
    )


def test_a_partial_install_is_not_a_status_the_gate_accepts(scanner, monkeypatch):
    """The end the whole fix exists for.

    ``ScanPhase`` validates dependencies before dispatching to the executor
    (``scan_phase.py:527-563``) and records MISSING without calling ``scan()``. MISSING is not
    on the completeness allowlist, so the run exits non-zero. Before the fix the same install
    satisfied dependencies, ran, evaluated nothing, and landed on SKIPPED -- which is.
    """
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_MISSING_DISTRIBUTIONS", ["aws-cdk-lib"])

    assert scanner.validate_plugin_dependencies() is False
    assert ScannerStatus.MISSING.value not in _COMPLETE_SCANNER_STATUSES
    assert ScannerStatus.SKIPPED.value in _COMPLETE_SCANNER_STATUSES, (
        "fixture check: SKIPPED really is accepted by the gate, which is why routing this "
        "state away from it is the fix"
    )


def test_the_installer_is_armed_when_a_distribution_is_missing(scanner, monkeypatch):
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", False)

    commands = scanner.get_installation_commands("linux", "x86_64")

    pip_commands = [command for command in commands if "pip" in command]
    assert pip_commands, (
        "ash dependencies install must emit a pip command in this state; gating it on the "
        "same flag the probe got wrong made the documented remediation a no-op"
    )
    installed = " ".join(pip_commands[0])
    for distribution in ("aws-cdk-lib", "cdk-nag", "constructs"):
        assert distribution in installed


def test_the_installer_stays_quiet_on_a_complete_install(scanner, monkeypatch):
    """The negative control for the test above: a good install must not reinstall itself."""
    monkeypatch.setattr(cdk_nag_scanner, "_CDK_AVAILABLE", True)

    commands = scanner.get_installation_commands("linux", "x86_64")

    assert [command for command in commands if "pip" in command] == []
