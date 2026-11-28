"""The version a scanner records is the version of the binary that runs.

``tool_version`` is what the SARIF step records as ``scanner_version``. A scanner
that verified a copy on PATH records that copy's version and drops the uv version
probe, since uv's environment is not what runs. Two later decisions put the uv
route back without undoing that record: a validation that finds the copy gone, and
a per-target config swap that resets the validation. The uv route then ran with
the copy's version still recorded and no probe owed, so the SARIF step named a
binary that did not run.

The other direction is the PATH fallbacks: a copy that answered no version kept the
version an earlier uv probe wrote, the checkov and cfn-lint resolver arms and
guarddog's last fallback never touched the record at all, and guarddog's uv-absent
arm kept the version the uv probe recorded and read the version of whatever copy the
PATH lookup found only when none was recorded.

Every test states the route the scan takes and asserts the record that route owes:
the copy's own version (or nothing when it answered none) on a direct route, and the
uv probe owed again on the uv route.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    bandit_scanner,
    cfn_lint_scanner,
    checkov_scanner,
    zizmor_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    CfnLintScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScanner,
    ZizmorScannerConfig,
    ZizmorScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
    guarddog_scanner,
)
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
    GuardDogScannerConfig,
    GuardDogScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils import pre_installed_tool, uv_tool_runner

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

VERIFY = "automated_security_helper.utils.pre_installed_tool.verify_pre_installed_tool"


def _context(tmp_path: Path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(source_dir=source, output_dir=output, config=AshConfig())


def _copy(tmp_path: Path, name: str) -> Path:
    """An executable stand-in for a copy on PATH."""
    copy = tmp_path / "pathbin" / name
    copy.parent.mkdir(exist_ok=True)
    copy.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    copy.chmod(0o755)
    return copy


def _satisfied(version: str | None) -> SimpleNamespace:
    return SimpleNamespace(
        status="satisfied",
        executable="/opt/bin/tool",
        detail="ok",
        summary="",
        from_nix=False,
        version=version,
    )


@pytest.fixture(autouse=True)
def _guarddog_reads_what_these_tests_replace(monkeypatch):
    """GuardDog takes the verifier, the PATH lookup and the uv lookup by name when its
    module is imported, while checkov, cfn-lint and bandit import them where they call
    them. ``patch(VERIFY, ...)`` and the unit tests' tool guard reach those calls and
    not GuardDog's names, so GuardDog's names are routed through the modules this file
    and the guard replace. Its PATH lookup finds no GuardDog: a uv answer looks there,
    since the uv-absent branch checks the copy a direct run would start. Its check runs
    as on a host it supports: it refuses Windows before anything else.

    The fixture changes only GuardDog's own names, and it keeps ``monkeypatch``'s
    default of failing on a name that is not there, so a binding renamed in GuardDog
    fails here instead of patching nothing."""
    monkeypatch.setattr(
        guarddog_scanner,
        "verify_pre_installed_tool",
        lambda *args, **kwargs: pre_installed_tool.verify_pre_installed_tool(
            *args, **kwargs
        ),
    )
    monkeypatch.setattr(
        guarddog_scanner, "find_uv_or_none", lambda: uv_tool_runner.find_uv_or_none()
    )
    monkeypatch.setattr(guarddog_scanner, "find_executable", lambda name: None)
    monkeypatch.setattr(
        GuardDogScanner, "unsupported_platform_reason", lambda self: None
    )


@pytest.fixture
def checkov(tmp_path) -> CheckovScanner:
    return CheckovScanner(context=_context(tmp_path))


def _select_verified_copy(scanner, tmp_path: Path, version: str, name: str) -> Path:
    """Run ``_select_tool_execution`` into its verified-copy arm."""
    copy = _copy(tmp_path, name)
    info = {"preferred_source": "pre_installed", "pre_installed_path": str(copy)}
    with (
        patch(VERIFY, return_value=_satisfied(version)),
        patch.object(type(scanner), "_is_offline_mode", return_value=False),
    ):
        assert scanner._select_tool_execution(info) is True
    assert scanner.use_uv_tool is False
    assert scanner._verified_pre_installed_executable == str(copy)
    return copy


# ---------------------------------------------------------------------------
# The selection owes no probe
# ---------------------------------------------------------------------------


def test_choosing_a_copy_on_path_records_its_version_and_drops_the_owed_probe(
    checkov, tmp_path
):
    checkov._deferred_tool_version_probe = ("checkov", checkov._uv_from_spec())
    checkov.use_uv_tool = True

    _select_verified_copy(checkov, tmp_path, "3.3.15", "checkov")

    # With no resolve call in between: the probe is dropped by the selection.
    assert checkov._deferred_tool_version_probe is None
    assert checkov.tool_version == "3.3.15"


# ---------------------------------------------------------------------------
# A dropped decision puts the uv route back with its record
# ---------------------------------------------------------------------------


def test_a_copy_that_is_gone_takes_its_version_with_the_decision(checkov, tmp_path):
    copy = _select_verified_copy(checkov, tmp_path, "3.3.15", "checkov")
    copy.unlink()

    assert checkov._honored_verified_pre_installed() is False

    assert checkov.use_uv_tool is True
    assert checkov._verified_pre_installed_executable is None
    assert checkov.tool_version is None
    assert checkov._deferred_tool_version_probe is not None
    assert checkov._deferred_tool_version_probe[0] == "checkov"


def test_the_sarif_step_names_the_environment_uv_runs_after_the_copy_is_gone(
    checkov, tmp_path
):
    copy = _select_verified_copy(checkov, tmp_path, "3.3.15", "checkov")
    copy.unlink()
    captured: dict = {}

    def capture(**kwargs):
        captured.update(kwargs)

    with (
        patch.object(
            CheckovScanner, "_validate_uv_tool_availability", return_value=True
        ),
        patch.object(
            CheckovScanner,
            "_get_tool_installation_info",
            return_value={"available": True, "preferred_source": "uv"},
        ),
        patch.object(CheckovScanner, "_is_offline_mode", return_value=False),
        patch.object(CheckovScanner, "_get_uv_tool_version", return_value="3.4.5"),
    ):
        assert checkov.validate_plugin_dependencies() is True

        report = SarifReport(
            version="2.1.0",
            runs=[Run(tool=Tool(driver=ToolComponent(name="checkov")), results=[])],
        )
        checkov.start_time = datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        checkov.end_time = datetime(2025, 1, 1, 12, 0, 5, tzinfo=timezone.utc)
        checkov.exit_code = 0
        checkov.errors = []
        with patch(
            "automated_security_helper.utils.sarif_utils.attach_scanner_details",
            capture,
        ):
            checkov._inject_invocation(report, ["checkov"], checkov.context.source_dir)

    assert checkov.use_uv_tool is True
    assert captured["scanner_version"] == "3.4.5"


def _swap_config_and_record_validation(scanner, target: Path, **changed_options):
    """Swap a config that differs only in options, as ``_pre_scan`` does per target.

    Returns what the re-validation saw: the route, the recorded version, and whether
    the uv probe was owed again.
    """
    observed = []

    def recording_validate(self):
        observed.append(
            (
                self.use_uv_tool,
                self.tool_version,
                self._deferred_tool_version_probe is not None,
            )
        )
        self.dependencies_satisfied = True
        return True

    changed = scanner.config.model_dump(by_alias=True)
    changed["options"].update(changed_options)
    with patch.object(
        type(scanner), "validate_plugin_dependencies", recording_validate
    ):
        assert scanner._pre_scan(target, target_type="source", config=changed)
    return observed


def _in_a_verified_path_decision(scanner, tmp_path: Path, name: str) -> None:
    """The state ``_select_tool_execution`` leaves, then a memoized validation."""
    scanner.use_uv_tool = False
    scanner.tool_version = "3.3.15"
    scanner._deferred_tool_version_probe = None
    scanner._verified_pre_installed_executable = str(_copy(tmp_path, name))
    scanner._dependencies_validated = True
    scanner.dependencies_satisfied = True


def test_a_config_swap_in_pre_scan_puts_the_uv_route_back_with_its_probe(
    checkov, tmp_path
):
    _in_a_verified_path_decision(checkov, tmp_path, "checkov")

    observed = _swap_config_and_record_validation(
        checkov, checkov.context.source_dir, scan_timeout=123
    )

    assert observed == [(True, None, True)]


def test_a_bandit_config_swap_puts_the_uv_route_back_with_its_probe(tmp_path):
    bandit = BanditScanner(context=_context(tmp_path))
    _in_a_verified_path_decision(bandit, tmp_path, "bandit")

    observed = _swap_config_and_record_validation(
        bandit, bandit.context.source_dir, scan_timeout=321
    )

    assert observed == [(True, None, True)]


# ---------------------------------------------------------------------------
# A copy that answered no version leaves the record empty
# ---------------------------------------------------------------------------


def test_bandit_records_nothing_for_a_resolved_copy_that_answered_no_version(tmp_path):
    bandit = BanditScanner(context=_context(tmp_path))
    bandit.tool_version = "1.8.6"  # what an earlier uv probe wrote

    with patch(VERIFY, return_value=_satisfied(None)):
        assert bandit._take_resolved_command(["/opt/bin/bandit"]) is True

    assert bandit.use_uv_tool is False
    assert bandit.tool_version is None


def test_bandit_records_the_version_a_resolved_copy_answered(tmp_path):
    bandit = BanditScanner(context=_context(tmp_path))
    bandit.tool_version = "1.8.6"

    with patch(VERIFY, return_value=_satisfied("1.8.3")):
        assert bandit._take_resolved_command(["/opt/bin/bandit"]) is True

    assert bandit.use_uv_tool is False
    assert bandit.tool_version == "1.8.3"


def test_a_bandit_revalidation_off_uv_takes_the_uv_route_the_resolver_names(
    tmp_path, monkeypatch
):
    """A bandit on a direct route is validated again. It records no verified copy,
    so the re-validation falls through to the final fallback and asks the resolver,
    and a uv answer there is the uv route: the scanner goes back to it with the
    record that route owes, the version of the copy dropped and the uv probe owed
    again. The check of uv's availability is not replaced: off uv, the real one
    answers True at once.

    Without the fix the route stayed direct, and the scan started whatever bandit
    PATH holds under a requirement it was never checked against."""
    bandit = BanditScanner(context=_context(tmp_path))
    bandit.use_uv_tool = False
    bandit.tool_version = "1.8.3"  # what the direct route recorded
    bandit._deferred_tool_version_probe = None
    monkeypatch.setattr(
        BanditScanner, "resolve_deferred_tool_version", lambda self: None
    )
    monkeypatch.setattr(
        bandit_scanner,
        "get_uv_tool_command",
        lambda *args, **kwargs: ["uv", "tool", "run", "bandit"],
    )

    with patch(VERIFY, side_effect=_never_verified):
        assert bandit.validate_plugin_dependencies() is True

    assert bandit.use_uv_tool is True
    assert bandit.tool_version is None
    assert bandit._deferred_tool_version_probe == ("bandit", None)
    assert bandit.dependencies_satisfied is True


# ---------------------------------------------------------------------------
# checkov, cfn-lint and guarddog resolver arms
# ---------------------------------------------------------------------------


def _checkov_for(tmp_path):
    return CheckovScanner(context=_context(tmp_path))


def _cfn_lint_for(tmp_path):
    return CfnLintScanner(context=_context(tmp_path), config=CfnLintScannerConfig())


def _guarddog_for(tmp_path):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return GuardDogScanner(
        context=context,
        config=GuardDogScannerConfig(
            enabled=True, options=GuardDogScannerConfigOptions()
        ),
    )


RESOLVER_SCANNERS = pytest.mark.parametrize(
    ("make", "module", "tool"),
    [
        (_checkov_for, checkov_scanner, "checkov"),
        (_cfn_lint_for, cfn_lint_scanner, "cfn-lint"),
        (_guarddog_for, guarddog_scanner, "guarddog"),
    ],
    ids=["checkov", "cfn-lint", "guarddog"],
)

#: uv named the ways the uv the resolver probes can be found: by its path, and as a
#: Windows executable in any letter case.
UV_NAMED_BY_PATH = pytest.mark.parametrize(
    "uv",
    ["/opt/uv/bin/uv", "C:\\Users\\me\\.local\\bin\\uv.exe", "C:/tools/UV.EXE"],
    ids=["posix-path", "windows-exe", "upper-case-exe"],
)


def _never_verified(*args, **kwargs):
    pytest.fail("a uv answer is not verified as the tool")


@RESOLVER_SCANNERS
def test_a_resolved_binary_after_a_failed_install_leaves_no_probe_version(
    tmp_path, monkeypatch, make, module, tool
):
    scanner = make(tmp_path)
    scanner.tool_version = "9.9.9"  # the uv probe's answer
    cls = type(scanner)
    monkeypatch.setattr(cls, "resolve_deferred_tool_version", lambda self: None)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: True)
    monkeypatch.setattr(
        cls, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(cls, "_install_uv_tool", lambda self, **kwargs: False)
    monkeypatch.setattr(
        module, "get_uv_tool_command", lambda *args, **kwargs: [f"/opt/bin/{tool}"]
    )

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.tool_version is None


@RESOLVER_SCANNERS
def test_the_resolver_returning_to_uv_takes_the_old_version_with_the_route(
    tmp_path, monkeypatch, make, module, tool
):
    scanner = make(tmp_path)
    scanner.use_uv_tool = False
    scanner._deferred_tool_version_probe = None
    scanner.tool_version = "1.2.3"
    cls = type(scanner)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: True)
    monkeypatch.setattr(
        module,
        "get_uv_tool_command",
        lambda *args, **kwargs: ["uv", "tool", "run", tool],
    )

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe is not None
    assert scanner._deferred_tool_version_probe[0] == tool


@RESOLVER_SCANNERS
@pytest.mark.parametrize("answered", ["3.3.15", None], ids=["a-version", "none"])
def test_a_binary_accepted_on_path_records_its_own_answer_over_the_probes(
    tmp_path, make, module, tool, answered
):
    scanner = make(tmp_path)
    scanner.tool_version = "9.9.9"  # the uv probe's answer
    scanner._deferred_tool_version_probe = (tool, None)

    with patch(VERIFY, return_value=_satisfied(answered)):
        assert scanner._accept_binary_on_path([f"/opt/bin/{tool}"]) is True

    assert scanner.use_uv_tool is False
    assert scanner.tool_version == answered
    assert scanner._deferred_tool_version_probe is None


@RESOLVER_SCANNERS
def test_accepting_the_uv_form_keeps_the_uv_routes_record(tmp_path, make, module, tool):
    """``_accept_binary_on_path`` is called only from the uv-absent branch of
    ``validate_plugin_dependencies``, entered only while ``use_uv_tool`` is True:
    ``_validate_uv_tool_availability`` answers True at once for a scanner off uv.
    A uv answer there leaves the uv route as it is, the version the uv probe
    recorded and a probe still owed included."""
    scanner = make(tmp_path)
    scanner.use_uv_tool = True
    scanner.tool_version = "3.4.5"
    scanner._deferred_tool_version_probe = (tool, None)

    with patch(VERIFY, side_effect=_never_verified):
        assert scanner._accept_binary_on_path(["uv", "tool", "run", tool]) is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version == "3.4.5"
    assert scanner._deferred_tool_version_probe == (tool, None)
    assert scanner.dependencies_satisfied is True


@RESOLVER_SCANNERS
@UV_NAMED_BY_PATH
@pytest.mark.parametrize(
    ("version", "owed"),
    [("9.9.9", False), (None, True)],
    ids=["probe-answered", "probe-owed"],
)
def test_a_uv_answer_named_by_path_after_a_failed_install_keeps_the_uv_record(
    tmp_path, monkeypatch, make, module, tool, uv, version, owed
):
    """After uv's install of the tool failed, a resolver answer that names uv by
    its path is still the uv route: the version the uv probe recorded and a probe
    still owed both stay, so the SARIF step names the release uv runs.

    Fails at the base: the answer was compared with the bare word ``uv``, so the
    route left uv and both records were cleared."""
    scanner = make(tmp_path)
    scanner.use_uv_tool = True
    scanner.tool_version = version
    scanner._deferred_tool_version_probe = (tool, None) if owed else None
    cls = type(scanner)
    monkeypatch.setattr(cls, "resolve_deferred_tool_version", lambda self: None)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: True)
    monkeypatch.setattr(
        cls, "_get_tool_installation_info", lambda self: {"available": False}
    )
    monkeypatch.setattr(cls, "_install_uv_tool", lambda self, **kwargs: False)
    monkeypatch.setattr(
        module,
        "get_uv_tool_command",
        lambda *args, **kwargs: [uv, "tool", "run", tool],
    )

    with patch(VERIFY, side_effect=_never_verified):
        assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version == version
    assert scanner._deferred_tool_version_probe == ((tool, None) if owed else None)
    assert scanner.dependencies_satisfied is True


@RESOLVER_SCANNERS
@UV_NAMED_BY_PATH
def test_a_uv_answer_named_by_path_with_uv_unavailable_is_not_verified_as_the_tool(
    tmp_path, monkeypatch, make, module, tool, uv
):
    """The runner reported uv unavailable while the resolver's own probe ran uv.
    An answer that names uv by its path is the uv route there too: it is not
    verified as the tool, and the uv route keeps the version the uv probe
    recorded.

    Fails at the base: the uv path was handed to the verifier as the tool."""
    scanner = make(tmp_path)
    scanner.use_uv_tool = True
    scanner.tool_version = "9.9.9"
    cls = type(scanner)
    monkeypatch.setattr(cls, "resolve_deferred_tool_version", lambda self: None)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: False)
    monkeypatch.setattr(
        module,
        "get_uv_tool_command",
        lambda *args, **kwargs: [uv, "tool", "run", tool],
    )

    with patch(VERIFY, side_effect=_never_verified):
        assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version == "9.9.9"
    assert scanner.dependencies_satisfied is True


@RESOLVER_SCANNERS
def test_a_uv_answer_reached_off_uv_takes_the_uv_route(
    tmp_path, monkeypatch, make, module, tool
):
    """The uv-absent branch is entered through ``_validate_uv_tool_availability``,
    which answers True at once for a scanner off uv, so its one real caller is on
    uv. Any other entry (an override of that check, a new caller, a test that
    patches it, as this one does) must not leave a uv answer on a direct route,
    where the scan starts whatever copy PATH holds, unverified. A uv answer is the
    uv route: the scanner goes back to it with the record that route owes, the
    version of the direct copy dropped and the uv probe owed again.

    Without the fix the branch returned True with the route still direct."""
    scanner = make(tmp_path)
    scanner.use_uv_tool = False
    scanner.tool_version = "3.3.15"  # a direct route's record
    scanner._deferred_tool_version_probe = None
    cls = type(scanner)
    monkeypatch.setattr(cls, "resolve_deferred_tool_version", lambda self: None)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: False)
    monkeypatch.setattr(
        module,
        "get_uv_tool_command",
        lambda *args, **kwargs: ["uv", "tool", "run", tool],
    )

    with patch(VERIFY, side_effect=_never_verified):
        assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version is None
    assert scanner._deferred_tool_version_probe == (tool, None)
    assert scanner.dependencies_satisfied is True


class _NoUvRunner:
    """A uv runner that reports uv as absent."""

    def uv_availability(self):
        return (False, None)

    def is_uv_available(self):
        return False

    def unavailable_reason(self):
        return "UV is not available"


@RESOLVER_SCANNERS
def test_a_revalidation_already_off_uv_keeps_the_version_of_the_copy_that_runs(
    tmp_path, monkeypatch, make, module, tool
):
    """No uv: the first validation records the verified copy's version. A per-target
    config swap then re-validates a scanner that is already off uv, whose
    availability check answers True at once, so the final fallback sees the same
    binary again and must not erase the version of the copy that keeps running."""
    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda *args, **kwargs: _NoUvRunner(),
    )
    monkeypatch.setattr(
        module, "get_uv_tool_command", lambda *args, **kwargs: [f"/opt/bin/{tool}"]
    )
    scanner = make(tmp_path)
    target = scanner.context.source_dir
    (target / "template.yaml").write_text("Resources: {}\n")

    with patch(VERIFY, return_value=_satisfied("3.3.15")):
        assert scanner.validate_plugin_dependencies() is True
        assert scanner.use_uv_tool is False
        assert scanner.tool_version == "3.3.15"

        scanner._dependencies_validated = True
        changed = scanner.config.model_dump(by_alias=True)
        changed["options"]["scan_timeout"] = 123
        scanner._pre_scan(target, target_type="source", config=changed)

    assert scanner.use_uv_tool is False
    assert scanner.tool_version == "3.3.15"


# ---------------------------------------------------------------------------
# zizmor
# ---------------------------------------------------------------------------


class _Completed:
    def __init__(self, stdout, returncode=0):
        self.stdout = stdout
        self.returncode = returncode


def _zizmor_with_executable(monkeypatch, version_output):
    monkeypatch.setattr(zizmor_scanner, "find_executable", lambda _: "/opt/bin/zizmor")
    monkeypatch.setattr(
        zizmor_scanner,
        "run_command",
        lambda args, env=None, **_: _Completed(version_output),
    )


def test_a_rejected_path_binary_takes_the_version_it_recorded_with_the_route(
    tmp_path, monkeypatch
):
    """The first check ran a satisfying zizmor on PATH and recorded its version.
    By the second check that binary reports an old release and the constrained
    probe resolves nothing; uv runs, and no version is recorded for it."""
    monkeypatch.setenv("ASH_OFFLINE", "true")
    source = tmp_path / "src"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    scanner = ZizmorScanner(
        context=context,
        config=ZizmorScannerConfig(enabled=True, options=ZizmorScannerConfigOptions()),
    )
    object.__setattr__(scanner, "_get_uv_tool_version", lambda *_, **__: None)

    _zizmor_with_executable(monkeypatch, "zizmor 1.29.0\n")
    assert scanner.validate_plugin_dependencies() is True
    assert scanner.tool_version == "1.29.0"
    assert scanner.use_uv_tool is False

    _zizmor_with_executable(monkeypatch, "zizmor 1.28.0\n")
    object.__setattr__(
        scanner, "_resolve_through_uv", lambda probe_satisfies=False: True
    )

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.tool_version is None
