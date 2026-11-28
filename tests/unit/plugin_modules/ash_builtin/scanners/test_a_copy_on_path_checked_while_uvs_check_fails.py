"""The copy checks of checkov, cfn-lint and bandit while uv's check does not pass.

The check does not pass when uv is absent, when its probe failed, and for the
runner's retry window after a probe of uv timed out or was killed, so uv may well
be installed. In that branch checkov and cfn-lint take the binary the resolver
names and verify it against the scan's requirement before running it, and bandit
does the same in its resolved-command check. They share the shape of guarddog's
check of a copy on PATH:

- A copy that falls short is MISSING, and the reason names the verifier's
  one-line summary of the shortfall and a remedy that fits the host and the
  shortfall: with a uv found, the install command and a run once the check
  passes, and a ``tool_version`` the copy meets only when the version constraint
  is all it fails; with none, installing uv. It never names the copy's path or
  the verifier's detail, which the ERROR line keeps. The detail quotes the scan's
  requirement in the spelling the options validator stored, and an
  environment-read ``tool_version`` was written in another spelling, which the
  plain match the scan phase applies to the reason does not see.
- The reason and every line go through the uv-aware redaction, with the plugin's
  values read once and guarded, and the lines name the availability check that
  did not pass, not an absent uv.
- A values hook that raises leaves the copy unrun, with a reason that names only
  the failure. A uv answer reads no hook: the uv route it keeps reads the hook on
  its own run path.

Only the availability check, the resolver, the verifier, the uv lookup and the
version probe the dependency check runs first are stood in for.
"""

from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List, NamedTuple

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    bandit_scanner,
    cfn_lint_scanner,
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)
from automated_security_helper.utils import pre_installed_tool, uv_tool_runner
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.pre_installed_tool import build_requirement

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

#: The uv the scanner's own lookup finds, in the tests whose remedy depends on one.
UV = "/opt/uv/bin/uv"

#: The verifier's one-line summaries of a shortfall. The first is its words for a copy
#: whose version alone falls short of the constraint, which it reaches only through
#: uv's dry run. The second is a ``--version`` probe that exits non-zero, which it
#: reports before it asks uv, with or without one.
SHORT_OF_THE_CONSTRAINT = (
    "the installed package does not satisfy the version constraint"
)
PROBE_EXITED = "its --version probe exited 1"

#: ``tool_version`` as an environment variable can hold it, with a space between the
#: operator and the version. The options validator stores it without one, so what the
#: plugin's values hook answers and what the verifier quotes are two spellings of one
#: value. The version is none that a fixed text of these scanners carries.
AS_READ = "== 3.7.4"


def _context(tmp_path: Path) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(source_dir=source, output_dir=output, config=AshConfig())


def _checkov(tmp_path: Path, tool_version: str | None = None) -> CheckovScanner:
    options = (
        CheckovScannerConfigOptions()
        if tool_version is None
        else CheckovScannerConfigOptions(tool_version=tool_version)
    )
    return CheckovScanner(
        context=_context(tmp_path), config=CheckovScannerConfig(options=options)
    )


def _cfn_lint(tmp_path: Path, tool_version: str | None = None) -> CfnLintScanner:
    options = (
        CfnLintScannerConfigOptions()
        if tool_version is None
        else CfnLintScannerConfigOptions(tool_version=tool_version)
    )
    return CfnLintScanner(
        context=_context(tmp_path), config=CfnLintScannerConfig(options=options)
    )


def _bandit(tmp_path: Path) -> BanditScanner:
    return BanditScanner(context=_context(tmp_path))


def _verdict(
    status: str, version: str | None = None, detail: str = "", summary: str = ""
) -> Any:
    return SimpleNamespace(
        status=status,
        executable="/opt/bin/tool",
        detail=detail,
        summary=summary,
        from_nix=False,
        version=version,
    )


class _Verifier:
    """Stands in for ``verify_pre_installed_tool``: gives one verdict, records what
    it was asked."""

    def __init__(self, verdict: Any) -> None:
        self.verdict = verdict
        self.asked: List[tuple[Any, ...]] = []

    def __call__(
        self, executable, package, extras=None, version_constraint=None, **kwargs
    ):
        self.asked.append((executable, package, extras, version_constraint))
        return self.verdict


def _never_verified(*args: Any, **kwargs: Any) -> Any:
    pytest.fail("no copy is verified here")


def _a_values_hook_that_raises(self: Any) -> tuple[str, ...]:
    raise RuntimeError("the hook failed")


def _with_uv_unavailable(
    monkeypatch, scanner, module, answer, verifier=_never_verified, uv=None
) -> None:
    """The scanner's dependency check as it runs while uv's availability check does
    not pass: the resolver answers ``answer``, ``verifier`` judges the copy, and the
    scanner's own lookup of uv finds ``uv``. The version probe the check runs first
    is stood in for."""
    cls = type(scanner)
    monkeypatch.setattr(cls, "resolve_deferred_tool_version", lambda self: None)
    monkeypatch.setattr(cls, "_validate_uv_tool_availability", lambda self: False)
    monkeypatch.setattr(module, "get_uv_tool_command", lambda *args, **kwargs: answer)
    monkeypatch.setattr(pre_installed_tool, "verify_pre_installed_tool", verifier)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: uv)


class _EnvReadPin(NamedTuple):
    """The spellings of one environment-read ``tool_version`` the check could show."""

    as_read: str
    stored: str
    requirement: str
    #: The verifier's detail for a copy that falls short of the constraint: it quotes
    #: the requirement, then the bare constraint, both as stored.
    detail: str


def _with_an_env_read_constraint(monkeypatch, tmp_path: Path, make, tool: str):
    """A scanner whose ``tool_version`` was read from the environment, and the three
    spellings of it that must not be shown: as the environment held it, as the
    options validator stored it, and inside the requirement built from that. The
    plugin's values hook answers what the environment held, as
    ``config_environment_values`` does for a value read with ``!ENV``."""
    scanner = make(tmp_path, tool_version=AS_READ)
    monkeypatch.setattr(type(scanner), "_values_to_redact", lambda self: (AS_READ,))
    stored = scanner._get_tool_version_constraint()
    requirement = build_requirement(tool, scanner._get_tool_package_extras(), stored)
    detail = (
        f"its environment (/opt/venv/bin/python) does not satisfy {requirement!r}: "
        f"installed {tool} does not satisfy {stored!r}"
    )
    # The controls. The validator changed the spelling, so the plain match the scan
    # phase applies to the reason cannot hide the stored one, and the detail carries
    # it: a text without it was hidden, not never given it.
    assert stored != AS_READ
    assert text_without_values(stored, [AS_READ]) == stored
    assert stored in detail
    return scanner, _EnvReadPin(AS_READ, stored, requirement, detail)


def _spellings_shown(pin: _EnvReadPin, **texts: str) -> list[str]:
    """Which of ``texts`` show which spelling of the constraint, as labels that name
    the kind of spelling and never its characters. Empty when none does."""
    return [
        f"{where}: {kind}"
        for where, text in texts.items()
        for kind, spelling in (
            ("as read", pin.as_read),
            ("as stored", pin.stored),
            ("in the requirement", pin.requirement),
        )
        if spelling in text
    ]


SCANNERS = pytest.mark.parametrize(
    ("make", "module", "tool"),
    [
        (_checkov, checkov_scanner, "checkov"),
        (_cfn_lint, cfn_lint_scanner, "cfn-lint"),
    ],
    ids=["checkov", "cfn-lint"],
)

HOOK_SCANNERS = pytest.mark.parametrize(
    ("make", "module", "tool"),
    [
        (_checkov, checkov_scanner, "checkov"),
        (_cfn_lint, cfn_lint_scanner, "cfn-lint"),
        (_bandit, bandit_scanner, "bandit"),
    ],
    ids=["checkov", "cfn-lint", "bandit"],
)

#: The shortfall, the host, and whether a constraint can fix it.
SHORTFALLS = pytest.mark.parametrize(
    ("uv_found", "summary", "offers_a_constraint"),
    [
        (True, SHORT_OF_THE_CONSTRAINT, True),
        (True, PROBE_EXITED, False),
        (False, PROBE_EXITED, False),
    ],
    ids=["uv-found", "uv-found-probe-exited", "no-uv"],
)


@SCANNERS
@SHORTFALLS
def test_a_copy_that_falls_short_is_missing_with_the_summary_and_a_remedy(
    tmp_path, monkeypatch, make, module, tool, uv_found, summary, offers_a_constraint
):
    """While uv's availability check does not pass, the copy on PATH the resolver
    names is the only copy the scan could run. One that falls short is MISSING, and
    the reason names the verifier's summary of the shortfall, the requirement and a
    remedy that fits the host and the shortfall: with a uv found, the install
    command and a run once the check passes, and a ``tool_version`` this copy meets
    only when the version constraint is all it fails; with none, installing uv. The
    reason names no path, quotes no detail and says nothing of uv being absent; the
    ERROR line keeps the copy's path and the detail, and names the check that did
    not pass.

    Without the fix: the reason was "uv is not installed and the <tool> on PATH
    (<path>) cannot be used: <detail>", with no remedy."""
    scanner = make(tmp_path)
    copy = f"/opt/bin/{tool}"
    detail = f"{tool} 0.0.1 does not satisfy the scan's requirement"
    verifier = _Verifier(
        _verdict("unsatisfied", version="0.0.1", detail=detail, summary=summary)
    )
    _with_uv_unavailable(
        monkeypatch, scanner, module, [copy], verifier, uv=UV if uv_found else None
    )
    requirement = build_requirement(
        tool,
        scanner._get_tool_package_extras(),
        scanner._get_tool_version_constraint(),
    )

    assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependencies_satisfied is False
    reason = scanner.dependency_unavailable_reason
    assert reason is not None
    assert copy not in reason
    assert detail not in reason
    assert "uv is not installed" not in reason
    assert summary in reason
    assert requirement in reason
    assert ("uv tool install" in reason) is uv_found
    assert ("once uv's availability check passes" in reason) is uv_found
    assert ("install uv" in reason) is not uv_found
    assert ("options.tool_version" in reason) is offers_a_constraint
    if offers_a_constraint:
        assert f"scanners.{tool}.options.tool_version" in reason
    # The log line keeps what the reason leaves out.
    about_the_copy = [line for line in scanner.errors if copy in line]
    assert any(detail in line for line in about_the_copy)
    assert all(
        "uv's availability check did not pass" in line for line in about_the_copy
    )
    assert not any("uv is not installed" in line for line in scanner.errors)
    assert [asked[:2] for asked in verifier.asked] == [(copy, tool)]


@SCANNERS
def test_the_reason_and_the_lines_show_no_spelling_of_an_env_read_constraint(
    tmp_path, monkeypatch, capture, make, module, tool
):
    """A ``tool_version`` read from the environment reaches the verifier in the
    spelling the options validator stored, which is not the spelling the plugin's
    values hook answers, so the plain match that redacts the reason in the scan
    phase does not see it. The verdict's detail for a copy that falls short quotes
    the requirement and the bare constraint in that spelling. Neither the reason,
    nor the ERROR line and the scanner's errors that carry the detail, nor the log
    shows the constraint in any of its three spellings. The reason is not empty for
    it: it still names the shortfall and the install command.

    Without the fix: the reason and the ERROR line quoted the detail unredacted."""
    scanner, pin = _with_an_env_read_constraint(monkeypatch, tmp_path, make, tool)
    verifier = _Verifier(
        _verdict(
            "unsatisfied",
            version="0.0.1",
            detail=pin.detail,
            summary=SHORT_OF_THE_CONSTRAINT,
        )
    )
    _with_uv_unavailable(
        monkeypatch, scanner, module, [f"/opt/bin/{tool}"], verifier, uv=UV
    )

    assert scanner.validate_plugin_dependencies() is False

    reason = scanner.dependency_unavailable_reason
    assert reason is not None
    assert (
        _spellings_shown(
            pin,
            reason=reason,
            errors="\n".join(scanner.errors),
            log=capture.text,
        )
        == []
    )
    assert SHORT_OF_THE_CONSTRAINT in reason
    assert "uv tool install" in reason


@SCANNERS
def test_the_warning_about_a_copy_that_cannot_be_verified_names_the_check_and_no_value(
    tmp_path, monkeypatch, capture, make, module, tool
):
    """A copy the check could not verify runs, with a warning, since nothing better
    can run while the check does not pass. The warning names the availability check
    that did not pass, not an absent uv, and it goes through the same redaction as
    the reason: the verdict's detail here quotes an environment-read constraint as
    stored, and no spelling of it is shown.

    Without the fix: the warning said uv was not installed and quoted the detail as
    it came."""
    scanner, pin = _with_an_env_read_constraint(monkeypatch, tmp_path, make, tool)
    copy = f"/opt/bin/{tool}"
    _with_uv_unavailable(
        monkeypatch,
        scanner,
        module,
        [copy],
        _Verifier(_verdict("unverifiable", detail=pin.detail)),
        uv=UV,
    )

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is False
    assert scanner.dependency_unavailable_reason is None
    about_the_copy = [
        record.getMessage() for record in capture.records if copy in record.getMessage()
    ]
    assert len(about_the_copy) == 1
    assert "could not be verified" in about_the_copy[0]
    assert "uv's availability check did not pass" in about_the_copy[0]
    assert "uv is not installed" not in about_the_copy[0]
    assert _spellings_shown(pin, log=capture.text) == []


@HOOK_SCANNERS
def test_a_values_hook_that_raises_leaves_the_copy_unrun(
    tmp_path, monkeypatch, capture, make, module, tool
):
    """The plugin's values hook is read once, guarded, before the copy on PATH is
    checked. One that raises leaves nothing to redact the check's lines with, so the
    copy does not run: the check is False, the reason names the hook's failure and
    nothing of the copy, a WARNING says so, and the route stays as it was.

    Without the fix: the hook was read bare, and its error escaped the check."""
    scanner = make(tmp_path)
    copy = f"/opt/bin/{tool}"
    route = scanner.use_uv_tool
    monkeypatch.setattr(type(scanner), "_values_to_redact", _a_values_hook_that_raises)
    _with_uv_unavailable(monkeypatch, scanner, module, [copy])

    assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependencies_satisfied is False
    reason = scanner.dependency_unavailable_reason
    assert reason is not None
    assert "values hook raised RuntimeError" in reason
    assert "Fix the plugin's values hook" in reason
    assert copy not in reason
    warnings = [
        record.getMessage()
        for record in capture.records
        if record.levelno == logging.WARNING
    ]
    assert any(
        "was not verified" in line and "raised RuntimeError" in line
        for line in warnings
    )
    assert scanner.use_uv_tool is route


@HOOK_SCANNERS
def test_a_uv_answer_reads_no_values_hook(tmp_path, monkeypatch, make, module, tool):
    """The control of the test above. A uv answer keeps the uv route without checking
    a copy, so nothing on the way reads the hook: the uv route's own run path reads
    it where it needs to. It passes with and without the fix; a failure at either
    means something on the way reads the hook bare."""
    scanner = make(tmp_path)
    monkeypatch.setattr(type(scanner), "_values_to_redact", _a_values_hook_that_raises)
    _with_uv_unavailable(monkeypatch, scanner, module, ["uv", "tool", "run", tool])

    assert scanner.validate_plugin_dependencies() is True

    assert scanner.use_uv_tool is True
    assert scanner.dependencies_satisfied is True
    assert scanner.dependency_unavailable_reason is None
