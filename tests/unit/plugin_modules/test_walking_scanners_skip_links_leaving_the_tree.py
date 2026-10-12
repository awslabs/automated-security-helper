# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every scanner that walks its target itself is kept off links that leave it.

ASH's scan set leaves out a link to a file whose target leaves the scanned tree, but
only detect-secrets, cfn-nag, cdk-nag and npm-audit read the scan set. Every other
scanner is handed a directory and walks it. bandit, checkov and ferret-scan are
covered in their own tests (test_scanners_skip_links_leaving_the_tree.py and the
ferret one). This covers the rest, and pins that every registered scanner is one of
the kinds below, so a new one cannot be added without deciding which:

- grype and syft follow no link leaving their target (measured with grype 0.120.1
  and syft 1.54.1). Each link is still passed in ``--exclude``, as ``./<path>`` with
  the glob characters escaped, which leaves out that path and no other.
- trivy (the trivy-repo scanner) skips every link (measured with trivy 0.75.0). Each
  link is passed in ``--skip-files`` with the glob characters escaped; a path with a
  comma is not, because trivy splits the value on commas.
- semgrep and opengrep skip every link (measured with semgrep 1.180.0 and opengrep
  1.30.2), and their ``--exclude`` cannot name one path: semgrep matches a pattern
  against paths below the git work tree's root when the target is inside one, and
  opengrep matches a top-level name at every depth. So no link is passed: a name
  passed when nothing below the target had it could still be one of the target's
  own directories, and then it left out the whole target.
- snyk-code uploads what it reads, has no option that leaves out one path, and how
  it treats links is not measured, so a target with such a link is not scanned.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from tests.utils.git_fixture import run_git

PluginContext.model_rebuild()

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)

PLUGIN_MODULES = Path(__file__).resolve().parents[3] / (
    "automated_security_helper/plugin_modules"
)

#: How each registered scanner is kept off a link that leaves its target.
LINK_HANDLING = {
    "detect-secrets": "reads the scan set",
    "cfn-nag": "reads the scan set",
    "cdk-nag": "reads the scan set",
    "npm-audit": "reads the scan set",
    "bandit": "excluded, or the target refused",
    "checkov": "excluded, or the target refused",
    "ferret-scan": "excluded, or the target refused",
    "grype": "follows no such link; excluded too",
    "syft": "follows no such link; excluded too",
    "trivy-repo": "follows no link; excluded too",
    "semgrep": "follows no link; not excluded",
    "opengrep": "follows no link; not excluded",
    "snyk-code": "the target refused",
}


class _Stop(Exception):
    """Raised in place of running the tool, once its argv is recorded."""


def _tree(base: Path, files: dict[str, str], links: dict[str, str]) -> Path:
    """A source tree with *files* and *links*, and an ``outside`` directory beside it.

    A link target of ``outside`` or ``outside/...`` points there; any other target
    is a path inside the tree.
    """
    outside = base / "outside"
    source = base / "source"
    for directory in (outside, source):
        directory.mkdir(exist_ok=True)
    for name in ("secret.py", "main.tf", "requirements.txt", "config.yml"):
        (outside / name).write_text(f"# outside {name}\n", encoding="utf-8")
    for rel, text in files.items():
        (source / rel).parent.mkdir(parents=True, exist_ok=True)
        (source / rel).write_text(text, encoding="utf-8")
    for rel, target in links.items():
        link = source / rel
        link.parent.mkdir(parents=True, exist_ok=True)
        if target == "outside" or target.startswith("outside/"):
            resolved = base / target
        else:
            resolved = source / target
        link.symlink_to(resolved, target_is_directory=resolved.is_dir())
    return source


def _context(source: Path, base: Path) -> PluginContext:
    output = base / "ash-output"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )


def _values(argv: list[str], flag: str) -> list[str]:
    values = []
    for index, arg in enumerate(argv):
        if arg == flag and index + 1 < len(argv):
            values.append(argv[index + 1])
        elif str(arg).startswith(f"{flag}="):
            values.append(str(arg)[len(flag) + 1 :])
    return values


def _recorded_argv(scanner, target: Path) -> list[str]:
    """The argv ``scanner.scan`` hands the tool, which is never started."""
    recorded: list[list[str]] = []

    def _record(*args, **kwargs):
        recorded.append(list(kwargs.get("command") or args[0]))
        raise _Stop

    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_record),
    ):
        with pytest.raises((_Stop, ScannerError)):
            scanner.scan(target=target, target_type="source")
    assert recorded, "the tool was not started"
    return recorded[0]


# ---------------------------------------------------------------------------
# Every registered scanner is accounted for
# ---------------------------------------------------------------------------


def _registered_scanner_names() -> set[str]:
    names = set()
    for path in PLUGIN_MODULES.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "@ash_scanner_plugin" not in text:
            continue
        names.update(re.findall(r'name: Literal\["([^"]+)"\] = "', text))
    return names


def test_every_registered_scanner_has_a_link_handling():
    assert _registered_scanner_names() == set(LINK_HANDLING)


# ---------------------------------------------------------------------------
# grype and syft
# ---------------------------------------------------------------------------

LINKS = {
    "link_out.txt": "outside/requirements.txt",
    "deep/requirements.txt": "outside/requirements.txt",
    "l[1]{a,b}*?.txt": "outside/requirements.txt",
    "back\\slash.txt": "outside/requirements.txt",
    "in_tree.txt": "real/requirements.txt",
}
FILES = {"requirements.txt": "six==1.0.0\n", "real/requirements.txt": "idna==2.0\n"}
DOUBLESTAR_EXCLUDES = {
    "./link_out.txt",
    "./deep/requirements.txt",
    "./l\\[1\\]\\{a,b\\}\\*\\?.txt",
    "./back\\\\slash.txt",
}


def test_grype_is_given_each_link_leaving_its_target_and_nothing_else(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    source = _tree(tmp_path, FILES, LINKS)
    scanner = GrypeScanner(
        context=_context(source, tmp_path), config=GrypeScannerConfig()
    )
    before = [(a.key, a.value) for a in scanner.args.extra_args]

    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert set(_values(argv, "--exclude")) == DOUBLESTAR_EXCLUDES
    # For this resolution only: the next target has links of its own.
    assert [(a.key, a.value) for a in scanner.args.extra_args] == before


def _scanner_named(name: str, source: Path, base: Path):
    if name == "grype":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner as scanner_class,
            GrypeScannerConfig as config_class,
        )
    elif name == "checkov":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner as scanner_class,
            CheckovScannerConfig as config_class,
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner as scanner_class,
            BanditScannerConfig as config_class,
        )
    return scanner_class(context=_context(source, base), config=config_class())


@pytest.mark.parametrize("name", ["grype", "checkov", "bandit"])
def test_the_list_extra_args_held_is_left_as_it_was(tmp_path, name):
    """The per-target entries go into a new list, not the one extra_args held.

    Code holding that list (a caller, a test) saw the link entries appended to it,
    even though extra_args itself was set back to a copy afterwards. And extra_args
    is that same list again after the resolution, not a copy of it.
    """
    # No glob character in a link name: bandit refuses a target with one.
    source = _tree(
        tmp_path,
        {**FILES, "main.tf": "", "app.py": "x = 1\n"},
        {
            "link_out.txt": "outside/requirements.txt",
            "deep/requirements.txt": "outside/requirements.txt",
            "link_out.tf": "outside/main.tf",
            "link_out.py": "outside/secret.py",
            "in_tree.txt": "real/requirements.txt",
        },
    )
    scanner = _scanner_named(name, source, tmp_path)
    held = scanner.args.extra_args
    before = [(a.key, a.value) for a in held]

    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert [(a.key, a.value) for a in held] == before
    assert scanner.args.extra_args is held
    # And the per-target entries did reach this resolution.
    assert any("link_out" in str(arg) for arg in argv)


@pytest.mark.parametrize("name", ["grype", "checkov", "bandit"])
def test_a_target_with_no_link_leaving_it_leaves_the_list_as_it_was(tmp_path, name):
    """The entries every resolution adds (bandit's --ini, grype's --config) too.

    With no link to leave out, the list extra_args held was the one these were
    added to, and as that list is the one put back, each scan added one more.
    """
    source = _tree(tmp_path, {**FILES, "main.tf": "", "app.py": "x = 1\n"}, {})
    scanner = _scanner_named(name, source, tmp_path)
    held = scanner.args.extra_args
    before = [(a.key, a.value) for a in held]

    first, _, _ = scanner._execute_scan(source, "source", [])
    second, _, _ = scanner._execute_scan(source, "source", [])

    assert [(a.key, a.value) for a in held] == before
    assert scanner.args.extra_args is held
    # The same options again; an empty config file's path is new each time.
    assert len(second) == len(first)
    assert [arg for arg in second if str(arg).startswith("-")] == [
        arg for arg in first if str(arg).startswith("-")
    ]


def test_syft_is_given_each_link_leaving_its_target_and_nothing_else(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
        SyftScannerConfig,
    )

    source = _tree(tmp_path, FILES, LINKS)
    scanner = SyftScanner(
        context=_context(source, tmp_path), config=SyftScannerConfig()
    )

    argv = _recorded_argv(scanner, source)

    assert set(_values(argv, "--exclude")) == DOUBLESTAR_EXCLUDES


def test_the_operators_syft_excludes_are_kept_beside_them(tmp_path):
    from automated_security_helper.models.core import IgnorePathWithReason
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScanner,
        SyftScannerConfig,
        SyftScannerConfigOptions,
    )

    source = _tree(tmp_path, FILES, {"link_out.txt": "outside/requirements.txt"})
    config = SyftScannerConfig(
        options=SyftScannerConfigOptions(
            exclude=[IgnorePathWithReason(path="./vendor/**", reason="vendored")]
        )
    )
    scanner = SyftScanner(context=_context(source, tmp_path), config=config)

    argv = _recorded_argv(scanner, source)

    assert sorted(_values(argv, "--exclude")) == ["./link_out.txt", "./vendor/**"]


# ---------------------------------------------------------------------------
# trivy
# ---------------------------------------------------------------------------


def test_trivy_is_given_each_link_leaving_its_target_without_a_comma(
    tmp_path, monkeypatch
):
    from automated_security_helper.plugin_modules.ash_trivy_plugins import (
        trivy_repo_scanner,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setattr(trivy_repo_scanner, "sandboxed_online", lambda offline: False)
    source = _tree(
        tmp_path,
        FILES,
        {
            "link_out.txt": "outside/requirements.txt",
            "deep/config.yml": "outside/config.yml",
            "we[1]*?{x}.txt": "outside/requirements.txt",
            "co,mma.txt": "outside/requirements.txt",
            "in_tree.txt": "real/requirements.txt",
        },
    )
    scanner = trivy_repo_scanner.TrivyRepoScanner(
        context=_context(source, tmp_path),
        config=trivy_repo_scanner.TrivyRepoScannerConfig(),
    )

    argv = _recorded_argv(scanner, source)

    assert set(_values(argv, "--skip-files")) == {
        "link_out.txt",
        "deep/config.yml",
        "we\\[1\\]\\*\\?\\{x\\}.txt",
    }


def test_a_link_trivy_cannot_be_given_is_logged_once(tmp_path):
    """A link left out of --skip-files is named in one debug record, not dropped silently."""
    from automated_security_helper.utils import link_exclusions
    from automated_security_helper.utils.log import ASH_LOGGER

    source = _tree(
        tmp_path,
        FILES,
        {
            "link_out.txt": "outside/requirements.txt",
            "co,mma.txt": "outside/requirements.txt",
            'quo"te.txt': "outside/requirements.txt",
            "line\nbreak.txt": "outside/requirements.txt",
        },
    )

    with patch.object(ASH_LOGGER, "debug") as debug:
        values = link_exclusions.trivy_skip_files(source)

    assert values == ["link_out.txt"]
    assert debug.call_count == 1
    args = debug.call_args.args
    message = args[0] % args[1:]
    for left_out in ("co,mma.txt", 'quo"te.txt', "line\nbreak.txt"):
        assert repr(left_out) in message
    assert "'link_out.txt'" not in message


def test_nothing_is_logged_when_every_link_can_be_given_to_trivy(tmp_path):
    from automated_security_helper.utils import link_exclusions
    from automated_security_helper.utils.log import ASH_LOGGER

    source = _tree(tmp_path, FILES, {"link_out.txt": "outside/requirements.txt"})

    with patch.object(ASH_LOGGER, "debug") as debug:
        assert link_exclusions.trivy_skip_files(source) == ["link_out.txt"]

    debug.assert_not_called()


# ---------------------------------------------------------------------------
# semgrep and opengrep
# ---------------------------------------------------------------------------


@pytest.fixture(params=["semgrep", "opengrep"])
def grep_scanner_class(request):
    if request.param == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner,
            SemgrepScannerConfig,
        )

        return SemgrepScanner, SemgrepScannerConfig
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
        OpengrepScannerConfig,
    )

    return OpengrepScanner, OpengrepScannerConfig


def _added_excludes(scanner, source: Path) -> list[str]:
    """The ``--exclude`` values the scan adds to the scanner's configured ones."""
    configured = [a.value for a in scanner.args.extra_args if a.key == "--exclude"]
    argv, _, _ = scanner._execute_scan(source, "source", [])
    added = list(_values(argv, "--exclude"))
    for value in configured:
        added.remove(value)
    return added


def test_a_grep_scanner_is_given_no_link_exclusion(
    tmp_path, monkeypatch, grep_scanner_class
):
    """semgrep and opengrep follow no link, and their --exclude cannot name one path.

    A link's name was passed when nothing else below the target had it. semgrep
    matches that name against paths below its project root, the git work tree's
    root, so a name that is also one of the target's own directories hid the whole
    target (54 results down to 0, measured with semgrep 1.180.0).
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner_class, config_class = grep_scanner_class
    source = _tree(
        tmp_path,
        {"app.py": "x = 1\n"},
        {
            "link_out.py": "outside/secret.py",
            "deep/vendor_conf.yml": "outside/config.yml",
            "dir_out": "outside",
            "in_tree.py": "app.py",
        },
    )
    scanner = scanner_class(context=_context(source, tmp_path), config=config_class())
    before = [(a.key, a.value) for a in scanner.args.extra_args]

    assert _added_excludes(scanner, source) == []
    assert [(a.key, a.value) for a in scanner.args.extra_args] == before


def test_a_link_named_like_the_targets_own_directory_does_not_hide_it(
    tmp_path, monkeypatch, grep_scanner_class
):
    """The target is a directory inside a git work tree, as a workspace project is."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    scanner_class, config_class = grep_scanner_class
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git("init", "-q", str(repo), check=True)
    project = repo / "proj"
    (project / "sub").mkdir(parents=True)
    (project / "real.py").write_text("x = 1\n", encoding="utf-8")
    (project / "sub" / "proj").symlink_to(tmp_path / "elsewhere" / "proj")
    scanner = scanner_class(context=_context(project, tmp_path), config=config_class())

    added = _added_excludes(scanner, project)

    assert "proj" not in added
    assert added == []


# ---------------------------------------------------------------------------
# snyk-code
# ---------------------------------------------------------------------------


def _snyk(source: Path, base: Path, monkeypatch):
    from automated_security_helper.plugin_modules.ash_snyk_plugins import (
        snyk_code_scanner,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    return snyk_code_scanner.SnykCodeScanner(
        context=_context(source, base),
        config=snyk_code_scanner.SnykCodeScannerConfig(),
    )


def test_snyk_code_does_not_scan_a_target_with_a_link_leaving_it(tmp_path, monkeypatch):
    source = _tree(
        tmp_path,
        {"app.py": "x = 1\n"},
        {"config.yml": "outside/config.yml", "in_tree.py": "app.py"},
    )
    scanner = _snyk(source, tmp_path, monkeypatch)
    scanner.dependencies_satisfied = True

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess") as run,
    ):
        with pytest.raises(ScannerError) as refused:
            scanner.scan(target=source, target_type="source")

    run.assert_not_called()
    assert "'config.yml'" in str(refused.value)
    assert "link leaves the scanned tree" in str(refused.value)


@pytest.mark.parametrize(
    "link",
    ["creds", "deep/aws"],
    ids=["top-level", "nested"],
)
def test_snyk_code_does_not_scan_a_target_with_a_directory_link_leaving_it(
    tmp_path, monkeypatch, link
):
    """A link to a directory outside, such as one pointing at ~/.aws.

    snyk might upload every file below it, and the walk that finds file links does
    not enter directory links, so these were not refused.
    """
    source = _tree(tmp_path, {"app.py": "x = 1\n"}, {link: "outside"})
    scanner = _snyk(source, tmp_path, monkeypatch)
    scanner.dependencies_satisfied = True

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess") as run,
    ):
        with pytest.raises(ScannerError) as refused:
            scanner.scan(target=source, target_type="source")

    run.assert_not_called()
    assert repr(link) in str(refused.value)
    assert "link leaves the scanned tree" in str(refused.value)


def test_snyk_code_still_scans_a_target_whose_links_stay_inside(tmp_path, monkeypatch):
    source = _tree(
        tmp_path,
        {"app.py": "x = 1\n", "real/x.py": "y = 2\n"},
        {"in_tree.py": "app.py", "dir_in": "real"},
    )
    scanner = _snyk(source, tmp_path, monkeypatch)

    argv = _recorded_argv(scanner, source)

    assert argv[:3] == ["snyk", "code", "test"]
