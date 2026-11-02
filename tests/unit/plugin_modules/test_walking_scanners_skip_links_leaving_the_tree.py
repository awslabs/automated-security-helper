# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every scanner that walks its target itself is kept off links that leave it.

ASH's scan set leaves out a link to a file whose target leaves the scanned tree, but
only detect-secrets, cfn-nag, cdk-nag, npm-audit, actionlint, zizmor, cfn-lint and
cfn-guard read the scan set. Every other scanner is handed a directory and walks
it. bandit, checkov and ferret-scan are covered in their own tests
(test_scanners_skip_links_leaving_the_tree.py and the ferret one). This covers the rest, and pins that every registered scanner is one of
the kinds below, so a new one cannot be added without deciding which:

- grype and syft follow no link leaving their target (measured with grype 0.120.1
  and syft 1.54.1). Each link is still passed in ``--exclude``, as ``./<path>`` with
  the glob characters escaped, which leaves out that path and no other.
- trivy (the trivy and trivy-repo scanners) skips every link (measured with trivy
  0.75.0). Each link is passed in ``--skip-files`` with the glob characters escaped;
  a path with a comma is not, because trivy splits the value on commas.
- gitleaks runs ``gitleaks dir`` without ``--follow-symlinks``, so it reads no link.
- semgrep and opengrep skip every link (measured with semgrep 1.180.0 and opengrep
  1.30.2), and their ``--exclude`` cannot name one path: semgrep matches a pattern
  against paths below the git work tree's root when the target is inside one, and
  opengrep matches a top-level name at every depth. So no link is passed: a name
  that nothing else below the target has can still be one of the target's own
  directories, and passing it would leave out the whole target.
- snyk-code uploads what it reads and has no option that leaves out one path, so it
  does not run on a target that holds a link leaving it, to a file or to a
  directory: the scan is an error that names the link. Past that refusal it tests a
  copy of the scan set (``_stage_source``), made through ``open_in_scanned_tree``,
  which copies no link. A file link leaving the target is not in the scan set, a
  directory link is not descended, and a link the scan set keeps is refused by the
  copy: nothing a link leads to reaches what snyk reads. The refusal is checked
  here for every kind of link, and the copy alone in the cells at the end, with the
  refusal set aside.
"""

from __future__ import annotations

import contextlib
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

#: Its inputs are ASH's scan set, which leaves the link out.
READS_THE_SCAN_SET = "reads the scan set"
#: Its command names the link in its exclusion option. bandit, checkov and
#: ferret-scan read such a link, and refuse the target when the option cannot carry
#: its name (test_scanners_skip_links_leaving_the_tree.py and the ferret test);
#: grype, syft and trivy follow none, and are given it all the same.
EXCLUDES_THE_LINK = "names the link in its exclusion option"
#: It follows no link, and its command names none.
FOLLOWS_NO_LINK = "follows no link and is given no exclusion"
#: It is not run on a target that holds such a link, and otherwise on a copy of the
#: scan set that holds no link.
REFUSES_THE_TARGET = "refuses a target holding the link"

#: How each registered scanner is kept off a link that leaves its target, which
#: test_each_scanners_link_handling_holds checks for each of them.
LINK_HANDLING = {
    "detect-secrets": READS_THE_SCAN_SET,
    "cfn-nag": READS_THE_SCAN_SET,
    "cdk-nag": READS_THE_SCAN_SET,
    "npm-audit": READS_THE_SCAN_SET,
    "actionlint": READS_THE_SCAN_SET,
    "zizmor": READS_THE_SCAN_SET,
    # Through utils/cfn_template_discovery.py.
    "cfn-lint": READS_THE_SCAN_SET,
    "cfn-guard": READS_THE_SCAN_SET,
    "bandit": EXCLUDES_THE_LINK,
    "checkov": EXCLUDES_THE_LINK,
    "ferret-scan": EXCLUDES_THE_LINK,
    "grype": EXCLUDES_THE_LINK,
    "syft": EXCLUDES_THE_LINK,
    "trivy-repo": EXCLUDES_THE_LINK,
    "trivy": EXCLUDES_THE_LINK,
    "semgrep": FOLLOWS_NO_LINK,
    "opengrep": FOLLOWS_NO_LINK,
    # `gitleaks dir` runs without --follow-symlinks.
    "gitleaks": FOLLOWS_NO_LINK,
    "snyk-code": REFUSES_THE_TARGET,
}

_SCANNERS = "automated_security_helper.plugin_modules"
#: Where each registered scanner's class and config class live.
SCANNER_CLASSES = {
    "bandit": ("ash_builtin.scanners.bandit_scanner", "BanditScanner", "Bandit"),
    "cdk-nag": ("ash_builtin.scanners.cdk_nag_scanner", "CdkNagScanner", "CdkNag"),
    "cfn-nag": ("ash_builtin.scanners.cfn_nag_scanner", "CfnNagScanner", "CfnNag"),
    "checkov": (
        "ash_builtin.scanners.checkov_scanner",
        "CheckovScanner",
        "Checkov",
    ),
    "detect-secrets": (
        "ash_builtin.scanners.detect_secrets_scanner",
        "DetectSecretsScanner",
        "DetectSecrets",
    ),
    "grype": ("ash_builtin.scanners.grype_scanner", "GrypeScanner", "Grype"),
    "npm-audit": (
        "ash_builtin.scanners.npm_audit_scanner",
        "NpmAuditScanner",
        "NpmAudit",
    ),
    "opengrep": (
        "ash_builtin.scanners.opengrep_scanner",
        "OpengrepScanner",
        "Opengrep",
    ),
    "semgrep": (
        "ash_builtin.scanners.semgrep_scanner",
        "SemgrepScanner",
        "Semgrep",
    ),
    "syft": ("ash_builtin.scanners.syft_scanner", "SyftScanner", "Syft"),
    "ferret-scan": (
        "ash_ferret_plugins.ferret_scanner",
        "FerretScanScanner",
        "Ferret",
    ),
    "snyk-code": (
        "ash_snyk_plugins.snyk_code_scanner",
        "SnykCodeScanner",
        "SnykCode",
    ),
    "trivy-repo": (
        "ash_trivy_plugins.trivy_repo_scanner",
        "TrivyRepoScanner",
        "TrivyRepo",
    ),
    "trivy": ("ash_builtin.scanners.trivy_scanner", "TrivyScanner", "Trivy"),
    "actionlint": (
        "ash_builtin.scanners.actionlint_scanner",
        "ActionlintScanner",
        "Actionlint",
    ),
    "zizmor": ("ash_builtin.scanners.zizmor_scanner", "ZizmorScanner", "Zizmor"),
    "cfn-lint": (
        "ash_builtin.scanners.cfn_lint_scanner",
        "CfnLintScanner",
        "CfnLint",
    ),
    "cfn-guard": (
        "ash_builtin.scanners.cfn_guard_scanner",
        "CfnGuardScanner",
        "CfnGuard",
    ),
    "gitleaks": (
        "ash_builtin.scanners.gitleaks_scanner",
        "GitleaksScanner",
        "Gitleaks",
    ),
}
#: Where the scanners that take their inputs from utils/cfn_template_discovery.py
#: call scan_set, which their own module does not.
_SCAN_SET_MODULE = {
    "cfn-lint": "automated_security_helper.utils.cfn_template_discovery",
    "cfn-guard": "automated_security_helper.utils.cfn_template_discovery",
}
#: The scanners whose own scan() resolves the command, rather than the template
#: scan() calling _execute_scan.
_OWN_SCAN = {"syft", "trivy-repo", "ferret-scan", "snyk-code"}


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


def _what_snyk_reads(scanner, target: Path) -> dict:
    """The copy the stand-in snyk is given, read while it exists: each regular file
    with its bytes, and each link."""
    seen: dict = {}

    def _record(*args, **kwargs):
        command = [str(arg) for arg in (kwargs.get("command") or args[0])]
        tested = Path(next(arg for arg in command[3:] if not arg.startswith("-")))
        entries = sorted(tested.rglob("*"))
        seen["files"] = {
            path.relative_to(tested).as_posix(): path.read_bytes()
            for path in entries
            if path.is_file() and not path.is_symlink()
        }
        seen["links"] = [
            path.relative_to(tested).as_posix() for path in entries if path.is_symlink()
        ]
        raise _Stop

    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_record),
    ):
        with pytest.raises((_Stop, ScannerError)):
            scanner.scan(target=target, target_type="source")
    assert seen, "snyk was not started"
    return seen


def _snyk_refusal(scanner, target: Path) -> str:
    """What snyk-code says when it refuses ``target``; snyk is not started."""
    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_Stop) as run,
    ):
        with pytest.raises(ScannerError) as refused:
            scanner.scan(target=target, target_type="source")
    run.assert_not_called()
    return str(refused.value)


def _no_outside_bytes(files: dict) -> None:
    """No file in the copy holds what a file outside the tree holds."""
    assert not [name for name, data in files.items() if b"# outside" in data], files


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


@pytest.mark.unit
def test_every_registered_scanner_has_a_link_handling():
    assert _registered_scanner_names() == set(LINK_HANDLING) == set(SCANNER_CLASSES)


def _scanner_for(name: str, source: Path, base: Path):
    import importlib

    module_name, class_name, config_prefix = SCANNER_CLASSES[name]
    module = importlib.import_module(f"{_SCANNERS}.{module_name}")
    scanner_class = getattr(module, class_name)
    config_class = getattr(module, f"{config_prefix}ScannerConfig")
    return module, scanner_class(context=_context(source, base), config=config_class())


#: Links that leave the tree, one for each kind of file a scanner reads; every name
#: holds "link_out", which no other path in the tree or its argv does.
HANDLING_LINKS = {
    "link_out.py": "outside/secret.py",
    "link_out.tf": "outside/main.tf",
    "link_out.txt": "outside/requirements.txt",
    "link_out.yml": "outside/config.yml",
}
HANDLING_FILES = {
    "app.py": "x = 1\n",
    "main.tf": "",
    "requirements.txt": "six==1.0.0\n",
    "settings.yml": "a: 1\n",
}


@pytest.mark.parametrize("name", sorted(LINK_HANDLING))
@pytest.mark.unit
def test_each_scanners_link_handling_holds(tmp_path, monkeypatch, name):
    """What LINK_HANDLING says of each scanner, checked on a tree with such links."""
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")
    if name in ("trivy-repo", "trivy"):
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            _trivy_scanner_base,
        )

        # No database update: the recorder replaces the run that would make one.
        monkeypatch.setattr(
            _trivy_scanner_base, "prepare_content_db", lambda *args, **kwargs: None
        )
    source = _tree(tmp_path, HANDLING_FILES, HANDLING_LINKS)
    module, scanner = _scanner_for(name, source, tmp_path)
    handling = LINK_HANDLING[name]

    if handling == READS_THE_SCAN_SET:
        import importlib

        seen: list[list[str]] = []
        # A scanner that does not import scan_set itself reads it through a helper
        # that imports it when called (cfn-nag and cdk-nag, through
        # cfn_template_model.cloudformation_candidate_files): spy on it there.
        # cfn-lint and cfn-guard read it through utils/cfn_template_discovery
        # (_SCAN_SET_MODULE).
        from automated_security_helper.utils import get_scan_set as get_scan_set_module

        if name in _SCAN_SET_MODULE:
            reads_from = importlib.import_module(_SCAN_SET_MODULE[name])
        elif hasattr(module, "scan_set"):
            reads_from = module
        else:
            reads_from = get_scan_set_module
        real = reads_from.scan_set

        def _spy(*args, **kwargs):
            seen.append([str(path) for path in real(*args, **kwargs)])
            raise _Stop

        scanner.dependencies_satisfied = True
        with (
            patch.object(reads_from, "scan_set", side_effect=_spy),
            patch.object(scanner, "_pre_scan", return_value=True),
            patch.object(scanner, "_post_scan"),
            patch.object(scanner, "_run_subprocess", side_effect=_Stop),
            # cfn-guard's rules come from an installed bundle, which the scan
            # reads before its templates; no rule is needed to reach them.
            (
                patch.object(scanner, "_selected_rules", return_value=[])
                if name == "cfn-guard"
                else contextlib.nullcontext()
            ),
        ):
            try:
                scanner.scan(target=source, target_type="source")
            except (_Stop, ScannerError):
                pass
        assert seen, f"{name} did not take its inputs from the scan set"
        assert any(path.endswith("/app.py") for path in seen[0]), seen[0]
        assert not [path for path in seen[0] if "link_out" in path]
        return

    if handling == REFUSES_THE_TARGET:
        refusal = _snyk_refusal(scanner, source)
        assert "'link_out.py'" in refusal, refusal
        assert "link leaves the scanned tree" in refusal, refusal
        return

    if name in _OWN_SCAN:
        argv = _recorded_argv(scanner, source)
    else:
        argv, _, _ = scanner._execute_scan(source, "source", [])
    naming_the_link = [str(arg) for arg in argv if "link_out" in str(arg)]
    if handling == EXCLUDES_THE_LINK:
        assert naming_the_link, argv
    else:
        assert handling == FOLLOWS_NO_LINK
        assert naming_the_link == [], argv


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


@pytest.mark.unit
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
@pytest.mark.unit
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


@pytest.mark.unit
def test_grypes_own_resolution_leaves_the_list_it_holds_as_it_was(tmp_path):
    """grype's _resolve_arguments adds an --exclude per ASH output directory inside
    the target, for that resolution only, in a new list: the one extra_args held is
    left as it was and is extra_args again afterwards."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    source = _tree(tmp_path, {**FILES}, {})
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = GrypeScanner(context=context, config=GrypeScannerConfig())
    held = scanner.args.extra_args
    before = [(a.key, a.value) for a in held]

    argv = scanner._resolve_arguments(
        target=f"dir:{source.as_posix()}", results_file=tmp_path / "r.sarif"
    )

    assert [(a.key, a.value) for a in held] == before
    assert scanner.args.extra_args is held
    # And the output directory's exclude did reach this resolution.
    assert any(".ash" in str(arg) for arg in _values(argv, "--exclude")), argv


@pytest.mark.parametrize("name", ["grype", "checkov", "bandit"])
@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.parametrize("scanner_name", ["trivy-repo", "trivy"])
@pytest.mark.unit
def test_trivy_is_given_each_link_leaving_its_target_without_a_comma(
    tmp_path, monkeypatch, scanner_name
):
    """Both trivy scanners build their argv in the shared base's terms."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _trivy_scanner_base,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
        TrivyScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins import (
        trivy_repo_scanner,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    # No database update: the recorder below replaces the run that would make one.
    monkeypatch.setattr(
        _trivy_scanner_base, "prepare_content_db", lambda *args, **kwargs: None
    )
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
    if scanner_name == "trivy":
        scanner = TrivyScanner(
            context=_context(source, tmp_path), config=TrivyScannerConfig()
        )
    else:
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


@pytest.mark.unit
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


@pytest.mark.unit
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
    """The ``--exclude`` values the scan adds to the scanner's configured ones.

    The configured ones take both forms: the tools' default ignore list as a split
    ``--exclude <pattern>`` pair, and the operator's patterns joined as
    ``--exclude=<pattern>`` (the key carries the value).
    """
    prefix = "--exclude="
    configured = []
    for arg in scanner.args.extra_args:
        if arg.key == "--exclude":
            configured.append(arg.value)
        elif str(arg.key).startswith(prefix):
            configured.append(str(arg.key)[len(prefix) :])
    argv, _, _ = scanner._execute_scan(source, "source", [])
    added = list(_values(argv, "--exclude"))
    for value in configured:
        added.remove(value)
    return added


@pytest.mark.unit
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


@pytest.mark.integration
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


@pytest.fixture
def snyk_refusals_set_aside(monkeypatch):
    """Run snyk-code's scan() without the refusals that come before the copy, so a
    cell can look at what the copy itself leaves out of a tree they would stop."""
    from automated_security_helper.plugin_modules.ash_snyk_plugins import (
        snyk_code_scanner,
    )

    for refusal in (
        "_refuse_output_dir_inside",
        "_refuse_links_leaving",
        "_refuse_ignored_files",
    ):
        monkeypatch.setattr(
            snyk_code_scanner.SnykCodeScanner,
            refusal,
            lambda self, *args, **kwargs: None,
        )


@pytest.mark.parametrize(
    "links, named",
    [
        ({"config.yml": "outside/config.yml"}, "config.yml"),
        ({"creds": "outside"}, "creds"),
        ({"deep/aws": "outside"}, "deep/aws"),
    ],
    ids=["file", "top-level directory", "nested directory"],
)
@pytest.mark.unit
def test_snyk_code_refuses_a_target_holding_a_link_leaving_it(
    tmp_path, monkeypatch, links, named
):
    """A link to a file, or to a directory such as one pointing at ~/.aws, whose
    target is outside the directory: snyk is not started and the error names it."""
    source = _tree(tmp_path, {"app.py": "x = 1\n"}, links)
    scanner = _snyk(source, tmp_path, monkeypatch)

    refusal = _snyk_refusal(scanner, source)

    assert f"'{named}': link leaves the scanned tree" in refusal, refusal


@pytest.mark.unit
def test_snyk_codes_copy_leaves_out_a_link_leaving_the_target(
    tmp_path, monkeypatch, snyk_refusals_set_aside
):
    """Nor a link inside it: snyk reads only the target's regular files."""
    source = _tree(
        tmp_path,
        {"app.py": "x = 1\n"},
        {"config.yml": "outside/config.yml", "in_tree.py": "app.py"},
    )
    scanner = _snyk(source, tmp_path, monkeypatch)

    read = _what_snyk_reads(scanner, source)

    assert sorted(read["files"]) == ["app.py"]
    assert read["links"] == []
    _no_outside_bytes(read["files"])


@pytest.mark.parametrize(
    "link",
    ["creds", "deep/aws"],
    ids=["top-level", "nested"],
)
@pytest.mark.unit
def test_snyk_codes_copy_holds_nothing_below_a_directory_link_leaving_it(
    tmp_path, monkeypatch, snyk_refusals_set_aside, link
):
    """A link to a directory outside, such as one pointing at ~/.aws.

    snyk might read every file below it. The scan set does not enter a directory
    link, so nothing below it is in the copy snyk is given.
    """
    source = _tree(tmp_path, {"app.py": "x = 1\n"}, {link: "outside"})
    scanner = _snyk(source, tmp_path, monkeypatch)

    read = _what_snyk_reads(scanner, source)

    assert sorted(read["files"]) == ["app.py"]
    assert read["links"] == []
    _no_outside_bytes(read["files"])


# The two guards the copy rests on, each pinned alone on the scan set's own output:
# the cells above go red only when both are off for a kind of link, since the copy
# (open_in_scanned_tree) refuses a link the scan set kept.


@pytest.mark.unit
def test_the_scan_set_snyk_code_copies_leaves_out_a_file_link_leaving_it(tmp_path):
    from automated_security_helper.utils.get_scan_set import scan_set

    source = _tree(
        tmp_path,
        {"app.py": "x = 1\n"},
        {"config.yml": "outside/config.yml", "in_tree.py": "app.py"},
    )

    files = scan_set(source=str(source), output=str(tmp_path / "ash-output"))

    assert sorted(Path(f).relative_to(source).as_posix() for f in files) == [
        "app.py",
        "in_tree.py",
    ]


@pytest.mark.unit
def test_the_scan_set_snyk_code_copies_does_not_enter_a_directory_link(tmp_path):
    """Not even one to a directory inside the tree, whose files all resolve inside
    it: so nothing below a directory link reaches the copy by the scan set."""
    from automated_security_helper.utils.get_scan_set import scan_set

    source = _tree(
        tmp_path,
        {"app.py": "x = 1\n", "real/x.py": "y = 2\n"},
        {"alias": "real", "creds": "outside"},
    )

    files = scan_set(source=str(source), output=str(tmp_path / "ash-output"))

    assert sorted(Path(f).relative_to(source).as_posix() for f in files) == [
        "app.py",
        "real/x.py",
    ]


@pytest.mark.unit
def test_snyk_code_still_scans_a_target_whose_links_stay_inside(tmp_path, monkeypatch):
    source = _tree(
        tmp_path,
        {"app.py": "x = 1\n", "real/x.py": "y = 2\n"},
        {"in_tree.py": "app.py", "dir_in": "real"},
    )
    scanner = _snyk(source, tmp_path, monkeypatch)

    argv = _recorded_argv(scanner, source)

    assert argv[:3] == ["snyk", "code", "test"]
