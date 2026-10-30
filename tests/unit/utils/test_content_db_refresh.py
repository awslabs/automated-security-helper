# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""grype's and trivy's databases are updated outside the sandbox, before the scan.

A scanner sandbox mounts their caches read-only, so neither can update its own
database there: measured, trivy failed online once its database was past
NextUpdate and grype once its database was past its age bound. ASH updates the
database first, unsandboxed and isolated from the scanned repository, and the
scanner then runs with its update turned off. See utils/content_db_refresh.py.
"""

import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.base import scanner_plugin
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import in_scanned_tree
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.utils import content_db_refresh as refresh
from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils.sandbox import SandboxRequirements
from automated_security_helper.utils.sandbox.backends import BACKENDS
from automated_security_helper.utils.sandbox.scope import (
    SandboxScope,
    active_scope,
    sandbox_scope,
)
from tests.utils.helpers import importing_this_checkout


#: The tools' own opt-outs of their database updates, which the refresh honors;
#: cleared so a developer's or a CI shell cannot change what these tests see
#: (GRYPE_DB_AUTO_UPDATE=false is a common grype-caching recipe, and read as it
#: is, it left every grype refresh here out, so the grype cases saw no call).
_TOOL_UPDATE_OPT_OUT_ENV = (
    "TRIVY_SKIP_DB_UPDATE",
    "TRIVY_SKIP_UPDATE",
    "TRIVY_SKIP_JAVA_DB_UPDATE",
    "GRYPE_DB_AUTO_UPDATE",
)


@pytest.fixture(autouse=True)
def _fresh_memo(monkeypatch):
    for name in _TOOL_UPDATE_OPT_OUT_ENV:
        monkeypatch.delenv(name, raising=False)
    refresh.forget_prepared()
    yield
    refresh.forget_prepared()


def _scope(tmp_path) -> SandboxScope:
    return SandboxScope(
        backend=object(),
        scanner_name="grype",
        requirements=SandboxRequirements(),
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        results_dir=tmp_path / "out" / "scanners" / "grype",
        scan_target=tmp_path,
        offline=False,
    )


def _where(tmp_path) -> dict:
    """Where the scan is, for prepare_content_db to place the tools outside it."""
    return {
        "source_dir": tmp_path / "src",
        "results_dir": tmp_path / "out" / "scanners" / "grype",
    }


class _Recorder:
    """Stands in for spawn_run and records each call as the tool would see it."""

    def __init__(self, returncode=0, stderr=""):
        self.calls = []
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv, **kwargs):
        config = Path(argv[argv.index("-c" if "-c" in argv else "--config") + 1])
        self.calls.append(
            SimpleNamespace(
                argv=list(argv),
                cwd=Path(kwargs["cwd"]),
                env=dict(kwargs["env"]),
                scope=active_scope(),
                config_text=config.read_text(),
                last_is_empty_dir=Path(argv[-1]).is_dir()
                and not any(Path(argv[-1]).iterdir()),
            )
        )
        return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(refresh, "spawn_run", rec)
    # The recorder stands in for the tool, so the tool need not be installed: the
    # CI unit-test runner has neither grype nor trivy, and a scanner's refresh
    # looks its tool up before it spawns anything.
    monkeypatch.setattr(refresh, "find_executable", lambda tool: tool)
    return rec


@pytest.mark.unit
def test_a_tool_that_is_not_installed_is_an_error(monkeypatch, tmp_path):
    monkeypatch.setattr(refresh, "find_executable", lambda tool: None)
    with pytest.raises(ScannerError, match="grype is not installed"):
        refresh.prepare_content_db("grype", tmp_path, offline=False, **_where(tmp_path))


@pytest.mark.unit
def test_offline_nothing_runs(recorder, tmp_path):
    refresh.prepare_content_db(
        "grype", tmp_path, offline=True, **_where(tmp_path), executable="grype"
    )
    refresh.prepare_content_db(
        "trivy", tmp_path, offline=True, **_where(tmp_path), executable="trivy"
    )
    assert recorder.calls == []


@pytest.mark.unit
def test_grype_is_updated_outside_the_sandbox_and_away_from_the_repo(
    recorder, tmp_path
):
    cache = tmp_path / "grype-db"
    with sandbox_scope(_scope(tmp_path)):
        refresh.prepare_content_db(
            "grype", cache, offline=False, **_where(tmp_path), executable="grype"
        )
        # The caller's sandbox is back once the refresh is done.
        assert isinstance(active_scope(), SandboxScope)
    (call,) = recorder.calls
    assert call.scope is None, "the update ran inside the scanner sandbox"
    assert call.argv[:3] == ["grype", "db", "update"]
    assert call.argv[3] == "-c" and call.config_text == ""
    assert call.env["GRYPE_DB_CACHE_DIR"] == cache.as_posix()
    # pytest runs from this checkout: the update must not, so no .grype.yaml in
    # a working directory can reach it.
    assert call.cwd != Path.cwd()
    assert not any((p / ".git").exists() for p in [call.cwd, *call.cwd.parents])


@pytest.mark.unit
@pytest.mark.parametrize("tool", ["grype", "trivy"])
def test_a_temporary_directory_inside_a_checkout_is_not_the_working_directory(
    recorder, tmp_path, monkeypatch, tool
):
    """When the temporary directory is inside a checkout, the update runs from the
    filesystem root instead, so no config file the checkout holds can be found."""
    checkout = tmp_path / "checkout"
    (checkout / ".git").mkdir(parents=True)
    (checkout / "tmp").mkdir()
    monkeypatch.setattr(refresh.tempfile, "tempdir", str(checkout / "tmp"))
    # Not vacuous: the update's scratch directory is made inside the checkout.
    assert checkout in Path(refresh.tempfile.gettempdir()).parents
    refresh.prepare_content_db(
        tool, tmp_path / "cache", offline=False, **_where(tmp_path), executable=tool
    )
    (call,) = recorder.calls
    config = Path(
        call.argv[call.argv.index("-c" if tool == "grype" else "--config") + 1]
    )
    # The config is the empty one ASH ships, not a file in the checkout.
    assert config == refresh.EMPTY_TOOL_CONFIG
    assert not any((p / ".git").exists() for p in [call.cwd, *call.cwd.parents])
    assert call.cwd == Path(call.cwd.anchor)


@pytest.mark.unit
def test_trivy_gets_its_database_and_when_asked_its_checks_bundle(recorder, tmp_path):
    cache = tmp_path / "trivy"
    refresh.prepare_content_db(
        "trivy",
        cache,
        offline=False,
        checks=True,
        **_where(tmp_path),
        executable="trivy",
    )
    db, checks = recorder.calls
    for call in (db, checks):
        assert call.scope is None
        assert call.config_text == ""
        assert call.argv[call.argv.index("--cache-dir") + 1] == cache.as_posix()
        assert call.cwd != Path.cwd()
    assert db.argv[1:3] == ["image", "--download-db-only"]
    # trivy fetches its checks bundle by checking configuration; here, of nothing.
    assert checks.argv[1] == "config" and checks.last_is_empty_dir


@pytest.mark.unit
def test_trivy_takes_the_operators_config_when_given_one(recorder, tmp_path):
    """A database mirror in the operator's trivy.yaml applies to the update too."""
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text("db:\n  repository: mirror.example/trivy-db\n")
    refresh.prepare_content_db(
        "trivy",
        tmp_path / "trivy",
        offline=False,
        checks=True,
        **_where(tmp_path),
        executable="trivy",
        config_file=operator,
    )
    for call in recorder.calls:
        assert Path(call.argv[call.argv.index("--config") + 1]) == operator.absolute()
        assert "mirror.example" in call.config_text
        assert call.cwd != operator.parent
    # The operator's file is left where it is.
    assert operator.is_file()


@pytest.mark.unit
def test_grype_takes_the_operators_config_when_given_one(recorder, tmp_path):
    """A database mirror in the operator's grype config applies to the update too.

    The caller establishes that the file is the operator's and outside the scanned
    tree (the grype scanner passes one only then); given one, the update runs with
    it, and given none, with the empty config, never with a file from the tree.
    """
    operator = tmp_path / "operator" / "grype.yaml"
    operator.parent.mkdir()
    operator.write_text("db:\n  update-url: https://mirror.example/grype-db\n")
    refresh.prepare_content_db(
        "grype",
        tmp_path / "grype",
        offline=False,
        **_where(tmp_path),
        executable="grype",
        config_file=operator,
    )
    (call,) = recorder.calls
    assert Path(call.argv[call.argv.index("-c") + 1]) == operator.absolute()
    assert "mirror.example" in call.config_text
    assert call.cwd != operator.parent
    assert operator.is_file()
    refresh.forget_prepared()
    recorder.calls.clear()
    refresh.prepare_content_db(
        "grype",
        tmp_path / "grype",
        offline=False,
        **_where(tmp_path),
        executable="grype",
    )
    (call,) = recorder.calls
    assert Path(call.argv[call.argv.index("-c") + 1]) != operator.absolute()
    assert call.config_text == ""


@pytest.mark.unit
def test_without_checks_trivy_only_updates_its_database(recorder, tmp_path):
    refresh.prepare_content_db(
        "trivy", tmp_path, offline=False, **_where(tmp_path), executable="trivy"
    )
    assert [c.argv[1:3] for c in recorder.calls] == [["image", "--download-db-only"]]


@pytest.mark.unit
def test_the_java_database_is_updated_only_when_asked(recorder, tmp_path):
    """About 935 MiB, and only modes that analyze JAR, WAR and EAR files read it."""
    refresh.prepare_content_db(
        "trivy",
        tmp_path,
        offline=False,
        java=True,
        **_where(tmp_path),
        executable="trivy",
    )
    db, java = recorder.calls
    assert java.argv[1:3] == ["image", "--download-java-db-only"]
    assert java.scope is None and java.config_text == ""
    assert java.argv[java.argv.index("--cache-dir") + 1] == tmp_path.as_posix()
    refresh.prepare_content_db(
        "trivy",
        tmp_path,
        offline=True,
        java=True,
        **_where(tmp_path),
        executable="trivy",
    )
    assert len(recorder.calls) == 2, "offline, the Java database is not updated"


# --------------------------------------------------------------------------- #
# The operator's own opt-out of trivy's database update
#
# trivy refuses `--download-db-only` when its settings also say to skip the update
# ("--skip-db-update and --download-db-only cannot be specified together"), so the
# operator's opt-out is honored rather than failing every online scan. Each case's
# expectation is what trivy 0.75.0 itself did: a refusal means it reads the setting
# as "skip". Measured against the real binary, see the commit that added this.
# --------------------------------------------------------------------------- #


@pytest.mark.unit
@pytest.mark.parametrize(
    "env, skips",
    [
        ({"TRIVY_SKIP_DB_UPDATE": "true"}, True),
        ({"TRIVY_SKIP_DB_UPDATE": "TRUE"}, True),
        ({"TRIVY_SKIP_DB_UPDATE": "1"}, True),
        ({"TRIVY_SKIP_DB_UPDATE": "t"}, True),
        # strconv.ParseBool, which is how trivy reads it: neither is true.
        ({"TRIVY_SKIP_DB_UPDATE": "yes"}, False),
        ({"TRIVY_SKIP_DB_UPDATE": "false"}, False),
        # The deprecated --skip-update's variable, read after the flag's own.
        ({"TRIVY_SKIP_UPDATE": "true"}, True),
        ({"TRIVY_SKIP_DB_UPDATE": "", "TRIVY_SKIP_UPDATE": "true"}, True),
        ({"TRIVY_SKIP_DB_UPDATE": "false", "TRIVY_SKIP_UPDATE": "true"}, False),
        ({"TRIVY_SKIP_JAVA_DB_UPDATE": "true"}, False),
    ],
)
def test_an_operators_environment_can_turn_the_database_update_off(
    recorder, tmp_path, monkeypatch, env, skips
):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    refresh.prepare_content_db(
        "trivy",
        tmp_path,
        offline=False,
        checks=True,
        **_where(tmp_path),
        executable="trivy",
    )
    ran = [c.argv[1:3] for c in recorder.calls]
    assert (["image", "--download-db-only"] not in ran) is skips
    # The checks bundle has an opt-out of its own, which trivy applies itself.
    assert ran[-1][:1] == ["config"]


@pytest.mark.unit
@pytest.mark.parametrize(
    "config, skips",
    [
        ("db:\n  skip-update: true\n", True),
        ('db:\n  skip-update: "true"\n', True),
        ("db:\n  skip-update: 1\n", True),
        ("db:\n  skip-update: 2\n", True),
        ("db: {skip-update: true}\n", True),
        ("db.skip-update: true\n", True),
        ("DB:\n  Skip-Update: true\n", True),
        # yaml.v3 reads these as strings, which ParseBool rejects.
        ("db:\n  skip-update: yes\n", False),
        ('db:\n  skip-update: "2"\n', False),
        ("db:\n  skip-update: false\n", False),
        ("db:\n  skip-update:\n", False),
        ("skip-db-update: true\n", False),
        ("db:\n  repository: mirror.example/trivy-db\n", False),
    ],
)
def test_an_operators_trivy_config_can_turn_the_database_update_off(
    recorder, tmp_path, monkeypatch, config, skips
):
    operator = tmp_path / "operator" / "trivy.yaml"
    operator.parent.mkdir()
    operator.write_text(config)
    refresh.prepare_content_db(
        "trivy",
        tmp_path / "cache",
        offline=False,
        **_where(tmp_path),
        executable="trivy",
        config_file=operator,
    )
    assert (recorder.calls == []) is skips


@pytest.mark.unit
def test_the_environment_outranks_the_operators_config(recorder, tmp_path, monkeypatch):
    operator = tmp_path / "trivy.yaml"
    operator.write_text("db:\n  skip-update: true\n")
    monkeypatch.setenv("TRIVY_SKIP_DB_UPDATE", "false")
    refresh.prepare_content_db(
        "trivy",
        tmp_path / "cache",
        offline=False,
        **_where(tmp_path),
        executable="trivy",
        config_file=operator,
    )
    assert [c.argv[1:3] for c in recorder.calls] == [["image", "--download-db-only"]]


@pytest.mark.unit
def test_the_java_database_has_its_own_opt_out(recorder, tmp_path, monkeypatch):
    monkeypatch.setenv("TRIVY_SKIP_JAVA_DB_UPDATE", "true")
    refresh.prepare_content_db(
        "trivy",
        tmp_path,
        offline=False,
        java=True,
        **_where(tmp_path),
        executable="trivy",
    )
    assert [c.argv[1:3] for c in recorder.calls] == [["image", "--download-db-only"]]
    operator = tmp_path / "trivy.yaml"
    operator.write_text("db:\n  java-skip-update: true\n")
    monkeypatch.delenv("TRIVY_SKIP_JAVA_DB_UPDATE")
    refresh.forget_prepared()
    recorder.calls.clear()
    refresh.prepare_content_db(
        "trivy",
        tmp_path,
        offline=False,
        java=True,
        **_where(tmp_path),
        executable="trivy",
        config_file=operator,
    )
    assert [c.argv[1:3] for c in recorder.calls] == [["image", "--download-db-only"]]


@pytest.mark.unit
def test_a_skipped_update_is_logged_with_the_setting_that_skipped_it(
    recorder, tmp_path, monkeypatch, caplog
):
    monkeypatch.setenv("TRIVY_SKIP_DB_UPDATE", "true")
    with caplog.at_level("WARNING"):
        refresh.prepare_content_db(
            "trivy", tmp_path, offline=False, **_where(tmp_path), executable="trivy"
        )
    assert recorder.calls == []
    assert "TRIVY_SKIP_DB_UPDATE=true" in caplog.text
    assert "did not update" in caplog.text


@pytest.mark.unit
def test_once_per_scan(recorder, tmp_path):
    for _ in range(3):
        refresh.prepare_content_db(
            "grype",
            tmp_path,
            offline=False,
            scan_id="scan-1",
            **_where(tmp_path),
            executable="grype",
        )
    refresh.prepare_content_db(
        "grype",
        tmp_path,
        offline=False,
        scan_id="scan-2",
        **_where(tmp_path),
        executable="grype",
    )
    assert len(recorder.calls) == 2


@pytest.mark.unit
def test_a_failed_update_raises_with_the_tools_words_and_is_retried(
    monkeypatch, tmp_path
):
    failing = _Recorder(returncode=1, stderr="unable to download the database")
    monkeypatch.setattr(refresh, "spawn_run", failing)
    for _ in range(2):
        with pytest.raises(ScannerError, match="unable to download the database"):
            refresh.prepare_content_db(
                "grype",
                tmp_path,
                offline=False,
                scan_id="s",
                **_where(tmp_path),
                executable="grype",
            )
    assert len(failing.calls) == 2, "a failure must not count as prepared"


@pytest.mark.unit
def test_the_lock_lives_in_the_cache_or_beside_it(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    assert refresh.update_lock_path("trivy", cache) == cache / ".ash-trivy-update.lock"
    if os.name != "nt" and os.geteuid() != 0:
        cache.chmod(0o500)
        try:
            outside = refresh.update_lock_path("trivy", cache)
            assert outside.parent != cache
            assert outside.name.startswith("ash-trivy-update-")
        finally:
            cache.chmod(0o700)


# Each tool's own rule, written out from its source rather than derived from the code
# under test. grype 0.120.1: filepath.Join(xdg.CacheHome, "grype", "db")
# (grype/db/v6/installation/curator.go), and github.com/adrg/xdg v0.5.3 takes
# CacheHome from XDG_CACHE_HOME when it is absolute, else ~/Library/Caches on darwin
# (paths_darwin.go), ~/.cache on other Unix (paths_unix.go) and
# %LOCALAPPDATA%\cache on Windows (paths_windows.go). trivy 0.75.0:
# filepath.Join(os.UserCacheDir(), "trivy") (pkg/cache/dir.go), else os.TempDir();
# Go's os.UserCacheDir is $XDG_CACHE_HOME (an error when relative) or ~/.cache on
# Unix, ~/Library/Caches on darwin whatever XDG_CACHE_HOME says, and %LocalAppData%
# on Windows. trivy honoring XDG_CACHE_HOME on Linux, and both tools' variables and
# flags beating a config file, were measured with the binaries.
_POSIX_CASES = [
    # platform, XDG_CACHE_HOME, grype's cache, trivy's cache; "~" is HOME.
    ("linux", None, "~/.cache/grype/db", "~/.cache/trivy"),
    ("linux", "/xdg", "/xdg/grype/db", "/xdg/trivy"),
    # Measured: a relative XDG_CACHE_HOME is ignored by grype, and sends trivy to
    # os.TempDir() because os.UserCacheDir refuses it.
    ("linux", "rel/xdg", "~/.cache/grype/db", "$TMPDIR/trivy"),
    ("darwin", None, "~/Library/Caches/grype/db", "~/Library/Caches/trivy"),
    ("darwin", "/xdg", "/xdg/grype/db", "~/Library/Caches/trivy"),
]


@pytest.mark.unit
@pytest.mark.skipif(os.name == "nt", reason="POSIX paths")
@pytest.mark.parametrize("platform,xdg,grype,trivy", _POSIX_CASES)
def test_the_cache_is_where_the_tool_itself_looks(
    monkeypatch, tmp_path, platform, xdg, grype, trivy
):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    env = {"TMPDIR": str(tmp_path / "tmp")}
    if xdg is not None:
        env["XDG_CACHE_HOME"] = xdg if xdg.startswith("rel") else f"{tmp_path}{xdg}"

    def spelled(path: str) -> Path:
        if path.startswith("$TMPDIR/"):
            return Path(env["TMPDIR"]) / path[len("$TMPDIR/") :]
        if path.startswith("~/"):
            return home / path[2:]
        return Path(f"{tmp_path}{path}")

    for tool, expected in (("grype", grype), ("trivy", trivy)):
        assert refresh.default_cache_dir(tool, env, platform) == spelled(expected), tool


@pytest.mark.unit
def test_on_windows_the_cache_is_under_local_app_data(tmp_path):
    local = str(tmp_path / "Local")
    env = {"LocalAppData": local}  # Windows variable names are case-insensitive
    assert (
        refresh.default_cache_dir("grype", env, "win32")
        == Path(local) / "cache" / "grype" / "db"
    )
    assert refresh.default_cache_dir("trivy", env, "win32") == Path(local) / "trivy"
    xdg = "C:\\xdg"
    env["XDG_CACHE_HOME"] = xdg
    assert (
        refresh.default_cache_dir("grype", env, "win32") == Path(xdg) / "grype" / "db"
    )
    assert refresh.default_cache_dir("trivy", env, "win32") == Path(local) / "trivy"


@pytest.mark.unit
@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_the_tools_own_variables_win_and_are_made_absolute(
    monkeypatch, tmp_path, platform
):
    env = {
        "XDG_CACHE_HOME": str(tmp_path / "xdg"),
        "LOCALAPPDATA": str(tmp_path / "local"),
        "GRYPE_DB_CACHE_DIR": str(tmp_path / "g"),
        "TRIVY_CACHE_DIR": "relative-trivy",
    }
    monkeypatch.chdir(tmp_path)
    assert refresh.default_cache_dir("grype", env, platform) == tmp_path / "g"
    assert (
        refresh.default_cache_dir("trivy", env, platform) == tmp_path / "relative-trivy"
    )


def _content_db_scanner(tool: str):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
    )

    return {"grype": GrypeScanner, "trivy": TrivyRepoScanner}[tool]


def _real_policy(tool: str, tmp_path: Path):
    """The policy the scanner's own declaration gets, as build_scanner_policy makes it."""
    from automated_security_helper.utils.sandbox.policy import build_scanner_policy

    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    return build_scanner_policy(
        {"grype": "grype", "trivy": "trivy-repo"}[tool],
        _content_db_scanner(tool).sandbox_requirements,
        argv0=sys.executable,
        source_dir=source,
        output_dir=output,
        results_dir=output / "scanners" / tool,
        scan_target=source,
        cwd=None,
        offline=False,
        network_scanners=None,
    )


def _within(path: Path, roots) -> bool:
    real = Path(os.path.realpath(path))
    return any(
        real == Path(os.path.realpath(root))
        or Path(os.path.realpath(root)) in real.parents
        for root in roots
    )


@pytest.mark.unit
@pytest.mark.parametrize("tool", ["grype", "trivy"])
@pytest.mark.parametrize("xdg", [False, True], ids=["no-xdg", "xdg"])
@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_every_cache_default_cache_dir_names_is_mounted(
    monkeypatch, tmp_path, tool, xdg, platform
):
    """Wherever the refresh writes and the check reads, the sandboxed scan can read."""
    if xdg and platform == "linux" and tool == "trivy" and sys.platform == "win32":
        # default_cache_dir judges XDG_CACHE_HOME with the simulated platform's
        # rules: a POSIX path must start with "/". A Windows tmp_path ("D:\...")
        # does not, so trivy falls back to the temp directory and there is no
        # XDG directory on this host to mount; the case cannot exist here.
        pytest.skip("a POSIX XDG_CACHE_HOME cannot name a directory on Windows")
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
    monkeypatch.delenv("TRIVY_CACHE_DIR", raising=False)
    if xdg:
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    else:
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    cache = refresh.default_cache_dir(tool, platform=platform)
    cache.mkdir(parents=True)
    policy = _real_policy(tool, tmp_path)
    assert _within(cache, [*policy.read_only, *policy.cache]), (cache, policy.cache)
    assert not _within(cache, policy.executable), "a database is not a program"


@pytest.mark.unit
@pytest.mark.skipif(sys.platform == "win32", reason="no backend runs on Windows")
@pytest.mark.parametrize("backend", sorted(BACKENDS))
@pytest.mark.parametrize("tool", ["grype", "trivy"])
def test_the_pinned_cache_reaches_the_sandboxed_tool_and_xdg_does_not(
    monkeypatch, tmp_path, backend, tool
):
    """What each backend hands the tool, from the scanner's real declaration.

    The scanners pin the cache because XDG_CACHE_HOME does not reach the sandboxed
    scan: grype gets GRYPE_DB_CACHE_DIR, trivy gets --cache-dir. The pin has to
    arrive intact on every backend, and the variable it replaces does not."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CACHE_HOME", str(xdg))
    monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
    monkeypatch.delenv("TRIVY_CACHE_DIR", raising=False)
    cache = refresh.default_cache_dir(tool, platform="linux")
    cache.mkdir(parents=True)
    env = {"PATH": "/usr/bin", "XDG_CACHE_HOME": str(xdg)}
    argv = ["/usr/bin/true"]
    if tool == "grype":
        env["GRYPE_DB_CACHE_DIR"] = cache.as_posix()
    else:
        argv.append(f"--cache-dir={cache.as_posix()}")
    runner = BACKENDS[backend]()
    if hasattr(runner, "_executable"):
        runner._executable = f"/usr/bin/{backend}"  # planning starts nothing
    plan = runner.plan(argv, env, _real_policy(tool, tmp_path))
    try:
        assert "XDG_CACHE_HOME" not in plan.env, backend
        if tool == "grype":
            assert plan.env.get("GRYPE_DB_CACHE_DIR") == cache.as_posix(), backend
        else:
            assert plan.argv[-1] == f"--cache-dir={cache.as_posix()}", backend
    finally:
        plan.run_cleanup()


@pytest.mark.unit
def test_threads_of_one_scan_take_turns(monkeypatch, tmp_path):
    spans = []

    def slow(argv, **kwargs):
        start = time.monotonic()
        time.sleep(0.2)  # stands in for a download
        spans.append((start, time.monotonic()))
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(refresh, "spawn_run", slow)
    threads = [
        threading.Thread(
            target=refresh.prepare_content_db,
            args=("trivy", tmp_path, False),
            kwargs={"executable": "trivy", **_where(tmp_path)},
        )
        for _ in range(3)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    _assert_no_overlap(spans)


@pytest.mark.integration
@pytest.mark.skipif(os.name == "nt", reason="the cross-process lock is POSIX flock")
def test_two_scans_in_separate_processes_take_turns(tmp_path):
    """Two ASH processes sharing a cache must not update it at the same time."""
    log = tmp_path / "spans.log"
    tool = tmp_path / "grype"
    tool.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import time
            start = time.time()
            time.sleep(0.5)
            with open({str(log)!r}, "a") as f:
                f.write(f"{{start}} {{time.time()}}\\n")
            """
        )
    )
    tool.chmod(0o755)
    cache = tmp_path / "cache"
    program = textwrap.dedent(
        f"""\
        from automated_security_helper.utils.content_db_refresh import prepare_content_db
        prepare_content_db(
            "grype", {str(cache)!r}, offline=False, executable={str(tool)!r},
            source_dir={str(tmp_path / "src")!r}, results_dir={str(tmp_path / "out")!r},
        )
        """
    )
    procs = [
        subprocess.Popen(  # nosec B603 - fixed argv
            [sys.executable, "-c", importing_this_checkout(program)]
        )
        for _ in range(2)
    ]
    assert [p.wait(timeout=60) for p in procs] == [0, 0]
    spans = [tuple(map(float, line.split())) for line in log.read_text().splitlines()]
    assert len(spans) == 2
    _assert_no_overlap(spans)


def _assert_no_overlap(spans):
    ordered = sorted(spans)
    for (_, end), (start, _) in zip(ordered, ordered[1:]):
        assert start >= end, f"two updates ran at once: {ordered}"


@pytest.mark.unit
class TestScannersUseThePreparedDatabase:
    """The scanners refresh before a sandboxed online scan, then skip their own."""

    @pytest.fixture
    def prepared(self, monkeypatch):
        calls = []

        def record(tool, cache_dir, offline, **kwargs):
            calls.append(
                SimpleNamespace(
                    tool=tool, cache_dir=Path(cache_dir), offline=offline, **kwargs
                )
            )

        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            grype_scanner,
        )
        from automated_security_helper.plugin_modules.ash_builtin.scanners import (
            _trivy_scanner_base,
        )

        monkeypatch.setattr(grype_scanner, "prepare_content_db", record)
        # trivy and trivy-repo prepare through their shared base.
        monkeypatch.setattr(_trivy_scanner_base, "prepare_content_db", record)
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        return calls

    def _grype(self, context):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
            GrypeScannerConfig,
        )

        scanner = GrypeScanner(context=context, config=GrypeScannerConfig())
        scanner._process_config_options()
        return scanner

    def test_grype_sandboxed_online(self, prepared, test_plugin_context, tmp_path):
        scanner = self._grype(test_plugin_context)
        with sandbox_scope(_scope(tmp_path)):
            _, _, env = scanner._execute_scan(tmp_path, "source", [])
        (call,) = prepared
        assert call.tool == "grype" and call.offline is False
        # Out of the assertion: env is the scan's whole environment, which a failure
        # would print.
        expected_cache = refresh.default_cache_dir("grype", env)
        assert call.cache_dir == expected_cache
        for name, value in refresh.GRYPE_PREPARED_ENV.items():
            assert env[name] == value, name

    def test_grype_unsandboxed_updates_itself(
        self, prepared, test_plugin_context, tmp_path
    ):
        scanner = self._grype(test_plugin_context)
        _, _, env = scanner._execute_scan(tmp_path, "source", [])
        assert prepared == []
        # The one value, not the scan's whole environment, which a failure would print.
        auto_update = (env or {}).get("GRYPE_DB_AUTO_UPDATE")
        assert auto_update != "false"

    def test_grype_sandboxed_offline_refreshes_nothing(
        self, prepared, test_plugin_context, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        scanner = self._grype(test_plugin_context)
        with sandbox_scope(_scope(tmp_path)):
            scanner._execute_scan(tmp_path, "source", [])
        assert prepared == []

    def test_trivy_repo_sandboxed_online_skips_its_update(
        self, prepared, test_plugin_context, tmp_path, monkeypatch
    ):
        from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
            TrivyRepoScanner,
            TrivyRepoScannerConfig,
        )

        scanner = TrivyRepoScanner(
            context=test_plugin_context, config=TrivyRepoScannerConfig()
        )
        scanner._process_config_options()
        # trivy need not be installed for this: what is asserted is the command
        # the scanner builds, and the run itself is replaced below.
        monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
        commands = []
        # The spawn under TrivyScannerBase._run_subprocess, which adds the update
        # and its skip flags for trivy and trivy-repo alike.
        from automated_security_helper.base.scanner_plugin import ScannerPluginBase

        # The stand-in answers as a completed run: the scanner grades the exit
        # code before it reads anything else, and a response with no code is
        # refused as a tool that never ran.
        monkeypatch.setattr(
            ScannerPluginBase,
            "_run_subprocess",
            lambda self, command, **kwargs: (
                commands.append(list(command)) or {"returncode": 0}
            ),
        )
        target = tmp_path / "repo"
        target.mkdir()
        (target / "requirements.txt").write_text("requests==2.19.0\n")
        with sandbox_scope(_scope(tmp_path)):
            scanner.scan(target, "source")
        (call,) = prepared
        assert call.tool == "trivy" and call.offline is False
        assert call.checks == ("misconfig" in scanner.config.options.scanners)
        (command,) = commands
        assert command[:2] == ["trivy", "repository"]
        assert "--skip-db-update" in command
        # trivy repository never reads the Java database, so it is neither updated
        # nor allowed to update itself in the read-only cache.
        assert not getattr(call, "java", False)
        assert "--skip-java-db-update" in command
        assert "--cache-backend=memory" in command


@pytest.mark.unit
class TestTrivyScanCacheUnderASandbox:
    """trivy-repo keeps its scan cache in memory in every run, sandboxed or not.

    trivy writes its scan cache (fanal/fanal.db) into its cache directory, which
    every backend but bwrap mounts read-only, and which can be read-only outside a
    sandbox as well. Measured with trivy 0.75.0 offline against a read-only cache:
    "unable to initialize fs cache: failed to create cache dir ... permission
    denied", exit 1; with --cache-backend=memory, the same findings as a writable
    cache. Online the flag was already there under a sandbox; offline it was not,
    so an offline scan under sandbox-exec, Landlock or firejail failed, and neither
    was it there unsandboxed.
    """

    def _command(self, context, tmp_path, monkeypatch, sandboxed: bool):
        scanner, commands = _trivy_scanner(context, monkeypatch)
        target = tmp_path / "repo"
        target.mkdir(exist_ok=True)
        (target / "requirements.txt").write_text("requests==2.19.0\n")
        if sandboxed:
            with sandbox_scope(_scope(tmp_path)):
                scanner.scan(target, "source")
        else:
            scanner.scan(target, "source")
        (command,) = commands
        return command

    def test_offline_under_a_sandbox(self, test_plugin_context, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        command = self._command(test_plugin_context, tmp_path, monkeypatch, True)
        assert "--offline-scan" in command
        assert "--cache-backend=memory" in command

    def test_and_without_one(self, test_plugin_context, tmp_path, monkeypatch):
        """A cache can be read-only with no sandbox too; see
        test_a_read_only_cache_outside_a_sandbox_still_scans."""
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        command = self._command(test_plugin_context, tmp_path, monkeypatch, False)
        assert "--cache-backend=memory" in command


def _grype_scanner(context):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScanner,
        GrypeScannerConfig,
    )

    scanner = GrypeScanner(context=context, config=GrypeScannerConfig())
    scanner._process_config_options()
    return scanner


def _trivy_scanner(context, monkeypatch):
    """trivy-repo with its run replaced: what is asserted is the command it builds.

    The spawn under TrivyScannerBase._run_subprocess is what is replaced, as in
    TestScannersUseThePreparedDatabase: trivy and trivy-repo add the database
    update, its skip flags, the cache directory and the scan cache's backend there.
    """
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.plugin_modules.ash_trivy_plugins import (
        trivy_repo_scanner,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
        TrivyRepoScannerConfig,
    )

    scanner = TrivyRepoScanner(context=context, config=TrivyRepoScannerConfig())
    scanner._process_config_options()
    monkeypatch.setattr(scanner, "validate_plugin_dependencies", lambda: True)
    # Offline, the scan reads trivy's default misconfiguration scanners from
    # `trivy repository --help` (TrivyScannerBase._offline_misconfig_args), a
    # start made through run_command, not through the replaced _run_subprocess,
    # so it would reach the tool guard's stand-in trivy and be recorded as a
    # started tool at teardown. This module keeps its real probes
    # (PROBE_SUBJECT_MODULES), so the list is answered here as on a host without
    # trivy: unknown, the fail-closed side, through the binding trivy-repo's own
    # module took at import (its _default_misconfig_scanners reads that name).
    # The memo itself is keyed on the resolved trivy path, so it is not pre-seeded.
    monkeypatch.setattr(
        trivy_repo_scanner,
        "trivy_default_misconfig_scanners",
        lambda *args, **kwargs: None,
    )
    commands = []
    # A completed run, as above: a response with no exit code is refused as a
    # tool that never ran.
    monkeypatch.setattr(
        ScannerPluginBase,
        "_run_subprocess",
        lambda self, command, **kwargs: (
            commands.append(list(command)) or {"returncode": 0}
        ),
    )
    return scanner, commands


def _context(source_dir: Path, output_dir: Path) -> PluginContext:
    source_dir.mkdir(parents=True, exist_ok=True)
    return PluginContext(
        source_dir=source_dir, output_dir=output_dir, config=get_default_config()
    )


def _probe_recorder(monkeypatch, stdout: str):
    """Stands in for the staleness probe's spawn_run and records each call."""
    calls = []

    def run(argv, **kwargs):
        calls.append(
            SimpleNamespace(
                argv=list(argv), env=dict(kwargs["env"]), cwd=kwargs.get("cwd")
            )
        )
        return subprocess.CompletedProcess(argv, 0, stdout, "")

    monkeypatch.setattr(staleness, "spawn_run", run)
    return calls


@pytest.mark.unit
class TestOneCacheForTheScanTheRefreshAndTheCheck:
    """With XDG_CACHE_HOME set, all three name the directory the tool itself uses.

    The sandbox drops XDG_CACHE_HOME, so a sandboxed grype or trivy left to itself
    reads ~/.cache, while the operator's own tool (and before this, nothing in ASH)
    used $XDG_CACHE_HOME. The scanner resolves the directory once and names it to
    the scan, the refresh and the staleness probe.
    """

    @pytest.fixture
    def env(self, monkeypatch, tmp_path):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        monkeypatch.delenv("GRYPE_DB_CACHE_DIR", raising=False)
        monkeypatch.delenv("TRIVY_CACHE_DIR", raising=False)
        monkeypatch.setenv("HOME", str(tmp_path / "home"))
        monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
        monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        # The probe is given the scanner's binary; the probe recorder stands in for
        # it, so it need not be installed (the CI unit-test runner has neither).
        monkeypatch.setattr(scanner_plugin, "find_executable", lambda tool: tool)
        return tmp_path

    @staticmethod
    def _expected(tool: str, tmp_path: Path) -> Path:
        """The tool's own rule on this platform; see the table above."""
        xdg = tmp_path / "xdg"
        if tool == "grype":
            return xdg / "grype" / "db"  # adrg/xdg honors it on every platform
        if sys.platform == "darwin":
            return tmp_path / "home" / "Library" / "Caches" / "trivy"
        if sys.platform == "win32":
            return tmp_path / "local" / "trivy"
        return xdg / "trivy"

    def test_grype(self, env, monkeypatch, recorder):
        tmp_path = env
        expected = self._expected("grype", tmp_path)
        scanner = _grype_scanner(_context(tmp_path / "src", tmp_path / "out"))
        with sandbox_scope(_scope(tmp_path)):
            _, _, scan_env = scanner._execute_scan(tmp_path / "src", "source", [])
            probe = scanner.content_database_probe_context()
        (refreshed,) = recorder.calls
        assert Path(refreshed.env["GRYPE_DB_CACHE_DIR"]) == expected, "the refresh"
        assert Path(scan_env.get("GRYPE_DB_CACHE_DIR", "")) == expected, "the scan"
        status = '{"built": "2026-01-01T00:00:00Z"}'
        probes = _probe_recorder(monkeypatch, status)
        staleness._built_from_grype(probe)
        (checked,) = probes
        assert Path(checked.env.get("GRYPE_DB_CACHE_DIR", "")) == expected, "the check"

    def test_trivy_repo(self, env, monkeypatch, recorder):
        tmp_path = env
        expected = self._expected("trivy", tmp_path)
        target = tmp_path / "src"
        scanner, commands = _trivy_scanner(
            _context(target, tmp_path / "out"), monkeypatch
        )
        (target / "requirements.txt").write_text("requests==2.19.0\n")
        with sandbox_scope(_scope(tmp_path)):
            scanner.scan(target, "source")
            probe = scanner.content_database_probe_context()
        refreshed = recorder.calls[0]
        assert Path(_flag(refreshed.argv, "--cache-dir")) == expected, "the refresh"
        (command,) = commands
        assert Path(_flag(command, "--cache-dir")) == expected, "the scan"
        version = '{"VulnerabilityDB": {"UpdatedAt": "2026-01-01T00:00:00Z"}}'
        probes = _probe_recorder(monkeypatch, version)
        staleness._built_from_trivy(probe)
        (checked,) = probes
        assert Path(_flag(checked.argv, "--cache-dir")) == expected, "the check"


def _flag(argv, name: str) -> str:
    """The value of ``name`` in ``argv``, spelled ``name value`` or ``name=value``."""
    for i, arg in enumerate(argv):
        if arg == name:
            return argv[i + 1]
        if arg.startswith(f"{name}="):
            return arg.split("=", 1)[1]
    return ""


@pytest.mark.unit
@pytest.mark.parametrize("checkout", [False, True], ids=["plain-tree", "git-checkout"])
def test_the_refresh_runs_outside_the_scanned_tree_when_the_temp_dir_is_in_it(
    recorder, monkeypatch, tmp_path, checkout
):
    """The tools run from cwd_outside_scanned_tree, the rule checkov's scans use.

    The refresh makes its scratch directory in the temporary directory, and a
    TMPDIR inside the scanned tree puts that inside the tree: then the directory
    the tools run from must be somewhere else. Asked of the same membership test as
    every other "inside the scanned tree" question, so a tree that is not a git
    checkout (the source directory itself is the tree then) counts too.
    """
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "cache"))
    tree = tmp_path / "repo"
    (tree / "tmp").mkdir(parents=True)
    if checkout:
        (tree / ".git").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tree / "tmp"))
    scanner = _grype_scanner(_context(tree, tmp_path / "out"))
    with sandbox_scope(_scope(tmp_path)):
        scanner._execute_scan(tree, "source", [])
    (call,) = recorder.calls
    assert not in_scanned_tree(call.cwd, tree), call.cwd


@pytest.mark.unit
class TestOncePerScan:
    """The memo is per scan, keyed on PluginContext.scan_id, not on the object's address."""

    @pytest.fixture(autouse=True)
    def _online(self, monkeypatch, tmp_path):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        monkeypatch.setenv("GRYPE_DB_CACHE_DIR", str(tmp_path / "cache"))

    def _scan(self, scanner, tmp_path):
        with sandbox_scope(_scope(tmp_path)):
            scanner._execute_scan(tmp_path / "src", "source", [])

    def test_one_scan_refreshes_once(self, recorder, tmp_path):
        context = _context(tmp_path / "src", tmp_path / "out")
        for _ in range(3):
            self._scan(_grype_scanner(context), tmp_path)
        assert len(recorder.calls) == 1

    def test_a_later_scan_at_a_reused_address_refreshes(
        self, recorder, monkeypatch, tmp_path
    ):
        """A long-running process (the MCP server) frees one scan's context, and
        CPython can put the next scan's context at the same address. Every context
        is given one address here, the worst case of that."""
        monkeypatch.setattr(refresh, "id", lambda obj: 1, raising=False)
        for _ in range(2):
            context = _context(tmp_path / "src", tmp_path / "out")
            self._scan(_grype_scanner(context), tmp_path)
        assert len(recorder.calls) == 2

    def test_a_context_without_a_scan_id_refreshes_every_time(self, recorder, tmp_path):
        for _ in range(2):
            refresh.prepare_content_db(
                "grype",
                tmp_path / "cache",
                offline=False,
                scan_id=refresh.scan_id_for(object()),
                executable="grype",
                **_where(tmp_path),
            )
        assert len(recorder.calls) == 2


@pytest.mark.unit
def test_a_failed_updates_excerpt_hides_a_value_straddling_its_cut(
    monkeypatch, tmp_path
):
    """The tool's stderr is redacted BEFORE the 1000-character head cut.

    The 992 filler characters put the head cut inside the value: cut first,
    the message would keep the fragment ``EDGE-SEC``, which the downstream
    whole-spelling redaction cannot match.
    """
    value = "EDGE-SECRET-9271"
    failing = _Recorder(returncode=1, stderr="y" * 992 + value + " then " + "z" * 1100)
    monkeypatch.setattr(refresh, "spawn_run", failing)

    with pytest.raises(ScannerError) as raised:
        refresh.prepare_content_db(
            "grype",
            tmp_path,
            offline=False,
            scan_id="s",
            executable="grype",
            values=[value],
            **_where(tmp_path),
        )

    message = str(raised.value)
    assert "could not update" in message, message
    assert value not in message, message
    assert "EDGE-SEC" not in message, message
