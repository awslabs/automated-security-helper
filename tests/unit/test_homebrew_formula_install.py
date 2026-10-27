# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Homebrew formula installs ASH with its dependencies, and CI can test it.

Why this file exists
--------------------
Homebrew's `virtualenv_install_with_resources` installs with pip `--no-deps`, so a
formula that declares no `resource` blocks gets ASH alone in the virtualenv, and
`ash --version` dies with "No module named 'typer'". `ruby -c Formula/ash.rb` only
parses the file, so it cannot tell.

The formula installs the dependency set locked in uv.lock (`uv sync --frozen`)
from the tagged source tree, so the lock moving with the tag is what keeps it
correct across releases. That makes three things load-bearing, and each has a
check here:

* the install method still has that shape,
* uv.lock agrees with pyproject.toml, since `--frozen` installs the lock as it is
  and a dependency added to pyproject.toml without relocking would be missing
  from every Homebrew install,
* .github/scripts/render-homebrew-formula.py can still rewrite the formula's
  source line, because CI installs that rewritten copy (built from the commit
  under test) and a formula it cannot rewrite would leave the leg unable to run.

The real install, `brew test` and the scans are .github/actions/validate-install
(homebrew.sh), on Linux and macOS runners.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess  # nosec B404 - runs the formula's install method under Ruby
import sys
from pathlib import Path
from typing import Any

import pytest
from hatchling.builders.sdist import SdistBuilder
from hatchling.builders.wheel import WheelBuilder
from packaging.markers import Marker
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
FORMULA_PATH = REPO_ROOT / "Formula" / "ash.rb"
PYPROJECT_PATH = REPO_ROOT / "pyproject.toml"
LOCK_PATH = REPO_ROOT / "uv.lock"
RENDERER_PATH = REPO_ROOT / ".github" / "scripts" / "render-homebrew-formula.py"
HOMEBREW_SH = REPO_ROOT / ".github" / "actions" / "validate-install" / "homebrew.sh"
STATUS_CHECKER = HOMEBREW_SH.with_name("check-scanner-statuses.py")


def _formula() -> str:
    return FORMULA_PATH.read_text(encoding="utf-8")


def _pyproject() -> dict[str, Any]:
    with PYPROJECT_PATH.open("rb") as handle:
        return tomllib.load(handle)


def _install_method() -> str:
    match = re.search(
        r"^  def install\n(?P<body>.*?)^  end\n", _formula(), re.DOTALL | re.MULTILINE
    )
    assert match, f"no `def install ... end` in {FORMULA_PATH}"
    return match["body"]


def _set_before_uv_sync(name: str, value: str) -> None:
    """`ENV["<name>"] = <value>` is a line of `def install`, ahead of `uv sync`."""
    lines = _install_method().splitlines()
    syncs = [
        i for i, line in enumerate(lines) if re.match(r'\s+system "uv", "sync"', line)
    ]
    assert len(syncs) == 1, "def install runs `uv sync` once"
    assignment = re.compile(rf'\s+ENV\["{re.escape(name)}"\] = {re.escape(value)}')
    settings = [i for i, line in enumerate(lines) if assignment.fullmatch(line)]
    assert settings, f'no uncommented `ENV["{name}"] = {value}` in def install'
    assert min(settings) < syncs[0], f"{name} is set after `uv sync` runs"


@functools.lru_cache(maxsize=None)
def _renderer():
    # Loaded once: a second load would define a second FormulaShapeError class,
    # and pytest.raises would not recognize the one the first load raises.
    spec = importlib.util.spec_from_file_location(
        "render_homebrew_formula", RENDERER_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestTheFormulaInstallsTheLockedDependencies:
    def test_install_syncs_the_lock_without_dev_dependencies(self):
        body = _install_method()
        sync = re.search(r'system "uv", "sync",(?P<args>[^\n]*(?:\n\s+[^\n]*)*)', body)
        assert sync, "def install no longer runs `uv sync`"
        args = sync["args"]
        for flag in ("--frozen", "--no-dev", "--no-editable"):
            assert f'"{flag}"' in args, f"`uv sync` in def install lost {flag}"

    def test_install_syncs_into_the_formula_virtualenv(self):
        """Without UV_PROJECT_ENVIRONMENT, uv syncs a .venv in the build directory.

        That directory is deleted after the install, so the keg's virtualenv would
        hold nothing and every console script would fail on its first import.
        """
        body = _install_method()
        _set_before_uv_sync("UV_PROJECT_ENVIRONMENT", "venv.root.to_s")
        # The interpreter is the formula's python@3.N, never one uv downloads.
        _set_before_uv_sync("UV_PYTHON_DOWNLOADS", '"never"')
        assert re.search(r'"--python", \(venv\.root/"bin/python"\)\.to_s', body)

    def test_install_reads_no_uv_configuration_files(self):
        """uv reads the user's uv.toml (``~/.config/uv/uv.toml``) by default.

        A setting there, another index for one, would change how the formula
        installs the lock on that machine and nowhere else. Dropping
        ``UV_NO_CONFIG`` passed every other test in this file, and so did the line
        commented out, or moved below `uv sync`, while this was a substring check.
        """
        _set_before_uv_sync("UV_NO_CONFIG", '"1"')

    def test_install_includes_the_extras_the_default_scanners_need(self):
        """The cdk extra is cdk-nag's; both the default and precommit sets select it.

        `uv sync` installs no optional dependencies unless named, which left a
        Homebrew install with cdk-nag MISSING, so a default scan exited 1, and the
        virtualenv has no pip to add the extra afterwards.
        """
        from automated_security_helper.interactions.run_ash_scan import (
            PRECOMMIT_MODE_SCANNERS,
        )

        assert "cdk-nag" in PRECOMMIT_MODE_SCANNERS
        assert "cdk" in _pyproject()["project"]["optional-dependencies"]
        sync = re.search(
            r'system "uv", "sync",(?P<args>[^\n]*(?:\n\s+[^\n]*)*)', _install_method()
        )
        assert sync and '"--extra", "cdk"' in sync["args"], (
            "`uv sync` in def install does not install the cdk extra"
        )

    def test_node_is_a_dependency(self):
        """cdk-nag runs on Node.js and npm-audit runs npm."""
        assert re.search(r'^  depends_on "node"$', _formula(), re.MULTILINE)

    def test_the_console_scripts_find_the_formulas_node(self):
        """Homebrew's node is on the scripts' PATH, after the user's own PATH."""
        assert re.search(
            r'path = "#\{libexec\}/bin:\$PATH:#\{Formula\["node"\]\.opt_bin\}"',
            _install_method(),
        )
        assert 'write_env_script libexec/"bin"/script, PATH: path' in _install_method()

    def test_the_formula_test_runs_cdk_nag(self):
        """brew test has to reach the scanner the cdk extra and Node.js exist for.

        And it has to hold the result to having run: a scan that reports cdk-nag
        MISSING still writes its results file, and only exits 1 for it.
        """
        match = re.search(
            r"^  test do\n(?P<body>.*?)^  end\n", _formula(), re.DOTALL | re.MULTILINE
        )
        assert match, "Formula/ash.rb has no `test do ... end`"
        body = match["body"]
        assert "--scanners cdk-nag" in body
        assert "assert_includes %w[PASSED FAILED], status" in body
        assert '"ash exited 2" : "ash exited 0"' in body

    def test_the_keg_keeps_rpath_install_names(self) -> None:
        """After the build, Homebrew rewrites every dylib ID in the keg to the
        library's absolute opt path, and gives up on a Mach-O whose header has no
        room for the longer name: `brew install` then exits 1 at "Failed to fix
        install linkage" with the formula fully built. The locked orjson wheel's
        extension module is such a file, a dylib with the ID
        `@rpath/orjson.cpython-312-darwin.so` and no header padding (the wheel is
        prebuilt, not linked under Homebrew's -headerpad_max_install_names), and
        it stopped both macOS legs that got past `uv sync`. `preserve_rpath` tells
        Homebrew to leave `@rpath` IDs alone; Python loads extension modules by
        path, so nothing reads the install name.
        """
        assert re.search(r"^  preserve_rpath$", _formula(), re.MULTILINE), (
            "Formula/ash.rb does not declare `preserve_rpath`"
        )

    def test_no_resource_based_install_is_left_behind(self):
        """`virtualenv_install_with_resources` with no resources is the defect."""
        assert "virtualenv_install_with_resources" not in _install_method()
        assert not re.search(r"^  resource ", _formula(), re.MULTILINE)

    def test_the_formula_python_satisfies_requires_python(self):
        match = re.search(
            r'^  depends_on "python@(?P<minor>3\.\d+)"$', _formula(), re.MULTILINE
        )
        assert match, 'Formula/ash.rb names no `depends_on "python@3.N"`'
        minor = match["minor"]
        requires_python = SpecifierSet(_pyproject()["project"]["requires-python"])
        assert f"{minor}.0" in requires_python, (
            f"the formula builds on python@{minor}, outside requires-python "
            f"{requires_python}"
        )
        assert f'"python{minor}"' in _install_method(), (
            f"def install does not create the virtualenv with python{minor}, the "
            "interpreter the formula depends on"
        )

    def test_every_console_script_is_put_on_path(self):
        scripts = set(_pyproject()["project"]["scripts"])
        match = re.search(r"%w\[(?P<names>[^\]]*)\]\.each", _install_method())
        assert match, "def install no longer lists the console scripts it links"
        assert set(match["names"].split()) == scripts


class TestTheCiLegScansWithTheDefaultSelection:
    """homebrew.sh runs `ash scan` with no --scanners, so a default scan is tested.

    A scan narrowed to detect-secrets passed while a default scan from the same
    install exited 1 with cdk-nag MISSING. The default scan may leave out only
    the scanners that are separate programs the formula does not install: the
    native binaries gitleaks, grype, opengrep, syft and trivy, and the Ruby gem
    cfn-nag. A default-set scanner the formula does provide for (the Python
    tools, cdk-nag, npm-audit) has to run.
    """

    def test_a_scan_without_a_scanner_selection_runs(self):
        # One logical line per command: the narrowed scans name --scanners on a
        # continuation line.
        script = HOMEBREW_SH.read_text(encoding="utf-8").replace("\\\n", " ")
        scans = [
            line
            for line in script.splitlines()
            if '"$ash_bin" scan' in line and '"$WORK/out-default"' in line
        ]
        assert len(scans) == 1, "homebrew.sh no longer runs its default-selection scan"
        assert "--scanners" not in scans[0] and "--exclude-scanners" not in scans[0]

    def test_only_the_tools_the_formula_does_not_install_may_be_missing(self):
        script = HOMEBREW_SH.read_text(encoding="utf-8").replace("\\\n", " ")
        allowed = re.findall(
            r"check-scanner-statuses\.py\S* .*--may-be-missing ([a-z,-]+)", script
        )
        assert len(allowed) == 1, (
            f"homebrew.sh should check the default scan's statuses once: {allowed}"
        )
        assert set(allowed[0].split(",")) == {
            "cfn-nag",
            "gitleaks",
            "grype",
            "opengrep",
            "syft",
            "trivy",
        }


class TestTheBuildBackendSkipsTheUvCache:
    """hatchling walks the whole project root while uv may still be writing into it.

    The formula builds ASH with `uv sync` from the unpacked source tree. hatchling
    lists every directory under the project root to decide what goes in the wheel,
    and it prunes a directory only when the directory is excluded AND
    `skip-excluded-dirs` is on: an `exclude` pattern alone drops the files it matches
    but the walk still descends. A uv cache under the project root was walked while
    uv was renaming temporary entries in it, and the walk died in `safe_walk` with
    FileNotFoundError on a directory that had vanished between listing and stat.
    The formula keeps its cache outside the tree now; this holds the backend side,
    so a `.uv-cache` put in the tree by anyone (a UV_CACHE_DIR of their own, an
    older formula) is never walked. It reads hatchling's own decision for this
    repository's configuration, not the text of pyproject.toml.
    """

    @pytest.mark.parametrize("builder_class", [WheelBuilder, SdistBuilder])
    def test_a_uv_cache_in_the_project_root_is_pruned(
        self, builder_class: type[WheelBuilder | SdistBuilder]
    ) -> None:
        config = builder_class(str(REPO_ROOT)).config

        assert config.directory_is_excluded(".uv-cache", "")
        # Controls: the package itself is walked, and the virtualenv is a directory
        # hatchling never descends into on its own.
        assert not config.directory_is_excluded("automated_security_helper", "")
        assert config.directory_is_excluded(".venv", "")


def _status_checker():
    spec = importlib.util.spec_from_file_location(
        "check_scanner_statuses", STATUS_CHECKER
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestTheScannerStatusCheck:
    """check-scanner-statuses.py, which homebrew.sh runs on the default scan."""

    ALLOWED = "cfn-nag,grype"

    @staticmethod
    def _run(tmp_path, statuses, allowed=ALLOWED, capsys=None):
        results = tmp_path / "ash_aggregated_results.json"
        results.write_text(
            json.dumps(
                {"scanner_results": {k: {"status": v} for k, v in statuses.items()}}
            ),
            encoding="utf-8",
        )
        return _status_checker().main([str(results), "--may-be-missing", allowed])

    def test_scanners_that_ran_pass(self, tmp_path, capsys):
        rc = self._run(
            tmp_path, {"bandit": "PASSED", "checkov": "FAILED", "cdk-nag": "SKIPPED"}
        )

        assert rc == 0
        assert capsys.readouterr().out.strip() == ""

    def test_an_allowed_missing_scanner_is_reported(self, tmp_path, capsys):
        rc = self._run(tmp_path, {"bandit": "PASSED", "grype": "MISSING"})

        assert rc == 0
        assert capsys.readouterr().out.strip() == "grype"

    @pytest.mark.parametrize("status", ["ERROR", "MISSING", "None", "RUNNING"])
    def test_anything_else_from_a_provided_scanner_fails(
        self, tmp_path, capsys, status
    ):
        """ERROR included: a crashed scanner did not scan."""
        rc = self._run(tmp_path, {"semgrep": status, "grype": "MISSING"})

        assert rc == 1
        assert f"semgrep={status}" in capsys.readouterr().err

    def test_an_allowed_scanner_that_errored_still_fails(self, tmp_path, capsys):
        rc = self._run(tmp_path, {"grype": "ERROR"})

        assert rc == 1
        assert "grype=ERROR" in capsys.readouterr().err

    def test_no_results_at_all_fails(self, tmp_path):
        assert self._run(tmp_path, {}) == 1


class TestTheLockAgreesWithPyproject:
    """What `uv lock --check` would say about [project] dependencies, offline."""

    @staticmethod
    def _root_requires_dist() -> list[dict[str, Any]]:
        with LOCK_PATH.open("rb") as handle:
            lock = tomllib.load(handle)
        name = canonicalize_name(_pyproject()["project"]["name"])
        roots = [p for p in lock["package"] if canonicalize_name(p["name"]) == name]
        assert len(roots) == 1, f"uv.lock has {len(roots)} entries for {name}"
        return roots[0]["metadata"]["requires-dist"]

    @staticmethod
    def _key(name: str, specifier: str, marker: str | None) -> tuple:
        # Through packaging's Marker, so the quoting uv writes and the quoting in
        # pyproject.toml read the same.
        return (
            canonicalize_name(name),
            SpecifierSet(specifier),
            str(Marker(marker)) if marker else "",
        )

    def test_the_lock_was_made_from_these_requirements(self):
        """A dependency's environment marker is part of it: the lock records it,
        and a requirement whose marker changed without a relock is a stale lock."""
        project = _pyproject()["project"]
        expected = set()
        for line in project["dependencies"]:
            requirement = Requirement(line)
            marker = str(requirement.marker) if requirement.marker else None
            expected.add(
                self._key(requirement.name, str(requirement.specifier), marker)
            )
        for extra, lines in project.get("optional-dependencies", {}).items():
            for line in lines:
                requirement = Requirement(line)
                expected.add(
                    self._key(
                        requirement.name,
                        str(requirement.specifier),
                        f"extra == '{extra}'",
                    )
                )
        locked = {
            self._key(entry["name"], entry.get("specifier", ""), entry.get("marker"))
            for entry in self._root_requires_dist()
        }
        assert locked == expected, (
            "uv.lock was not regenerated after a change to pyproject.toml's "
            "dependencies; run `uv lock`. Homebrew installs the lock as it is "
            f"(`uv sync --frozen`). In pyproject only: {sorted(map(str, expected - locked))}; "
            f"in uv.lock only: {sorted(map(str, locked - expected))}"
        )


class TestTheCiRendererCanRewriteTheFormula:
    def _render(self, formula: str, tarball: Path, version: str = "3.7.0") -> str:
        return _renderer().render(formula, tarball, version, "0" * 64)

    def test_only_the_source_line_changes(self, tmp_path):
        tarball = tmp_path / "automated-security-helper-3.7.0.tar.gz"
        original = _formula()
        rendered = self._render(original, tarball)

        removed = [
            line for line in original.splitlines() if line not in rendered.splitlines()
        ]
        added = [
            line for line in rendered.splitlines() if line not in original.splitlines()
        ]
        assert len(removed) == 1 and removed[0].startswith('  url "https://github.com/')
        assert added == [f'  url "{tarball.as_uri()}"', f'  sha256 "{"0" * 64}"']

    def test_a_tarball_named_for_another_version_is_refused(self, tmp_path):
        renderer = _renderer()
        with pytest.raises(renderer.FormulaShapeError, match="must be named"):
            self._render(_formula(), tmp_path / "ash.tar.gz")

    def test_a_relative_tarball_path_is_refused(self):
        renderer = _renderer()
        with pytest.raises(renderer.FormulaShapeError, match="absolute"):
            self._render(_formula(), Path("automated-security-helper-3.7.0.tar.gz"))

    @pytest.mark.parametrize("count", [0, 2])
    def test_a_formula_without_exactly_one_tag_url_is_refused(self, tmp_path, count):
        renderer = _renderer()
        line = '  url "https://github.com/awslabs/automated-security-helper.git", tag: "v3.7.0"\n'
        formula = "class Ash < Formula\n" + line * count + "end\n"
        with pytest.raises(renderer.FormulaShapeError, match=f"found {count}"):
            self._render(formula, tmp_path / "automated-security-helper-3.7.0.tar.gz")

    def test_the_command_line_writes_the_copy(self, tmp_path):
        tarball = tmp_path / "automated-security-helper-3.7.0.tar.gz"
        tarball.write_bytes(b"not really a tarball")
        out = tmp_path / "tap" / "Formula" / "ash.rb"

        rc = _renderer().main(
            [
                "--formula",
                str(FORMULA_PATH),
                "--tarball",
                str(tarball),
                "--version",
                "3.7.0",
                "--out",
                str(out),
            ]
        )

        assert rc == 0
        text = out.read_text(encoding="utf-8")
        assert f'url "{tarball.resolve().as_uri()}"' in text
        # The digest of this tarball, not just any 64 hex digits: Homebrew refuses
        # an install whose download does not match it.
        digest = hashlib.sha256(tarball.read_bytes()).hexdigest()
        assert re.findall(r'^  sha256 "([0-9a-f]+)"$', text, re.MULTILINE) == [digest]


# ---------------------------------------------------------------------------
# def install, run under Ruby with Homebrew's API stood in for
# ---------------------------------------------------------------------------

#: Just enough of Homebrew for Formula/ash.rb to load and run `def install`. The
#: virtualenv is a directory, `system` records its argv, and `uv sync` lays out
#: what uv writes for a non-editable install from a directory: a dist-info with a
#: direct_url.json naming the build directory.
STAND_IN_HOMEBREW = r"""
require "fileutils"
require "json"
require "pathname"
require "tmpdir"

module Language
  module Python
    module Virtualenv
      Venv = Struct.new(:root)

      def virtualenv_create(dir, _python, system_site_packages: true)
        FileUtils.mkdir_p(dir / "bin")
        Venv.new(Pathname(dir))
      end
    end
  end
end

class Pathname
  def write_env_script(target, env)
    dirname.mkpath
    write("#!/bin/sh\n# #{target} #{env}\n")
  end
end

class Formula
  include FileUtils

  class << self
    %i[desc homepage url license depends_on test sha256 head livecheck preserve_rpath].each do |name|
      define_method(name) { |*_args, **_kwargs, &_block| nil }
    end

    def [](_name)
      Struct.new(:opt_bin).new(Pathname("/opt/node/bin"))
    end
  end

  def initialize(prefix)
    @prefix = Pathname(prefix)
  end

  def libexec
    @prefix / "libexec"
  end

  def bin
    @prefix / "bin"
  end

  def buildpath
    @prefix.parent / "build-dir"
  end

  def odie(message)
    raise message
  end

  def system(*args)
    File.open(ENV.fetch("STANDIN_SYSTEM_LOG"), "a") { |log| log.puts(args.join(" ")) }
    return true unless args.first(2) == %w[uv sync]

    File.write(
      ENV.fetch("STANDIN_SYNC_ENV"),
      JSON.generate(ENV.to_h.select { |key, _| key.start_with?("UV_") })
    )
    site = Pathname(ENV.fetch("UV_PROJECT_ENVIRONMENT")) / "lib/python3.12/site-packages"
    Integer(ENV.fetch("STANDIN_DIST_INFOS", "1")).times do |n|
      dist = site / "automated_security_helper-3.7.#{n}.dist-info"
      FileUtils.mkdir_p(dist)
      (dist / "METADATA").write("Name: automated-security-helper\n")
      (dist / "direct_url.json").write(
        JSON.generate({ "url" => "file://#{buildpath}", "dir_info" => {} })
      )
    end
    true
  end
end

load ARGV.fetch(0)
Ash.new(ARGV.fetch(1)).install
"""


@pytest.mark.skipif(
    os.name == "nt" or shutil.which("ruby") is None,
    reason="Homebrew runs on macOS and Linux only",
)
class TestTheInstallLeavesNoBuildPathBehind:
    """uv records where it built ASH from, and that is Homebrew's build directory.

    `uv sync --no-editable` writes a direct_url.json naming the directory it built
    the package from. For the formula that is a build directory under Homebrew's
    temporary directory, which Homebrew deletes after the install, so the record
    names a directory that no longer holds ASH's source and that a container scan
    must not build from. The install
    deletes that record, so the install is resolved like one from an index: by the
    commit its package build recorded.
    """

    @staticmethod
    def _install(
        tmp_path: Path, dist_infos: int = 1
    ) -> tuple[subprocess.CompletedProcess, Path]:
        harness = tmp_path / "stand_in_homebrew.rb"
        harness.write_text(STAND_IN_HOMEBREW, encoding="utf-8")
        prefix = tmp_path / "Cellar" / "ash" / "3.7.0"
        env = {
            **os.environ,
            "STANDIN_SYSTEM_LOG": str(tmp_path / "system.log"),
            "STANDIN_SYNC_ENV": str(tmp_path / "sync-env.json"),
            "STANDIN_DIST_INFOS": str(dist_infos),
        }
        for key in [k for k in env if k.startswith("UV_")]:
            del env[key]
        proc = subprocess.run(  # nosec B603 B607 - ruby on a fixed harness, list args
            ["ruby", str(harness), str(FORMULA_PATH), str(prefix)],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return proc, prefix

    def test_no_direct_url_json_is_left_for_ash(self, tmp_path):
        proc, prefix = self._install(tmp_path)

        assert proc.returncode == 0, proc.stderr
        [dist_info] = (prefix / "libexec").glob(
            "lib/python*/site-packages/automated_security_helper-*.dist-info"
        )
        assert (dist_info / "METADATA").is_file(), "the dist-info itself is kept"
        assert not (dist_info / "direct_url.json").exists()
        system = (tmp_path / "system.log").read_text(encoding="utf-8")
        assert system.startswith("uv sync --frozen")

    def test_uv_sync_runs_with_the_formulas_settings(self, tmp_path):
        """What uv sees when it runs, not what the text says: a setting commented
        out or moved below `uv sync` reaches no uv."""
        proc, prefix = self._install(tmp_path)

        assert proc.returncode == 0, proc.stderr
        env = json.loads((tmp_path / "sync-env.json").read_text(encoding="utf-8"))
        assert env["UV_PROJECT_ENVIRONMENT"] == str(prefix / "libexec")
        assert env["UV_PYTHON_DOWNLOADS"] == "never"
        assert env["UV_NO_CONFIG"] == "1"
        assert env["UV_LINK_MODE"] == "copy"

    def test_uv_caches_outside_the_source_tree(self, tmp_path: Path) -> None:
        """A cache under buildpath raced hatchling's walk of the project root.

        See TestTheBuildBackendSkipsTheUvCache for the walk. The stand-in's
        buildpath is <prefix>/../build-dir, and uv must see a UV_CACHE_DIR that is
        not under it. The directory goes with the build: Homebrew deletes its
        build directory, and a cache elsewhere has to be deleted by the formula.
        """
        proc, prefix = self._install(tmp_path)

        assert proc.returncode == 0, proc.stderr
        env = json.loads((tmp_path / "sync-env.json").read_text(encoding="utf-8"))
        cache = Path(env["UV_CACHE_DIR"])
        assert cache.is_absolute()
        assert not cache.is_relative_to(prefix.parent / "build-dir"), (
            f"uv's cache {cache} is under the build directory hatchling walks"
        )
        assert not cache.exists(), "uv's cache was not deleted after the install"

    @pytest.mark.parametrize("dist_infos", [0, 2])
    def test_an_unexpected_layout_fails_the_install(self, tmp_path, dist_infos):
        """A record left behind silently is the defect, so a layout the deletion
        does not recognize stops the install instead of passing it."""
        proc, _prefix = self._install(tmp_path, dist_infos=dist_infos)

        assert proc.returncode != 0
        # The formula's own message, with the count: "automated_security_helper"
        # alone also matches the source line in a Ruby traceback.
        assert f"automated_security_helper dist-info, found {dist_infos}" in proc.stderr
