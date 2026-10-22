# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which ASH revision a container image build installs, and that it can be cloned.

Why this file exists
--------------------
A non-LOCAL image build clones ASH at ``INSTALL_ASH_REVISION`` in the Dockerfile's
``uv-reqs`` stage. Two kinds of install need care there.

* An installation that records no git source.
  A Homebrew install has no direct_url.json, an install from an archive URL or a
  package file records no revision; for these the package build records the commit
  it was built from in assets/ASH_INSTALLED_REVISION (a build without git records
  "unknown-commit", which counts as nothing recorded), and
  the image build fetches that commit. Only with nothing recorded does it fall back
  to ``v<version>``, with a warning that this is a guess (an unreleased commit
  carries the previous release's version); a version that is not a release is
  refused with a message naming --ash-revision-to-install. The version comes from
  the dist-info beside the running package, never from importlib.metadata, which a
  dist-info directory committed in the scanned repository can answer first.
* An install from a git URL with no ref records only a commit id, and ``git clone
  --branch <commit id>`` cannot check one out. The Dockerfile checks a full commit
  id out of a clone of ASH's branches and tags, and refuses one that none of them
  reaches. A failed clone fails the clone step itself, so the build stops there,
  before ``uv build``.

test_container_clone_step_runs.py runs the clone step under sh, and
test_container_branch_build_reclones.py covers its cache. No image is built and
nothing is fetched from the network: the commit-id cases in
test_container_clone_step_runs.py clone a local repository.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, List
from urllib.error import URLError

import pytest

from automated_security_helper.core import constants
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import get_ash_revision
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "Dockerfile"

# What get_ash_revision checks beside the package to recognize a full clone.
_CHECKOUT_MARKERS = frozenset(
    {
        ".github",
        ".gitignore",
        ".dockerignore",
        "Dockerfile",
        "pyproject.toml",
        "NOTICE",
        "docs",
        "tests",
    }
)

COMMIT_ID = "0123456789abcdef0123456789abcdef01234567"


class _Install:
    """An ASH installed outside a checkout, with what it recorded under test control."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        self._monkeypatch = monkeypatch
        self.module = ModuleType("automated_security_helper")
        package_dir = tmp_path / "site-packages" / "automated_security_helper"
        package_dir.mkdir(parents=True)
        self.module.__path__ = [package_dir.as_posix()]
        self.module.__version__ = "3.7.0"
        monkeypatch.setattr(rac, "import_module", lambda name: self.module)
        self.dist_info = (
            package_dir.parent / "automated_security_helper-3.7.0.dist-info"
        )
        self.dist_info.mkdir()
        self.built_with("unknown-commit")

    def version(self, version: str) -> "_Install":
        """The installed version: the name of the dist-info beside the package."""
        self.module.__version__ = version
        renamed = self.dist_info.with_name(
            f"automated_security_helper-{version}.dist-info"
        )
        self.dist_info.rename(renamed)
        self.dist_info = renamed
        return self

    def built_with(self, recorded: str) -> "_Install":
        """What the build wrote into assets/ASH_INSTALLED_REVISION."""
        self._monkeypatch.setattr(rac, "ASH_REPO_LATEST_REVISION", recorded)
        return self

    def direct_url(self, record: Any) -> "_Install":
        self.dist_info.joinpath("direct_url.json").write_text(
            record if isinstance(record, str) else json.dumps(record), encoding="utf-8"
        )
        return self


class _Log:
    """Stands in for ASH_LOGGER, which does not propagate to pytest's capture."""

    def __init__(self) -> None:
        self.records: List[tuple] = []

    def __getattr__(self, level):
        return lambda message, *args, **kwargs: self.records.append((level, message))

    def warnings(self) -> List[str]:
        return [message for level, message in self.records if level == "warning"]


@pytest.fixture
def log(monkeypatch) -> _Log:
    recorder = _Log()
    monkeypatch.setattr(rac, "ASH_LOGGER", recorder)
    return recorder


@pytest.fixture
def unreadable_tree(monkeypatch, tmp_path) -> Path:
    """An ASH source tree whose files cannot be looked at: every stat raises EACCES.

    As under a parent directory made unreadable. Path.is_file re-raises EACCES and
    ESTALE on 3.10 to 3.13; it is made to raise here on every version.
    """
    tree = tmp_path / "unreadable-ash-src"
    tree.mkdir()
    (tree / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (tree / "pyproject.toml").write_text(
        '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
    )
    for name in ("is_file", "exists", "is_dir"):
        real = getattr(Path, name)

        def refuse(self, *args, _real=real, **kwargs):
            if tree in (self, *self.parents):
                raise PermissionError(13, "Permission denied", str(self))
            return _real(self, *args, **kwargs)

        monkeypatch.setattr(Path, name, refuse)
    return tree


@pytest.fixture
def installed(monkeypatch, tmp_path) -> _Install:
    """get_ash_revision past its checkout test, the way a pip or Homebrew install is.

    This suite runs from a clone, so the eight markers exist beside the real package.
    Only those eight paths are reported absent.
    """
    checkout = Path(rac.__file__).parent.parent.parent
    real_exists = Path.exists

    def exists(self, *args, **kwargs):
        if self.parent == checkout and self.name in _CHECKOUT_MARKERS:
            return False
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", exists)
    return _Install(monkeypatch, tmp_path)


# ---------------------------------------------------------------------------
# NEW-13: an installation that records no git source
# ---------------------------------------------------------------------------


class TestNothingRecordedBuildsTheReleaseTag:
    @pytest.mark.parametrize(
        "recorded",
        [
            "unknown-commit",
            "no-git-available",
            "build-error",
            "HEAD",
            "",
            "ERROR: Unexpected error\nboom",
        ],
    )
    def test_with_nothing_recorded_the_release_tag_is_a_logged_guess(
        self, installed, log, recorded
    ):
        """No direct_url.json, and the build recorded a placeholder, not a ref."""
        installed.built_with(recorded)

        assert get_ash_revision() == "v3.7.0"
        [warning] = log.warnings()
        assert "v3.7.0" in warning and "guess" in warning

    def test_a_missing_asset_reads_as_nothing_recorded(self, tmp_path):
        """A missing asset reads as "unknown-commit", which names no ref."""
        recorded = constants._installed_revision(tmp_path / "ASH_INSTALLED_REVISION")

        assert recorded == "unknown-commit"
        assert not rac._names_a_ref(recorded)

    def test_the_commit_the_package_was_built_from_is_built(self, installed, log):
        """hatch_build.py records the commit; the Dockerfile checks it out of a clone
        of ASH's branches and tags."""
        installed.built_with(COMMIT_ID)

        assert get_ash_revision() == COMMIT_ID
        assert log.warnings() == []

    def test_a_package_file_install_builds_what_its_build_recorded(self, installed):
        """`pip install ./ash.whl` records file:// with archive_info: not a tree."""
        installed.built_with(COMMIT_ID).direct_url(
            {"url": "file:///tmp/dist/ash-3.7.0-py3-none-any.whl", "archive_info": {}}
        )

        assert get_ash_revision() == COMMIT_ID

    def test_a_directory_install_whose_directory_is_gone_builds_its_commit(
        self, installed, tmp_path
    ):
        """`pip install ./ash` then `rm -rf ash`: the record names nothing on disk.

        It does not read as LOCAL, so no build looks for a Dockerfile in the working
        directory, which is usually the repository being scanned.
        """
        installed.built_with(COMMIT_ID).direct_url(
            {"url": (tmp_path / "deleted-ash-src").as_uri(), "dir_info": {}}
        )

        assert get_ash_revision() == COMMIT_ID

    def test_a_directory_install_of_a_tree_that_is_not_ash_builds_its_commit(
        self, installed, tmp_path
    ):
        """A directory at the recorded path that is not ASH's source is no source."""
        other = tmp_path / "reused-path"
        other.mkdir()
        (other / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
        (other / "pyproject.toml").write_text(
            '[project]\nname = "someone-else"\n', encoding="utf-8"
        )
        installed.built_with(COMMIT_ID).direct_url(
            {"url": other.as_uri(), "dir_info": {}}
        )

        assert get_ash_revision() == COMMIT_ID

    def test_a_recorded_directory_that_cannot_be_read_builds_its_commit(
        self, installed, unreadable_tree
    ):
        """A stat that fails with EACCES (a parent made unreadable) or ESTALE does
        not escape get_ash_revision as an OSError."""
        installed.built_with(COMMIT_ID).direct_url(
            {"url": unreadable_tree.as_uri(), "dir_info": {}}
        )

        assert get_ash_revision() == COMMIT_ID

    def test_an_unreadable_tree_is_not_an_ash_source_tree(self, unreadable_tree):
        """On its own, not only through get_ash_revision, whose except also catches
        OSError: the explicit-LOCAL path below reaches this with no except around."""
        assert rac._is_ash_source_tree(unreadable_tree) is False

    def test_a_record_that_cannot_be_read_builds_the_recorded_commit(
        self, installed, monkeypatch
    ):
        installed.built_with(COMMIT_ID).direct_url({"url": "file:///x", "dir_info": {}})
        record = installed.dist_info / "direct_url.json"
        real_read_text = Path.read_text

        def read_text(self, *args, **kwargs):
            if self == record:
                raise PermissionError(13, "Permission denied", str(self))
            return real_read_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "read_text", read_text)

        assert get_ash_revision() == COMMIT_ID

    def test_a_record_that_cannot_be_looked_at_builds_the_recorded_commit(
        self, installed, monkeypatch
    ):
        """The stat of direct_url.json itself raising EACCES, before any read."""
        installed.built_with(COMMIT_ID).direct_url({"url": "file:///x", "dir_info": {}})
        record = installed.dist_info / "direct_url.json"
        for name in ("is_file", "exists"):
            real = getattr(Path, name)

            def refuse(self, *args, _real=real, **kwargs):
                if self == record:
                    raise PermissionError(13, "Permission denied", str(self))
                return _real(self, *args, **kwargs)

            monkeypatch.setattr(Path, name, refuse)

        assert get_ash_revision() == COMMIT_ID

    def test_a_file_url_the_platform_cannot_turn_into_a_path_is_not_followed(
        self, installed, monkeypatch
    ):
        """On Python 3.14, url2pathname raises URLError for `file:////server/share`."""

        def url2pathname(_path):
            raise URLError("URL '//server/share/ash' is a UNC path")

        monkeypatch.setattr(rac, "url2pathname", url2pathname)
        installed.built_with(COMMIT_ID).direct_url(
            {"url": "file:////server/share/ash", "dir_info": {}}
        )

        assert rac._file_url_path("file:////server/share/ash") is None
        assert get_ash_revision() == COMMIT_ID

    def test_a_directory_install_of_an_ash_tree_is_local(self, installed, tmp_path):
        tree = tmp_path / "ash-src"
        tree.mkdir()
        (tree / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tree / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )
        installed.built_with(COMMIT_ID).direct_url(
            {"url": tree.as_uri(), "dir_info": {}}
        )

        assert get_ash_revision() == "LOCAL"

    def test_a_planted_dist_info_cannot_choose_the_tag(
        self, monkeypatch, installed, tmp_path
    ):
        """The version comes from the dist-info beside the package, not sys.path.

        `python -m automated_security_helper` from a repository that commits an
        automated_security_helper-9.9.9.dist-info puts that first on sys.path, and
        importlib.metadata, which __version__ comes from, then reports 9.9.9.
        """
        planted_root = tmp_path / "scanned"
        planted = planted_root / "automated_security_helper-9.9.9.dist-info"
        planted.mkdir(parents=True)
        (planted / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: automated-security-helper\nVersion: 9.9.9\n",
            encoding="utf-8",
        )
        monkeypatch.syspath_prepend(str(planted_root))
        import importlib.metadata

        assert importlib.metadata.version("automated-security-helper") == "9.9.9"
        installed.module.__version__ = "9.9.9"

        assert get_ash_revision() == "v3.7.0"

    def test_an_archive_url_install_with_nothing_recorded_builds_the_release_tag(
        self, installed
    ):
        """`pip install https://.../v3.7.0.tar.gz` records a URL and no revision."""
        installed.direct_url(
            {
                "url": "https://github.com/awslabs/automated-security-helper/archive/refs/tags/v3.7.0.tar.gz",
                "archive_info": {},
            }
        )

        assert get_ash_revision() == "v3.7.0"

    def test_a_record_of_the_wrong_shape_builds_the_release_tag(self, installed):
        installed.direct_url([1, 2, 3])

        assert get_ash_revision() == "v3.7.0"

    @pytest.mark.parametrize(
        "version",
        ["3.7.1.dev3", "3.8.0rc1", "3.7.0.post1", "3.7.0+g1a2b3c4", "unknown"],
    )
    def test_a_version_that_is_not_a_release_has_no_revision(self, installed, version):
        """None of these has a tag, and another revision would be another ASH."""
        installed.version(version)

        assert get_ash_revision() is None

    def test_a_recorded_branch_is_built_with_a_warning(self, installed, log):
        """A package built before commit ids were recorded names its branch."""
        installed.built_with("main")

        assert get_ash_revision() == "main"
        [warning] = log.warnings()
        assert "'main'" in warning and "tip" in warning

    def test_a_git_file_url_with_a_ref_builds_that_ref_from_the_ash_repository(
        self, installed
    ):
        """`git+file:///path/repo@v3.6.1` names a ref; the image clones it from GitHub."""
        installed.direct_url(
            {
                "url": "git+file:///home/me/ash",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "v3.6.1",
                    "commit_id": COMMIT_ID,
                },
            }
        )

        assert get_ash_revision() == "v3.6.1"

    def test_a_requested_git_revision_is_built(self, installed):
        installed.direct_url(
            {
                "url": "git+https://github.com/awslabs/automated-security-helper.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "v3.6.1",
                    "commit_id": COMMIT_ID,
                },
            }
        )

        assert get_ash_revision() == "v3.6.1"

    def test_a_git_url_with_no_ref_builds_its_commit(self, installed):
        installed.direct_url(
            {
                "url": "git+https://github.com/awslabs/automated-security-helper.git",
                "vcs_info": {"vcs": "git", "commit_id": COMMIT_ID},
            }
        )

        assert get_ash_revision() == COMMIT_ID


@pytest.fixture
def container_runtime(monkeypatch, tmp_path) -> Dict[str, List[List[str]]]:
    """Recorders in place of the runtime: every build and run argv, nothing executed."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    seen: Dict[str, List[List[str]]] = {"build": [], "run": []}

    def fake_run_cmd_direct(cmd_list, check=True, debug=False, shell=False):
        seen["build"].append([str(item) for item in cmd_list])
        return create_completed_process(args=list(cmd_list), returncode=0)

    def fake_execute(cmd, debug=False, env=None):
        seen["run"].append([str(item) for item in cmd])
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", fake_run_cmd_direct)
    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in (
        "CI",
        "IsCI",
        "ISCI",
        "CODEBUILD_BUILD_ID",
        "ASH_IMAGE_NAME",
        "ASH_BASE_IMAGE_OVERRIDE",
        "ASH_BASE_OCI_LAYOUT",
        "ACTIONS_RUNTIME_TOKEN",
        "OCI_RUNNER_WRAPPER",
    ):
        monkeypatch.delenv(name, raising=False)
    return seen


def _build_args(argv: List[str]) -> List[str]:
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == "--build-arg"]


def _assets_dockerfile() -> str:
    """ASH's packaged Dockerfile as the build command names it: in POSIX form."""
    return (rac.ASH_ASSETS_DIR / "Dockerfile").as_posix()


def _assert_local_is_refused(container_runtime) -> None:
    """An explicit LOCAL build of the same install is refused, and builds nothing."""
    builds_before = list(container_runtime["build"])

    result = rac.run_ash_container(
        source_dir="src", build=True, run=False, ash_revision_to_install="LOCAL"
    )

    assert result.returncode == 1, result.stderr
    assert not rac.container_was_started(result)
    assert "a LOCAL revision builds the ASH source tree" in result.stderr
    assert container_runtime["build"] == builds_before


class TestTheBuildCommand:
    def test_a_deleted_install_directory_never_builds_the_working_directory(
        self, installed, container_runtime, tmp_path
    ):
        """The scanned repository's Dockerfile is not ASH's, whatever the record says.

        The working directory here is tmp_path, with a Dockerfile and a
        pyproject.toml of its own, as a scanned Python project has.
        """
        (tmp_path / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "scanned"\n', encoding="utf-8"
        )
        installed.built_with(COMMIT_ID).direct_url(
            {"url": (tmp_path / "deleted-ash-src").as_uri(), "dir_info": {}}
        )

        result = rac.run_ash_container(source_dir="src", build=True, run=False)

        assert result.returncode == 0
        [build] = container_runtime["build"]
        assert "INSTALL_ASH_REVISION=" + COMMIT_ID in _build_args(build)
        assert build[build.index("--file") + 1] == _assets_dockerfile()
        assert build[-1] == rac.ASH_ASSETS_DIR.as_posix()
        assert (tmp_path / "Dockerfile").as_posix() not in build

    def test_a_tree_planted_at_a_homebrew_build_path_is_not_built(
        self, installed, container_runtime, tmp_path
    ):
        """Why Formula/ash.rb deletes the install's direct_url.json.

        uv records the build directory, under Homebrew's temporary directory, and
        Homebrew deletes it after the install. Whoever creates that path again with
        an ASH-named tree would have it built as LOCAL while the record is there, so
        the formula deletes the record, and the image installs the commit the
        package build recorded, from ASH's packaged Dockerfile.
        """
        planted = tmp_path / "tmp" / "ash-20261011-1234-abcdef"
        planted.mkdir(parents=True)
        (planted / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
        (planted / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )
        installed.built_with(COMMIT_ID).direct_url(
            {"url": planted.as_uri(), "dir_info": {}}
        )
        assert get_ash_revision() == "LOCAL", "the record is what made it LOCAL"
        installed.dist_info.joinpath("direct_url.json").unlink()

        result = rac.run_ash_container(source_dir="src", build=True, run=False)

        assert result.returncode == 0
        [build] = container_runtime["build"]
        assert "INSTALL_ASH_REVISION=" + COMMIT_ID in _build_args(build)
        assert build[build.index("--file") + 1] == _assets_dockerfile()
        assert not [arg for arg in build if planted.as_posix() in arg]

    @pytest.mark.parametrize("url", ["file://", "file://localhost", "file:"])
    def test_a_record_with_no_path_does_not_name_the_working_directory(
        self, installed, container_runtime, tmp_path, url
    ):
        """`file://` holds no path, and Path(url2pathname("")) is Path("."): the
        working directory, which is the project being scanned. With an ASH-named
        tree there, such a record does not read as LOCAL, and "." is never the
        build context.

        `file:` never reaches _file_url_path from a record: both callers first
        require the URL to start with "file://". For it, the end-to-end checks
        hold without the fix, and only the helper assertion covers it."""
        (tmp_path / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )
        installed.built_with(COMMIT_ID).direct_url({"url": url, "dir_info": {}})

        result = rac.run_ash_container(source_dir="src", build=True, run=False)

        assert result.returncode == 0
        [build] = container_runtime["build"]
        assert "INSTALL_ASH_REVISION=" + COMMIT_ID in _build_args(build)
        assert build[build.index("--file") + 1] == _assets_dockerfile()
        assert rac._file_url_path(url) is None
        _assert_local_is_refused(container_runtime)

    @staticmethod
    def _assert_the_working_directory_is_not_built(
        installed, container_runtime, tmp_path, url
    ):
        """With an ASH-named tree in the working directory (and in sub/), a record
        of ``url`` builds the recorded commit from ASH's packaged Dockerfile, and an
        explicit LOCAL build is refused."""
        for tree in (tmp_path, tmp_path / "sub"):
            tree.mkdir(exist_ok=True)
            (tree / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
            (tree / "pyproject.toml").write_text(
                '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
            )
        installed.built_with(COMMIT_ID).direct_url({"url": url, "dir_info": {}})

        result = rac.run_ash_container(source_dir="src", build=True, run=False)

        assert result.returncode == 0
        [build] = container_runtime["build"]
        assert "INSTALL_ASH_REVISION=" + COMMIT_ID in _build_args(build)
        assert build[build.index("--file") + 1] == _assets_dockerfile()
        _assert_local_is_refused(container_runtime)

    @pytest.mark.parametrize(
        "path",
        [
            "/proc/self/cwd",
            "/proc/thread-self/cwd",
            "/proc/self/cwd/sub",
            # The same directory, spelled so that its first component is not "proc".
            "/dev/../proc/self/cwd",
            "/tmp/../proc/self/cwd",
            "/dev/%2E%2E/proc/self/cwd",
            "/%2Fproc/self/cwd",
            # On 3.10 url2pathname keeps the doubled slash; 3.14 raises for it.
            "//proc/self/cwd",
        ],
    )
    @pytest.mark.parametrize("host", ["", "localhost"])
    def test_a_record_naming_the_working_directory_by_proc_is_not_followed(
        self, installed, container_runtime, tmp_path, path, host
    ):
        """`/proc/self/cwd` is an absolute path to whatever directory ASH runs in,
        the project being scanned, and docker resolves the build context through
        it, so a record naming it does not read as LOCAL. A "..", a doubled slash
        or an escaped slash does not get the same directory past the check."""
        self._assert_the_working_directory_is_not_built(
            installed, container_runtime, tmp_path, f"file://{host}{path}"
        )

    @pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges there")
    @pytest.mark.parametrize("host", ["", "localhost"])
    def test_a_record_naming_a_link_to_proc_is_not_followed(
        self, installed, container_runtime, tmp_path, host
    ):
        """A link anywhere, here outside the scanned tree, to /proc/self/cwd names
        the working directory too, and no lexical check of the recorded path can
        see it. Resolving the link would not either: /proc/self/cwd resolves to
        the working directory's own path."""
        link = tmp_path / "elsewhere" / "cwd-link"
        link.parent.mkdir()
        os.symlink("/proc/self/cwd", link)

        self._assert_the_working_directory_is_not_built(
            installed, container_runtime, tmp_path, f"file://{host}{link.as_posix()}"
        )

    @pytest.mark.skipif(os.name == "nt", reason="no /dev/fd and no O_DIRECTORY there")
    @pytest.mark.parametrize("host", ["", "localhost"])
    def test_a_record_naming_an_open_descriptor_of_it_is_not_followed(
        self, installed, container_runtime, tmp_path, host
    ):
        """/dev/fd/N names whatever descriptor N has open, here the working
        directory itself. A fixed /dev/fd/3 named whatever the test worker had
        open as 3, which was not the working directory, so that case passed with
        the check removed."""
        descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            self._assert_the_working_directory_is_not_built(
                installed,
                container_runtime,
                tmp_path,
                f"file://{host}/dev/fd/{descriptor}",
            )
        finally:
            os.close(descriptor)

    def test_a_homebrew_install_builds_its_release_tag(
        self, installed, container_runtime
    ):
        """The build passes the release tag, never INSTALL_ASH_REVISION=unknown-commit."""
        result = rac.run_ash_container(source_dir="src", build=True, run=False)

        assert result.returncode == 0
        [build] = container_runtime["build"]
        assert "INSTALL_ASH_REVISION=v3.7.0" in _build_args(build)

    def test_a_version_with_no_tag_is_refused_before_any_build(
        self, installed, container_runtime
    ):
        installed.version("3.7.1.dev3")

        result = rac.run_ash_container(source_dir="src", build=True, run=True)

        assert result.returncode == 1
        assert not rac.container_was_started(result)
        assert "--ash-revision-to-install" in result.stderr
        assert "full commit id" in result.stderr
        assert "3.7.1.dev3" in result.stderr
        assert container_runtime == {"build": [], "run": []}

    def test_a_requested_revision_needs_nothing_recorded(
        self, installed, container_runtime
    ):
        installed.version("3.7.1.dev3")

        result = rac.run_ash_container(
            source_dir="src", build=True, run=False, ash_revision_to_install="v3.7.0"
        )

        assert result.returncode == 0
        [build] = container_runtime["build"]
        assert "INSTALL_ASH_REVISION=v3.7.0" in _build_args(build)

    def test_an_explicit_revision_does_not_log_a_local_source_build(
        self, container_runtime, log
    ):
        """Run from a clone, the install would resolve to LOCAL; a named revision
        decides the build instead, so only that revision is named."""
        result = rac.run_ash_container(
            source_dir="src", build=True, run=False, ash_revision_to_install="main"
        )

        assert result.returncode == 0, result.stderr
        messages = [message for _level, message in log.records]
        assert not [m for m in messages if "building with LOCAL source" in m], messages
        assert any("ASH revision main" in m for m in messages), messages
        [build] = container_runtime["build"]
        assert "INSTALL_ASH_REVISION=main" in _build_args(build)

    def test_a_build_with_no_named_revision_logs_the_local_source_it_builds(
        self, container_runtime, log
    ):
        """Control: from a clone with no revision named, the LOCAL line is logged."""
        rac.run_ash_container(source_dir="src", build=True, run=False)

        messages = [message for _level, message in log.records]
        assert any("building with LOCAL source" in m for m in messages), messages

    def test_a_refused_revision_never_reaches_the_provenance_line_raw(
        self, container_runtime, log
    ):
        """The provenance line prints only after the revision passed
        validation, so a value carrying a control character is named by the
        escaping refusal alone and no log line emits it raw."""
        bad = "main\x1b[2Jx"
        result = rac.run_ash_container(
            source_dir="src", build=True, run=False, ash_revision_to_install=bad
        )

        assert result.returncode == 1
        assert "Invalid ASH revision value" in result.stderr
        messages = [message for _level, message in log.records]
        assert not [m for m in messages if "\x1b" in m], messages
        assert not [m for m in messages if "Building with ASH revision" in m], messages

    @pytest.mark.parametrize(
        "kwargs",
        [
            pytest.param({"build": False, "run": True}, id="no-build"),
            pytest.param(
                {"build": True, "run": False, "ash_revision_to_install": "v3.7.0"},
                id="explicit-revision",
            ),
            pytest.param({"build": True, "run": False}, id="resolved-revision"),
        ],
    )
    def test_an_unreadable_recorded_directory_does_not_stop_the_run(
        self, installed, container_runtime, unreadable_tree, kwargs
    ):
        """run_ash_container resolves the revision before it looks at --no-build or
        --ash-revision-to-install, so the OSError stopped those runs too."""
        installed.built_with(COMMIT_ID).direct_url(
            {"url": unreadable_tree.as_uri(), "dir_info": {}}
        )

        result = rac.run_ash_container(source_dir="src", **kwargs)

        assert result.returncode == 0, result.stderr
        if kwargs["build"]:
            [build] = container_runtime["build"]
            expected = kwargs.get("ash_revision_to_install", COMMIT_ID)
            assert "INSTALL_ASH_REVISION=" + expected in _build_args(build)

    def test_an_explicit_local_build_of_an_unreadable_tree_is_refused(
        self, installed, container_runtime, unreadable_tree
    ):
        """`--ash-revision-to-install LOCAL` reaches the tree through
        _local_source_tree, whose lookup catches only a failed read of the record:
        an OSError from the tree escaped here as a traceback, not a refusal."""
        installed.built_with(COMMIT_ID).direct_url(
            {"url": unreadable_tree.as_uri(), "dir_info": {}}
        )

        result = rac.run_ash_container(
            source_dir="src", build=True, run=False, ash_revision_to_install="LOCAL"
        )

        assert result.returncode == 1
        assert not rac.container_was_started(result)
        assert "a LOCAL revision builds the ASH source tree" in result.stderr
        assert container_runtime == {"build": [], "run": []}

    def test_no_build_needs_no_revision(self, installed, container_runtime):
        """--no-build runs the image already there; nothing is installed into one."""
        installed.version("3.7.1.dev3")

        result = rac.run_ash_container(source_dir="src", build=False, run=True)

        assert result.returncode == 0
        assert container_runtime["build"] == []
        assert len(container_runtime["run"]) == 1


# ---------------------------------------------------------------------------
# The Dockerfile side
# ---------------------------------------------------------------------------


def _stage(name: str) -> List[str]:
    lines = DOCKERFILE.read_text(encoding="utf-8").splitlines()
    start = next(
        i for i, line in enumerate(lines) if re.match(rf"FROM \S+ AS {name}\b", line)
    )
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("FROM ")),
        len(lines),
    )
    return lines[start:end]


def _instructions(lines: List[str]) -> List[str]:
    """The stage's instructions, continuation lines joined, comments dropped."""
    instructions: List[str] = []
    current = ""
    for line in lines:
        if not current and (not line.strip() or line.lstrip().startswith("#")):
            continue
        current += line.rstrip("\\").rstrip() + " " if line.endswith("\\") else line
        if not line.endswith("\\"):
            instructions.append(current.strip())
            current = ""
    return instructions


def _clone_step() -> str:
    [step] = [
        i
        for i in _instructions(_stage("uv-reqs"))
        if "INSTALL_ASH_REVISION" in i and i.startswith("RUN ")
    ]
    return step


class TestTheDockerfileCloneStep:
    def test_a_failed_clone_fails_the_step(self):
        """`|| echo "Skipping clone..."` after the clone made a failed clone pass."""
        assert "||" not in _clone_step()

    def test_each_kind_of_revision_has_its_command(self):
        step = _clone_step()

        assert 'if [ "${INSTALL_ASH_REVISION}" = "LOCAL" ]; then' in step
        # What the TOML check decides is pinned by running it, in
        # test_container_clone_step_runs.py; this pins only that it is there.
        assert "elif python3 -c 'import re, sys;" in step
        assert "/ash-context/pyproject.toml 2>/dev/null; then" in step
        # A commit id: which ones are built is pinned by running the step against a
        # local repository, in test_container_clone_step_runs.py.
        assert (
            'git clone --quiet --filter=blob:none --no-checkout "${ASH_REPO_CLONE_URL}" .'
            in step
        )
        assert 'git checkout --quiet --detach "${INSTALL_ASH_REVISION}"' in step
        # Nothing fetches by id, which on GitHub reaches a commit only a fork holds.
        assert "git fetch" not in step
        assert (
            'git clone --branch "${INSTALL_ASH_REVISION}" "${ASH_REPO_CLONE_URL}" .'
            in step
        )
