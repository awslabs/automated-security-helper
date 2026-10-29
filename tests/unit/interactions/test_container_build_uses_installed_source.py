# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A container build builds ASH's own Dockerfile, never the working directory's.

Why this file exists
--------------------
`get_ash_revision` returns LOCAL when ASH's package directory sits inside a
checkout (an editable install, or running from source), or when the dist-info's
direct_url.json names a `file://` directory that holds an ASH source tree, which
is what `pip install <dir>` records. That second case is how pre-commit installs a
`language: python` hook: `pip install .` inside its clone of the hook repository.

For a hook, or for an editable install run from another project, the working
directory is the repository being scanned, so no build, LOCAL or pinned, takes a
Dockerfile from it or from a directory above it holding both a Dockerfile and a
pyproject.toml: a scanned repository does not get to build the image that scans it
and have it tagged as ASH's.

A LOCAL revision builds the ASH source tree the running package comes from
(`_local_source_tree`): the checkout around it, or the directory direct_url.json
records. Either must hold a Dockerfile and a pyproject.toml whose [project] name
is automated-security-helper, and the directory an installer put ASH in
(site-packages, or one holding ASH's dist-info) is never taken for a checkout.
With neither, the build is refused, naming what to do instead. A pinned revision
always builds the packaged Dockerfile. A direct_url.json that names a directory
which is gone, or is not ASH's, does not read as LOCAL: the image installs the
revision the package build recorded (test_container_image_revision.py).
"""

from __future__ import annotations

import importlib.metadata
import json
import os
import re
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath
from types import ModuleType
from urllib.parse import quote, urlparse

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _find_dockerfile,
    _local_source_tree,
)

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
REFUSAL = re.escape(
    "a LOCAL revision builds the ASH source tree this ASH was installed"
)


def _localhost_url(path: PurePath) -> str:
    """``path`` as a file:// URL whose host is localhost, as pip may record it.

    The URL path starts with a slash before a Windows drive too
    (file://localhost/C:/...): a Windows path is not a URL path as it stands.
    PurePath.as_uri() would do this, but it is deprecated from Python 3.14.
    """
    return "file://localhost/" + quote(path.as_posix().lstrip("/"), safe="/:")


def _make_source_tree(root: Path, name: str = "automated-security-helper") -> Path:
    root.mkdir(parents=True)
    (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "{name}"\nversion = "9.9.9"\n', encoding="utf-8"
    )
    return root


def _make_checkout(root: Path, name: str = "automated-security-helper") -> Path:
    """A source tree with every marker get_ash_revision looks for beside a clone."""
    _make_source_tree(root, name)
    for marker in (".github", "docs", "tests"):
        (root / marker).mkdir()
    for marker in (".gitignore", ".dockerignore", "NOTICE"):
        (root / marker).write_text("", encoding="utf-8")
    return root


@pytest.fixture
def not_in_a_checkout(monkeypatch, tmp_path):
    """The running package is in site-packages, as for a pip or pre-commit install."""
    site_root = tmp_path / "venv" / "lib" / "python3.12" / "site-packages"
    site_root.mkdir(parents=True)
    monkeypatch.setattr(rac, "_checkout_root", lambda: site_root)
    return site_root


@pytest.fixture
def installed_from(monkeypatch, tmp_path, not_in_a_checkout):
    """Record a direct_url.json the way pip and uv write one.

    Lays out site-packages as an installer does, the package directory and its
    dist-info side by side, and points ``import_module`` at that package: the
    record run_ash_container reads is the one beside the running package.
    """
    package_dir = not_in_a_checkout / "automated_security_helper"
    package_dir.mkdir()
    module = ModuleType("automated_security_helper")
    module.__path__ = [package_dir.as_posix()]
    module.__version__ = "9.9.9"
    monkeypatch.setattr(rac, "import_module", lambda name: module)
    dist_info = not_in_a_checkout / "automated_security_helper-9.9.9.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: automated-security-helper\nVersion: 9.9.9\n",
        encoding="utf-8",
    )

    def write(
        url: str,
        *,
        editable: bool = False,
        raw: str | None = None,
        info: dict | None = None,
    ) -> Path:
        """``info`` replaces the ``dir_info`` member, for a VCS or archive record."""
        path = dist_info / "direct_url.json"
        if raw is None:
            record = {"url": url, **(info or {"dir_info": {"editable": editable}})}
            raw = json.dumps(record)
        path.write_text(raw, encoding="utf-8")
        return path

    return write


@pytest.fixture
def scanned_repo(monkeypatch, tmp_path):
    """The working directory a hook runs in: the user's repository, a Python project.

    It has a Dockerfile and a pyproject.toml of its own, the shape a
    working-directory search would accept.
    """
    repo = tmp_path / "user-repo"
    repo.mkdir()
    (repo / "Dockerfile").write_text("FROM busybox\n", encoding="utf-8")
    (repo / "pyproject.toml").write_text(
        '[project]\nname = "someone-else"\n', encoding="utf-8"
    )
    monkeypatch.chdir(repo)
    return repo


def _refused(scanned_repo: Path) -> None:
    """A LOCAL build with no ASH source tree is refused, and names no Dockerfile here."""
    with pytest.raises(FileNotFoundError, match=REFUSAL) as raised:
        _find_dockerfile("LOCAL")
    assert str(scanned_repo) not in str(raised.value)


class TestLocalBuildUsesTheInstalledSource:
    def test_a_hook_install_finds_the_dockerfile_in_its_own_clone(
        self, installed_from, scanned_repo, tmp_path
    ):
        """The ash-full-scan case: pre-commit's clone of the hook repository."""
        clone = _make_source_tree(tmp_path / "pre-commit-home" / "repoabc123")
        installed_from(clone.as_uri())

        assert _find_dockerfile("LOCAL") == clone / "Dockerfile"

    def test_a_dist_info_ahead_on_sys_path_is_not_followed(
        self, monkeypatch, installed_from, scanned_repo
    ):
        """`python -m automated_security_helper` from the scanned repository.

        The working directory then comes first on sys.path, and a dist-info
        directory the repository commits is the distribution
        importlib.metadata.distribution() returns. Read through that, its
        direct_url.json would choose the tree to build, so ASH reads the record
        that sits beside the running package.
        """
        installed_from("", raw="{}")  # this install records no source tree
        evil = _make_source_tree(scanned_repo / "evil")
        planted = scanned_repo / "automated_security_helper-3.7.0.dist-info"
        planted.mkdir()
        (planted / "METADATA").write_text(
            "Metadata-Version: 2.1\nName: automated-security-helper\nVersion: 3.7.0\n",
            encoding="utf-8",
        )
        (planted / "direct_url.json").write_text(
            json.dumps({"url": evil.as_uri(), "dir_info": {}}), encoding="utf-8"
        )
        monkeypatch.syspath_prepend(str(scanned_repo))
        # The precondition: the planted record is what importlib.metadata finds.
        found = importlib.metadata.distribution("automated-security-helper")
        assert evil.as_uri() in (found.read_text("direct_url.json") or "")

        assert rac._recorded_source_tree() is None
        _refused(scanned_repo)

    def test_a_percent_encoded_source_path_is_decoded(
        self, installed_from, scanned_repo, tmp_path
    ):
        """direct_url.json carries a URL, so a space in the path arrives as %20."""
        clone = _make_source_tree(tmp_path / "with space" / "ash")
        assert "%20" in clone.as_uri()
        installed_from(clone.as_uri())

        assert _find_dockerfile("LOCAL") == clone / "Dockerfile"

    def test_two_dist_infos_beside_the_package_record_nothing(
        self, installed_from, not_in_a_checkout, scanned_repo, tmp_path
    ):
        """Which of two records is this package's cannot be told, so neither counts."""
        clone = _make_source_tree(tmp_path / "ash-src")
        installed_from(clone.as_uri())
        (not_in_a_checkout / "automated_security_helper-3.7.0.dist-info").mkdir()

        assert rac._direct_url_json_path() is None
        _refused(scanned_repo)


class TestRunningFromACheckout:
    def test_the_checkout_around_the_running_package_wins(
        self, monkeypatch, scanned_repo, tmp_path
    ):
        """Editable install, run from another project that has its own Dockerfile."""
        checkout = _make_checkout(tmp_path / "ash-checkout")
        monkeypatch.setattr(rac, "_checkout_root", lambda: checkout)

        assert _find_dockerfile("LOCAL") == checkout / "Dockerfile"

    @pytest.mark.skipif(
        os.name == "nt", reason="a directory symlink needs privileges on Windows"
    )
    def test_a_symlinked_package_is_placed_where_it_really_is(
        self, monkeypatch, tmp_path
    ):
        """A repository on sys.path holding a symlink named automated_security_helper
        is not a checkout of ASH: the package is wherever the link points."""
        real = tmp_path / "real-site"
        module = real / "automated_security_helper" / "interactions"
        module.mkdir(parents=True)
        (module / "run_ash_container.py").write_text("", encoding="utf-8")
        repo = _make_checkout(tmp_path / "some-repo")
        (repo / "automated_security_helper").symlink_to(
            real / "automated_security_helper", target_is_directory=True
        )
        monkeypatch.setattr(
            rac,
            "__file__",
            str(
                repo
                / "automated_security_helper"
                / "interactions"
                / "run_ash_container.py"
            ),
        )

        assert rac._checkout_root() == real.resolve()
        assert rac._is_checkout(rac._checkout_root()) is False

        # Nor is a dist-info planted beside the link the package's own record.
        planted = repo / "automated_security_helper-3.7.0.dist-info"
        planted.mkdir()
        (planted / "direct_url.json").write_text(
            json.dumps({"url": repo.as_uri(), "dir_info": {}}), encoding="utf-8"
        )
        package = ModuleType("automated_security_helper")
        package.__path__ = [str(repo / "automated_security_helper")]
        monkeypatch.setattr(rac, "import_module", lambda name: package)

        assert rac._own_dist_info() is None
        assert rac._direct_url_json_path() is None

    def test_this_test_environment_resolves_to_this_checkout(self):
        """No doubles: the suite runs from an editable install of this repository."""
        assert Path(rac.__file__).resolve().is_relative_to(REPO_ROOT)
        assert _local_source_tree().resolve() == REPO_ROOT

    def test_the_checkout_root_is_the_directory_holding_the_package(self):
        """Two levels above interactions/, the checkout here, never the package."""
        root = rac._checkout_root().resolve()
        assert root == REPO_ROOT
        assert (
            root.joinpath(
                "automated_security_helper", "interactions", "run_ash_container.py"
            )
            == Path(rac.__file__).resolve()
        )

    def test_this_editable_install_run_from_another_project_builds_this_tree(
        self, scanned_repo
    ):
        """No doubles: the scanned project's Dockerfile is not the one built."""
        assert _find_dockerfile("LOCAL").resolve() == REPO_ROOT / "Dockerfile"

    def test_a_renamed_fork_checkout_builds_itself(
        self, monkeypatch, scanned_repo, tmp_path
    ):
        """A fork that renames its [project] is still the checkout ASH runs from.

        get_ash_revision takes it for LOCAL from the clone's markers, and the LOCAL
        build then refused it for its name, with a message that it had no source
        tree. The package is running from that tree, so it is the one built; the
        name check stays for a directory an installer recorded, which is a path
        outside the package.
        """
        checkout = _make_checkout(tmp_path / "acme-ash", name="acme-ash")
        monkeypatch.setattr(rac, "_checkout_root", lambda: checkout)

        assert rac.get_ash_revision() == "LOCAL"
        assert _find_dockerfile("LOCAL") == checkout / "Dockerfile"


class TestAnInstallDirectoryIsNotACheckout:
    """Files that look like ASH's tree beside an installed ASH are not its checkout.

    Whatever else was installed there put them there: a scanned repository's own
    virtualenv can carry every marker of a clone in its site-packages.
    """

    def test_a_directory_named_site_packages_is_not_a_checkout(
        self, monkeypatch, scanned_repo, tmp_path
    ):
        """No dist-info beside the package: the directory's name alone decides."""
        site = _make_checkout(tmp_path / "venv" / "lib" / "site-packages")
        monkeypatch.setattr(rac, "_checkout_root", lambda: site)

        assert not rac._is_checkout(site)
        _refused(scanned_repo)

    def test_a_tree_beside_the_dist_info_is_not_a_checkout(
        self, monkeypatch, scanned_repo, tmp_path
    ):
        """`pip install --target vendor` puts the dist-info beside the package."""
        vendor = _make_checkout(tmp_path / "vendor")
        (vendor / "automated_security_helper-9.9.9.dist-info").mkdir()
        monkeypatch.setattr(rac, "_checkout_root", lambda: vendor)

        assert not rac._is_checkout(vendor)
        _refused(scanned_repo)


class TestTheAshNameCheck:
    """_is_ash_source_tree on its own, on every system.

    The same check runs in the Dockerfile's clone step, and
    test_container_clone_step_runs.py holds the two to one answer, but only where a
    POSIX sh can run that step: the Windows legs pinned none of this.
    """

    @pytest.mark.parametrize(
        ("pyproject", "is_ash"),
        [
            pytest.param('[project]\nname = "automated-security-helper"\n', True),
            pytest.param('[project]\nname = "Automated_Security.Helper"\n', True),
            pytest.param("[project]\nname = 'automated-security-helper'\n", True),
            pytest.param(
                '[project]\nname = "automated-security-helper"\n'
                'keywords = ["security", 1]\n',
                True,
                id="toml-1.0-mixed-array",
            ),
            pytest.param('[project]\nname = "automated-security-helpers"\n', False),
            pytest.param(
                '[project]\nname = "other"\n[tool.x]\nname = "automated-security-helper"\n',
                False,
            ),
            pytest.param("[project]\nname = 3\n", False),
            pytest.param("[project\n", False),
        ],
    )
    def test_the_project_name_decides(self, tmp_path, pyproject, is_ash):
        """A TOML 1.0 array of mixed types is valid, and tomllib reads it; the
        `toml` 0.10 package ASH used on Python 3.10 refused it, so the CLI there
        said "not ASH" of a tree the image's clone step called ASH's."""
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tree / "pyproject.toml").write_text(pyproject, encoding="utf-8")

        assert rac._is_ash_source_tree(tree) is is_ash

    def test_a_toml_1_1_pyproject_is_not_ash_on_any_python(self, tmp_path):
        """A pyproject.toml only TOML 1.1 reads (here a multi-line inline table
        with a trailing comma) is not ASH's on any Python. tomllib on 3.11-3.14
        refuses it, and so does tomli on 3.10, which pyproject.toml holds below
        2.4: with tomli 2.4, which reads TOML 1.1, the tree was ASH's on 3.10
        alone. Lifting that cap, or a tomllib that learns TOML 1.1, fails here."""
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tree / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n'
            'urls = {\n  homepage = "https://example.invalid",\n}\n',
            encoding="utf-8",
        )

        assert rac._is_ash_source_tree(tree) is False

    def test_a_tree_without_a_dockerfile_is_not_ash(self, tmp_path):
        tree = _make_source_tree(tmp_path / "tree")
        (tree / "Dockerfile").unlink()

        assert rac._is_ash_source_tree(tree) is False


class TestARecordedTreeMustBeAsh:
    def test_a_tree_whose_pyproject_names_another_project_is_not_built(
        self, installed_from, scanned_repo, tmp_path
    ):
        """A deleted install directory whose path was reused is not ASH."""
        impostor = _make_source_tree(tmp_path / "shared" / "build", name="not-ash")
        installed_from(impostor.as_uri())

        assert rac._recorded_source_tree() is None
        _refused(scanned_repo)

    def test_a_reused_recorded_directory_is_named_in_the_refusal(
        self, installed_from, scanned_repo, tmp_path
    ):
        """ASH was installed from a directory that now holds another project.

        That is what this refusal can detect: ASH's own dist-info recorded the
        directory, and its pyproject.toml now names something else. It names the
        directory and the project in it, and says to reinstall ASH from its own
        source, not to `pip install -e` that unrelated project.
        """
        reused = _make_source_tree(tmp_path / "shared" / "build", name="someone-else")
        installed_from(reused.as_uri())

        with pytest.raises(FileNotFoundError, match=REFUSAL) as raised:
            _find_dockerfile("LOCAL")

        message = str(raised.value)
        assert repr(str(reused)) in message
        assert "'someone-else'" in message
        assert "Reinstall ASH from its own source directory" in message
        assert "pip install -e" not in message
        assert str(scanned_repo) not in message

    def test_a_renamed_fork_installed_from_its_directory_gets_the_fork_advice(
        self, monkeypatch, not_in_a_checkout, scanned_repo, tmp_path
    ):
        """The case the reused-directory text was first written for, as a real
        install lays it out: a fork that renames its [project] is installed under
        its own name (acme_ash-*.dist-info), so the running package has no
        automated_security_helper dist-info and the generic refusal is the one
        shown. It says how to build a fork."""
        fork = _make_source_tree(tmp_path / "acme-ash", name="acme-ash")
        package_dir = not_in_a_checkout / "automated_security_helper"
        package_dir.mkdir()
        module = ModuleType("automated_security_helper")
        module.__path__ = [package_dir.as_posix()]
        monkeypatch.setattr(rac, "import_module", lambda name: module)
        dist_info = not_in_a_checkout / "acme_ash-0.1.0.dist-info"
        dist_info.mkdir()
        (dist_info / "direct_url.json").write_text(
            json.dumps({"url": fork.as_uri(), "dir_info": {}}), encoding="utf-8"
        )

        with pytest.raises(FileNotFoundError, match=REFUSAL) as raised:
            _find_dockerfile("LOCAL")

        message = str(raised.value)
        assert "has none beside it or recorded for it" in message
        assert "pip install -e" in message
        # Once, for a released revision: it builds ASH's revision, not the fork,
        # so the fork advice no longer offers it again.
        assert message.count("--ash-revision-to-install") == 1
        assert str(scanned_repo) not in message

    @pytest.mark.skipif(
        os.name == "nt", reason="Windows file names cannot hold control characters"
    )
    def test_a_recorded_directory_name_cannot_write_raw_lines_or_escapes(
        self, installed_from, tmp_path
    ):
        """The directory is printed quoted, so a name holding a newline cannot start
        a line of its own (`::error::` is a GitHub Actions command) and an escape
        sequence reaches the terminal escaped."""
        name = "nl\n::error::PATH-LINE\x1b[31mesc"
        reused = _make_source_tree(tmp_path / name, name="someone-else")
        installed_from(reused.as_uri())

        with pytest.raises(FileNotFoundError, match=REFUSAL) as raised:
            _find_dockerfile("LOCAL")

        message = str(raised.value)
        assert "\x1b" not in message
        assert not [line for line in message.splitlines() if line.startswith("::")]

    @pytest.mark.skipif(
        os.name == "nt", reason="Windows file names cannot hold control characters"
    )
    def test_the_installation_directory_in_the_generic_refusal_is_quoted_too(
        self, monkeypatch, tmp_path
    ):
        """The refusal for an installation with no ASH source tree names the
        installation's own directory, which can hold any name too."""
        site_root = tmp_path / "nl\n::error::PATH-LINE\x1b[31mesc" / "site-packages"
        site_root.mkdir(parents=True)
        monkeypatch.setattr(rac, "_checkout_root", lambda: site_root)
        package_dir = site_root / "automated_security_helper"
        package_dir.mkdir()
        module = ModuleType("automated_security_helper")
        module.__path__ = [package_dir.as_posix()]
        monkeypatch.setattr(rac, "import_module", lambda name: module)

        with pytest.raises(FileNotFoundError, match=REFUSAL) as raised:
            _find_dockerfile("LOCAL")

        message = str(raised.value)
        assert "has none beside it or recorded for it" in message
        assert "\x1b" not in message
        assert not [line for line in message.splitlines() if line.startswith("::")]

    def test_a_pyproject_that_does_not_parse_is_not_ash(
        self, installed_from, scanned_repo, tmp_path
    ):
        broken = tmp_path / "broken"
        broken.mkdir()
        (broken / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (broken / "pyproject.toml").write_text("[project\n", encoding="utf-8")
        installed_from(broken.as_uri())

        _refused(scanned_repo)

    def test_a_source_tree_without_a_dockerfile_is_not_ash(
        self, installed_from, scanned_repo, tmp_path
    ):
        not_ash = tmp_path / "wheel-dir"
        not_ash.mkdir()
        (not_ash / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )
        installed_from(not_ash.as_uri())

        _refused(scanned_repo)

    def test_a_package_file_is_not_a_source_tree(
        self, installed_from, scanned_repo, tmp_path
    ):
        """`pip install ./ash.whl` records archive_info, and a wheel is no tree."""
        wheel_dir = _make_source_tree(tmp_path / "dist")
        installed_from(wheel_dir.as_uri(), info={"archive_info": {}})

        _refused(scanned_repo)


class TestWithNoAshTreeTheBuildIsRefused:
    """With no ASH source tree, each case is refused, and no Dockerfile beside it is built."""

    def test_a_source_tree_that_is_gone(self, installed_from, scanned_repo, tmp_path):
        installed_from((tmp_path / "deleted-build-dir").as_uri())

        _refused(scanned_repo)

    def test_a_vcs_install(self, installed_from, scanned_repo):
        """git+https installs resolve to a revision, never to a LOCAL context."""
        installed_from(
            "git+https://example.invalid/ash.git",
            info={"vcs_info": {"vcs": "git", "commit_id": "0" * 40}},
        )

        _refused(scanned_repo)

    def test_a_file_url_with_a_remote_host_is_not_resolved_on_posix(
        self, monkeypatch, installed_from, scanned_repo, tmp_path
    ):
        """`file://host/share/...` names another machine; only Windows can open it.

        url2pathname(urlparse(url).path) would drop the host and read
        /share/... on this machine instead, so off Windows such a record is
        ignored.
        """
        monkeypatch.setattr(rac, "_on_windows", lambda: False)
        _make_source_tree(tmp_path / "share" / "ash")
        installed_from("file://fileserver" + (tmp_path / "share" / "ash").as_posix())

        assert rac._recorded_source_tree() is None
        _refused(scanned_repo)

    def test_no_dist_info_beside_the_package(
        self, monkeypatch, not_in_a_checkout, scanned_repo
    ):
        package_dir = not_in_a_checkout / "automated_security_helper"
        package_dir.mkdir()
        module = ModuleType("automated_security_helper")
        module.__path__ = [package_dir.as_posix()]
        monkeypatch.setattr(rac, "import_module", lambda name: module)

        assert rac._direct_url_json_path() is None
        _refused(scanned_repo)

    def test_no_direct_url_json(self, installed_from, scanned_repo):
        _refused(scanned_repo)

    def test_unparseable_direct_url_json(self, installed_from, scanned_repo):
        installed_from("", raw="{ not json")

        _refused(scanned_repo)

    def test_a_dockerfile_alone_in_the_working_directory(
        self, installed_from, scanned_repo
    ):
        """A LOCAL build takes no Dockerfile from the working directory, with or
        without a pyproject.toml."""
        (scanned_repo / "pyproject.toml").unlink()

        _refused(scanned_repo)

    def test_a_dockerfile_and_pyproject_in_a_parent_directory(
        self, installed_from, scanned_repo, monkeypatch
    ):
        """Nor does it take one from a parent of the working directory."""
        below = scanned_repo / "src" / "pkg"
        below.mkdir(parents=True)
        monkeypatch.chdir(below)

        _refused(scanned_repo)


class TestUnixAndWindowsFileUrls:
    def test_a_file_url_with_a_remote_host_is_a_unc_path_on_windows(self, monkeypatch):
        """pip writes `file://fileserver/share/ash` for \\\\fileserver\\share\\ash.

        ``os.name`` itself stays as it is: set to "nt" off Windows, it made every
        Path refuse to be created on Python 3.10 and 3.11, this test's failure
        report included, and pytest stopped with an internal error.
        """
        monkeypatch.setattr(rac, "_on_windows", lambda: True)

        path = rac._file_url_path("file://fileserver/share/my%20ash")

        assert str(path) == r"\\fileserver\share\my ash"

    @pytest.mark.parametrize(
        "url",
        [
            "file://server",
            "file://server/",
            "file://.",
            "file://work",
            "file://%2E",
            # A path after the host, but an empty share segment.
            "file://work//sub",
            "file://.//work",
            "file://server/%5C",
            "file://./%5C",
            "file://server/%2Fx",
            # A backslash in the host itself: host "work\" ends the server name,
            # and in "wo\rk" it splits the host into a server and a share.
            "file://work\\/sub",
            "file://.\\/x",
            "file://wo\\rk/sub",
        ],
    )
    def test_a_host_with_no_share_path_names_no_directory(self, monkeypatch, url):
        """`\\\\server` with no share after it is no share. On Python 3.10 and 3.11,
        PureWindowsPath("\\\\server") is the rooted, drive-relative "\\server", a
        directory on the current drive, so such a record names no directory. An
        empty share segment is the same: `\\\\work\\\\sub` reads as "\\work\\sub",
        and `\\\\server\\\\` (from an escaped backslash) as "\\server". So is a
        host holding a backslash, which urlparse keeps in the host:
        `file://work\\/sub` builds `\\\\work\\\\sub` again."""
        monkeypatch.setattr(rac, "_on_windows", lambda: True)

        assert rac._file_url_path(url) is None

    def test_localhost_names_this_machine(self, installed_from, tmp_path):
        clone = _make_source_tree(tmp_path / "ash")
        installed_from(_localhost_url(clone))

        assert _local_source_tree() == clone

    @pytest.mark.parametrize(
        "path",
        [PureWindowsPath(r"C:\Users\me\ash"), PurePosixPath("/home/me/ash")],
        ids=["windows", "posix"],
    )
    def test_the_localhost_url_names_localhost_on_every_system(self, path):
        """`"file://localhost" + path.as_posix()` was file://localhostC:/... on
        Windows: a host named 'localhostC:', so the test above failed there."""
        url = _localhost_url(path)

        assert urlparse(url).netloc == "localhost"
        assert url.endswith("/me/ash")


@pytest.mark.skipif(os.name == "nt", reason="symbolic links need privileges there")
class TestARecordedPathThroughALink:
    """The /proc lookup in _file_url_path follows each link in a recorded path."""

    def test_an_ash_tree_reached_through_a_link_is_local(
        self, installed_from, tmp_path
    ):
        """A link that leads to an ASH source tree, not to /proc or /dev/fd, is
        followed. With every link refused, a directory install recorded through
        a symbolic link would have lost LOCAL with every test still green."""
        tree = _make_source_tree(tmp_path / "real" / "ash")
        link = tmp_path / "link"
        os.symlink(tree, link)
        installed_from(link.as_uri())

        assert rac._recorded_source_tree() == link
        assert _local_source_tree() == link

    def test_a_relative_link_to_an_ash_tree_is_local(self, installed_from, tmp_path):
        _make_source_tree(tmp_path / "real" / "ash")
        link = tmp_path / "links" / "ash"
        link.parent.mkdir()
        os.symlink("../real/ash", link)
        installed_from(link.as_uri())

        assert _local_source_tree() == link

    def test_a_loop_of_links_names_no_directory(
        self, installed_from, scanned_repo, tmp_path
    ):
        """Two links that point at each other never finish a lookup. The walk
        stops after Linux's own 40 links and treats the path as unusable."""
        first, second = tmp_path / "first", tmp_path / "second"
        os.symlink(second, first)
        os.symlink(first, second)
        installed_from(first.as_uri())

        assert rac._reaches_a_process_directory(first) is True
        assert rac._recorded_source_tree() is None
        _refused(scanned_repo)

    def test_a_link_that_cannot_be_read_names_no_directory(
        self, monkeypatch, installed_from, scanned_repo, tmp_path
    ):
        """A link the walk cannot read cannot be checked, so the path is not used,
        even though the kernel could still open what the link leads to."""
        tree = _make_source_tree(tmp_path / "real" / "ash")
        link = tmp_path / "link"
        os.symlink(tree, link)
        installed_from(link.as_uri())
        real_readlink = os.readlink

        def readlink(path, *args, **kwargs):
            if os.fspath(path) == os.fspath(link):
                raise PermissionError(13, "Permission denied", os.fspath(path))
            return real_readlink(path, *args, **kwargs)

        monkeypatch.setattr(rac.os, "readlink", readlink)

        assert rac._reaches_a_process_directory(link) is True
        assert rac._recorded_source_tree() is None
        _refused(scanned_repo)


class TestAPinnedRevisionBuildsThePackagedDockerfile:
    @pytest.fixture
    def assets(self, monkeypatch, tmp_path):
        assets = tmp_path / "assets"
        assets.mkdir()
        (assets / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
        return assets

    def test_a_project_with_a_dockerfile_and_pyproject_is_not_built(
        self, assets, scanned_repo
    ):
        """A pinned revision builds the packaged Dockerfile, not the project's."""
        assert _find_dockerfile("v1.2.3") == assets / "Dockerfile"

    def test_an_ash_checkout_as_the_working_directory_is_not_built_either(
        self, assets, monkeypatch, tmp_path
    ):
        """The packaged Dockerfile clones the pinned revision; a checkout is not it."""
        checkout = _make_checkout(tmp_path / "ash-checkout")
        monkeypatch.chdir(checkout)

        assert _find_dockerfile("v1.2.3") == assets / "Dockerfile"

    def test_the_install_record_plays_no_part(
        self, assets, installed_from, scanned_repo, tmp_path
    ):
        clone = _make_source_tree(tmp_path / "ash-src")
        installed_from(clone.as_uri())

        assert _find_dockerfile("v1.2.3") == assets / "Dockerfile"
