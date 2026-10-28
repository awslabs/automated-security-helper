# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rest of "a config file that does not load is refused, never the defaults".

``test_resolve_config_load_failures.py`` covers the named and discovered YAML and
JSON files. This covers the other ways a config file reaches resolution -- the
operator's trusted config, a ``pyproject.toml`` probed during discovery, an empty
path, ``ASH_CONFIG`` with a schema error -- and the discovery warnings
``resolve_config`` now records, which are the resolution warnings a scan reports
with its results.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import (
    ASH_CONFIG_FILE_NAMES,
    ASH_PYPROJECT_FILE_NAME,
    ASH_RC_FILE_NAMES,
)
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


class TestOtherConfigInputs:
    def test_an_empty_config_path_is_refused_as_empty(self, tmp_path):
        """Path("") is the working directory; the refusal says the path is empty."""
        with pytest.raises(ASHConfigSourceError, match="path is empty"):
            resolve_config(config_path="", source_dir=tmp_path)

    @pytest.mark.parametrize(
        "names", ["a-missing-file", "a-link-to-nothing", "a-directory"]
    )
    def test_the_default_config_refuses_an_ash_config_that_names_no_file(
        self, tmp_path, monkeypatch, names
    ):
        """get_default_config is the config when none is named or found; with
        ASH_CONFIG set it is that file, and one that is not there is refused, never
        replaced by the built-in defaults."""
        from automated_security_helper.config.default_config import get_default_config

        target = tmp_path / "ash.yaml"
        if names == "a-link-to-nothing":
            target.symlink_to(tmp_path / "absent.yaml")
        elif names == "a-directory":
            target.mkdir()
        monkeypatch.setenv("ASH_CONFIG", str(target))

        with pytest.raises(ASHConfigSourceError, match="ash.yaml"):
            get_default_config()

    @pytest.mark.parametrize("empty", ["", "   "])
    def test_the_read_check_refuses_an_empty_path_as_empty(self, empty):
        """check_config_path is what MCP config_load_error and get_config(raw) reach."""
        from automated_security_helper.config.resolve_config import check_config_path

        with pytest.raises(ASHConfigSourceError) as excinfo:
            check_config_path(empty)

        assert "path is empty" in str(excinfo.value)
        assert str(Path.cwd()) not in str(excinfo.value)

    def test_a_named_trusted_config_that_does_not_exist_is_refused(self, tmp_path):
        """The operator's file the sandbox grants come from must exist when named.

        Refused like any named config, so the grants of an in-tree config are
        always decided against the file the operator named.
        """
        (tmp_path / ".ash").mkdir()
        (tmp_path / ".ash" / ".ash.yaml").write_text(
            "project_name: in-tree\n", encoding="utf-8"
        )

        with pytest.raises(ASHConfigValidationError, match="operator.yaml"):
            resolve_config(
                source_dir=tmp_path, trusted_config_path=tmp_path / "operator.yaml"
            )

    def test_a_trusted_config_that_does_not_parse_is_refused(self, tmp_path):
        source = tmp_path / "src"
        (source / ".ash").mkdir(parents=True)
        (source / ".ash" / ".ash.yaml").write_text(
            "project_name: in-tree\n", encoding="utf-8"
        )
        operator = tmp_path / "operator.yaml"
        operator.write_text("sandbox: [unclosed\n", encoding="utf-8")

        with pytest.raises(ASHConfigSourceError, match="could not parse"):
            resolve_config(source_dir=source, trusted_config_path=operator)

    def test_an_ash_config_variable_naming_a_schema_invalid_file_is_a_config_error(
        self, tmp_path, monkeypatch
    ):
        """Not pydantic's ValidationError, which ``ash scan`` reports as exit 1."""
        env_file = tmp_path / "env.yaml"
        env_file.write_text("global_settings: 7\n", encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(env_file))
        source = tmp_path / "src"
        source.mkdir()

        with pytest.raises(ASHConfigValidationError, match="env.yaml"):
            resolve_config(source_dir=source)

    def test_control_an_empty_ash_config_variable_is_unset(self, tmp_path, monkeypatch):
        """As click treats it for --config, so an empty CI input keeps working."""
        monkeypatch.setenv("ASH_CONFIG", "")

        config = resolve_config(source_dir=tmp_path)

        assert config.global_settings.suppressions == []


needs_permissions = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions that root ignores",
)


@needs_permissions
class TestAConfigFileThatCannotBeRead:
    """A config file that exists but cannot be read refuses as a config error.

    Every way a file reaches resolution is covered, because each takes a
    different path to read_config_document: without its OSError arm, a named or
    ASH_CONFIG file became the catch-all's generic refusal, and the operator's
    trusted config and an MCP session profile raised a bare PermissionError (exit
    1 from a workspace scan instead of 3).
    """

    @pytest.fixture
    def unreadable(self, tmp_path):
        path = tmp_path / "operator" / "locked.yaml"
        path.parent.mkdir()
        path.write_text("project_name: locked\n", encoding="utf-8")
        path.chmod(0)
        yield path
        path.chmod(0o644)

    def _assert_unreadable(self, error: BaseException) -> None:
        assert isinstance(error, ASHConfigSourceError), repr(error)
        assert "could not read" in str(error)

    def test_a_named_file(self, tmp_path, unreadable):
        with pytest.raises(Exception) as excinfo:
            resolve_config(config_path=unreadable, source_dir=tmp_path)
        self._assert_unreadable(excinfo.value)

    def test_a_discovered_file(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        path = repo / ".ash.yaml"
        path.write_text("project_name: locked\n", encoding="utf-8")
        path.chmod(0)
        try:
            with pytest.raises(Exception) as excinfo:
                resolve_config(source_dir=repo)
        finally:
            path.chmod(0o644)
        self._assert_unreadable(excinfo.value)

    def test_the_operators_trusted_config(self, tmp_path, unreadable):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".ash.yaml").write_text("project_name: in-tree\n", encoding="utf-8")

        with pytest.raises(Exception) as excinfo:
            resolve_config(
                source_dir=repo, scanned_root=repo, trusted_config_path=unreadable
            )
        self._assert_unreadable(excinfo.value)

    def test_the_file_ash_config_names(self, tmp_path, monkeypatch, unreadable):
        repo = tmp_path / "repo"
        repo.mkdir()
        monkeypatch.setenv("ASH_CONFIG", str(unreadable))

        with pytest.raises(Exception) as excinfo:
            resolve_config(source_dir=repo)
        self._assert_unreadable(excinfo.value)

    def test_an_mcp_session_profile_exits_3(self, unreadable):
        from automated_security_helper.cli.mcp import workspace as mcp_workspace

        with pytest.raises(Exception) as excinfo:
            mcp_workspace._gate_client_overrides(["project_name=x"], str(unreadable))
        self._assert_unreadable(excinfo.value)
        assert mcp_workspace._exit_code_for(excinfo.value) == 3


class TestThePreReadCheckClassifiesEveryStatError:
    """check_config_path decides from os.stat, not Path.is_file.

    Before Python 3.14, Path.is_file() raises for an error other than "not
    found" -- a directory above the file that cannot be searched gives
    PermissionError -- so the check let a bare PermissionError out instead of
    refusing the file as a config that cannot be read. 3.14's is_file returns
    False there, so the older behavior is reproduced with a patched is_file.
    """

    def test_an_is_file_that_raises_does_not_escape(self, tmp_path, monkeypatch):
        from automated_security_helper.config.resolve_config import check_config_path

        path = tmp_path / "locked" / "cfg.yaml"
        path.parent.mkdir()
        path.write_text("project_name: x\n", encoding="utf-8")

        def raising_is_file(self):
            raise PermissionError(13, "Permission denied", str(self))

        monkeypatch.setattr(Path, "is_file", raising_is_file)

        assert check_config_path(path) == path

    @needs_permissions
    def test_a_directory_above_that_cannot_be_searched(self, tmp_path):
        from automated_security_helper.config.resolve_config import check_config_path

        locked = tmp_path / "locked"
        locked.mkdir()
        (locked / "cfg.yaml").write_text("project_name: x\n", encoding="utf-8")
        locked.chmod(0)
        try:
            with pytest.raises(ASHConfigSourceError, match="Permission denied"):
                check_config_path(locked / "cfg.yaml")
        finally:
            locked.chmod(0o755)

    def test_a_path_with_an_embedded_nul_is_refused_as_not_loadable(self):
        """os.stat raises ValueError for a NUL in the path, which the check let out
        as a bare error where every other bad path is refused as one that cannot
        be read. An MCP client can send such a string (U+0000 is legal JSON); the
        CLI cannot, since argv and the environment are C strings.

        The message holds the path as describe_config_path writes it, the NUL
        unescaped: the sink the message is shown through escapes it.
        """
        from automated_security_helper.cli.mcp import workspace as mcp_workspace
        from automated_security_helper.config.config_sources import (
            describe_config_path,
        )
        from automated_security_helper.config.resolve_config import check_config_path

        name = "cfg\x00.yaml"

        with pytest.raises(ASHConfigSourceError) as excinfo:
            check_config_path(name)

        message = str(excinfo.value)
        assert describe_config_path(Path(name)) in message
        assert "cannot be read" in message
        assert mcp_workspace._exit_code_for(excinfo.value) == 3


class TestARustPanicWhileResolvingIsRefused:
    """pydantic-core reports a Rust panic as pyo3's PanicException, a BaseException.

    resolve_config's catch-all is ``except Exception``, so a panic while a config
    validated went past it, and past MCP get_config's handler, into whatever
    called; in an MCP server that is the process every session shares. It is
    refused as a config that could not be resolved. KeyboardInterrupt and
    SystemExit still pass through.
    """

    @staticmethod
    def _raise(error: BaseException):
        def raiser(*args, **kwargs):
            raise error

        return raiser

    def test_a_panic_while_validating_is_a_config_error(self, tmp_path, monkeypatch):
        from automated_security_helper.config.ash_config import AshConfig

        panic = type("PanicException", (BaseException,), {"__module__": "pyo3_runtime"})
        (tmp_path / ".ash.yaml").write_text("project_name: x\n", encoding="utf-8")
        monkeypatch.setattr(
            AshConfig, "model_validate", self._raise(panic("PyObject pointer is null"))
        )

        with pytest.raises(ASHConfigValidationError, match="PanicException"):
            resolve_config(source_dir=tmp_path)

    @pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit])
    def test_control_an_interrupt_still_propagates(self, tmp_path, monkeypatch, error):
        from automated_security_helper.config.ash_config import AshConfig

        (tmp_path / ".ash.yaml").write_text("project_name: x\n", encoding="utf-8")
        monkeypatch.setattr(AshConfig, "model_validate", self._raise(error()))

        with pytest.raises(error):
            resolve_config(source_dir=tmp_path)


needs_proc_environ = pytest.mark.skipif(
    not Path("/proc/self/environ").exists(), reason="needs Linux /proc"
)


@needs_proc_environ
class TestAConfigLinkedToAPseudoFile:
    """Known limit: a pseudo-file passes the regular-file check and is read.

    ``/proc/self/environ`` is a regular file to ``stat``, so a config name linked
    to it is opened and read, then refused when it does not parse. These tests
    pin what that refusal says: it names the config file, and it quotes none of
    the content, so no environment value reaches a log or an MCP client. A
    change that refuses such a link before the read must keep it a config error.
    The MCP server already refuses it before the read.
    """

    MARKER = "marker-value-pseudo-file"

    def test_it_is_refused_naming_the_file_and_no_content(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_TEST_PSEUDO_FILE_MARKER", self.MARKER)
        link = tmp_path / ".ash.yaml"
        link.symlink_to("/proc/self/environ")

        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(config_path=link, source_dir=tmp_path)

        message = str(excinfo.value)
        assert message.startswith(f"could not parse {link.as_posix()}: "), message
        assert "unacceptable character #x0000" in message
        assert f'in "{link}", position' in message
        assert self.MARKER not in message

    def test_get_config_raw_refuses_it_before_the_read(self, tmp_path, monkeypatch):
        """The MCP server judges a config input by where it resolves, so the link
        is refused as outside the permitted config roots, not read."""
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        monkeypatch.setenv("ASH_TEST_PSEUDO_FILE_MARKER", self.MARKER)
        link = tmp_path / ".ash.yaml"
        link.symlink_to("/proc/self/environ")

        result = mcp_get_config(config_path=str(link), raw=True)

        assert result["success"] is False, "raw read returned content"
        assert result["error_type"] == "config_input_not_permitted", result
        assert result["error_category"] == "invalid_path"
        assert self.MARKER not in str(result)


#: Every name discovery looks for, where it looks: each dedicated name at the root
#: and in .ash/, each ashrc name at the root, and pyproject.toml.
EVERY_DISCOVERY_LOCATION = [
    *ASH_CONFIG_FILE_NAMES,
    *(f".ash/{name}" for name in ASH_CONFIG_FILE_NAMES),
    *ASH_RC_FILE_NAMES,
    ASH_PYPROJECT_FILE_NAME,
]


class TestDiscoveryLocations:
    @pytest.mark.parametrize("relative", EVERY_DISCOVERY_LOCATION)
    def test_a_directory_at_a_config_name_is_refused(self, tmp_path, relative):
        (tmp_path / relative).mkdir(parents=True)

        with pytest.raises(ASHConfigSourceError, match="not a regular file"):
            resolve_config(source_dir=tmp_path)

    def test_an_unreadable_pyproject_that_would_be_selected_is_refused(self, tmp_path):
        """It may hold the repository's [tool.ash] table, and that cannot be told."""
        (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")

        with pytest.raises(ASHConfigSourceError, match="pyproject.toml"):
            resolve_config(source_dir=tmp_path)

    def test_control_an_unreadable_pyproject_behind_a_dedicated_file_is_ignored(
        self, tmp_path
    ):
        """Shadowed, it would be ignored even if readable, so it is only logged."""
        (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")
        (tmp_path / ".ash.yaml").write_text("project_name: used\n", encoding="utf-8")

        assert resolve_config(source_dir=tmp_path).project_name == "used"


def _two_sources(root: Path) -> Path:
    (root / ".ash").mkdir()
    used = root / ".ash" / ".ash.yaml"
    used.write_text("project_name: used\n", encoding="utf-8")
    (root / ".ashrc.toml").write_text('project_name = "ignored"\n', encoding="utf-8")
    return used


class TestIgnoredSourcesAreResolutionWarnings:
    def test_discovery_records_the_ignored_source(self, tmp_path):
        _two_sources(tmp_path)

        config = resolve_config(source_dir=tmp_path)

        assert config.project_name == "used"
        assert len(config._resolution_warnings) == 1
        assert ".ashrc.toml" in config._resolution_warnings[0]

    def test_the_file_discovery_selects_records_it_when_passed_by_path(self, tmp_path):
        """``ash scan`` and workspace mode discover first and pass the path."""
        used = _two_sources(tmp_path)

        config = resolve_config(config_path=used, source_dir=tmp_path)

        assert [".ashrc.toml" in w for w in config._resolution_warnings] == [True]

    def test_a_file_in_a_linked_ash_directory_records_it_when_passed_by_path(
        self, tmp_path
    ):
        """``.ash`` linked to a shared directory is still where discovery looked."""
        repo = tmp_path / "repo"
        repo.mkdir()
        shared = tmp_path / "shared"
        shared.mkdir()
        (shared / ".ash.yaml").write_text("project_name: used\n", encoding="utf-8")
        (repo / ".ash").symlink_to(shared)
        (repo / ".ashrc.toml").write_text(
            'project_name = "ignored"\n', encoding="utf-8"
        )

        config = resolve_config(
            config_path=repo / ".ash" / ".ash.yaml", source_dir=repo
        )

        assert config.project_name == "used"
        assert [".ashrc.toml" in w for w in config._resolution_warnings] == [True]

    def test_the_warning_survives_config_overrides(self, tmp_path):
        """An override rebuilds the config object; the warning is added after it."""
        _two_sources(tmp_path)

        config = resolve_config(
            source_dir=tmp_path, config_overrides=["project_name=overridden"]
        )

        assert config.project_name == "overridden"
        assert len(config._resolution_warnings) == 1

    def test_control_a_file_chosen_over_discovery_records_nothing(self, tmp_path):
        """Naming the ignored source itself, or a file elsewhere, is a choice."""
        _two_sources(tmp_path)
        elsewhere = tmp_path / "configs" / "ci.yaml"
        elsewhere.parent.mkdir()
        elsewhere.write_text("project_name: ci\n", encoding="utf-8")

        for path in (tmp_path / ".ashrc.toml", elsewhere):
            config = resolve_config(config_path=path, source_dir=tmp_path)
            assert config._resolution_warnings == [], path

    def test_control_a_single_source_records_nothing(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text("project_name: only\n", encoding="utf-8")

        assert resolve_config(source_dir=tmp_path)._resolution_warnings == []
