# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ASH reads a config file: never blocking, never unbounded, never the defaults.

A config file is opened without blocking and read only when the opened file is
a regular file, up to ``ASH_CONFIG_MAX_FILE_BYTES``. So a FIFO or a device at a
config name, whether it was there when the name was checked or swapped in
afterwards, is refused at once rather than blocking the scan or reading until
memory runs out. Describing a config path for a message reads nothing from a
file that is not a regular file. A failure ASH did not foresee while resolving a
config is refused too, not answered with the defaults.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    describe_config_path,
    read_config_file,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
# The private name is kept: two other test modules still import it from here.
from tests.utils.fifo_calls import returns_promptly as _returns_promptly
from tests.utils.open_audit import record_opens

pytestmark = pytest.mark.unit

needs_fifo = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX file type"
)
needs_dev_zero = pytest.mark.skipif(
    not os.path.exists("/dev/zero"), reason="needs a /dev/zero character device"
)
needs_dev_null = pytest.mark.skipif(
    not os.path.exists("/dev/null"), reason="needs a /dev/null character device"
)


@pytest.fixture(autouse=True)
def _no_ash_config_variable(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


class TestSpecialFilesAreNotRead:
    @needs_fifo
    def test_a_fifo_named_pyproject_toml_given_as_the_config_is_refused_at_once(
        self, tmp_path
    ):
        fifo = tmp_path / "pyproject.toml"
        os.mkfifo(fifo)

        error = _returns_promptly(
            lambda: resolve_config(config_path=fifo, source_dir=tmp_path), fifo
        )

        assert isinstance(error, ASHConfigSourceError), error
        assert "not a regular file" in str(error)

    @needs_fifo
    def test_describing_a_fifo_named_pyproject_toml_reads_nothing(self, tmp_path):
        fifo = tmp_path / "pyproject.toml"
        os.mkfifo(fifo)

        assert _returns_promptly(lambda: describe_config_path(fifo), fifo) is None

    @needs_fifo
    @pytest.mark.parametrize("name", ["cfg.yaml", "cfg.json", "cfg.toml"])
    def test_a_fifo_reached_after_the_regular_file_check_is_not_read(
        self, tmp_path, name
    ):
        """read_config_file is what runs after a caller checked the name."""
        fifo = tmp_path / name
        os.mkfifo(fifo)

        error = _returns_promptly(lambda: read_config_file(fifo), fifo)

        assert isinstance(error, OSError), error
        assert "not a regular file" in str(error)

    @needs_dev_zero
    @pytest.mark.parametrize("name", ["cfg.json", "cfg.yaml", "pyproject.toml"])
    def test_a_link_to_a_device_is_not_read(self, tmp_path, monkeypatch, name):
        """Refused by the file type. The bound is lowered so that, should the type
        check go, the read still stops at 1 MiB and this fails on the size
        instead of reading /dev/zero until memory runs out."""
        monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 1 << 20)
        link = tmp_path / name
        link.symlink_to("/dev/zero")

        with pytest.raises(OSError, match="not a regular file"):
            read_config_file(link)

    def test_a_file_larger_than_the_bound_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 64)
        big = tmp_path / ".ash.yaml"
        big.write_text("project_name: x\n" + "# padding\n" * 20, encoding="utf-8")

        with pytest.raises(ASHConfigSourceError, match="larger than 64 bytes"):
            resolve_config(source_dir=tmp_path)

    def test_the_bound_is_1_mib(self, tmp_path):
        """Six times ASH's own config; parsing a file that size stays cheap."""
        from automated_security_helper.core.constants import ASH_CONFIG_MAX_FILE_BYTES

        assert ASH_CONFIG_MAX_FILE_BYTES == 1024 * 1024
        big = tmp_path / ".ash.yaml"
        big.write_text(
            "project_name: x\n" + "#" * ASH_CONFIG_MAX_FILE_BYTES, encoding="utf-8"
        )

        with pytest.raises(ASHConfigSourceError, match="larger than 1048576 bytes"):
            resolve_config(source_dir=tmp_path)

    def test_control_ashs_own_config_is_within_the_bound(self):
        from automated_security_helper.core.constants import ASH_CONFIG_MAX_FILE_BYTES

        own = Path(__file__).resolve().parents[3] / ".ash" / ".ash.yaml"

        assert own.stat().st_size < ASH_CONFIG_MAX_FILE_BYTES / 4

    def test_control_a_file_at_the_bound_is_read(self, tmp_path, monkeypatch):
        content = "project_name: x\n"
        monkeypatch.setattr(
            config_sources, "ASH_CONFIG_MAX_FILE_BYTES", len(content.encode())
        )
        # Bytes, not write_text: text mode would write the newline as CRLF on
        # Windows and the file would be one byte over the bound.
        (tmp_path / ".ash.yaml").write_bytes(content.encode())

        assert resolve_config(source_dir=tmp_path).project_name == "x"

    def test_a_yaml_syntax_error_still_names_the_file_and_line(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: x\nscanners: [bandit\n", encoding="utf-8")

        with pytest.raises(ASHConfigSourceError) as excinfo:
            resolve_config(config_path=path, source_dir=tmp_path)

        assert f'in "{path}", line 2' in str(excinfo.value)


def _record_opens(monkeypatch) -> list:
    """Every open made while the test runs, as (path, flags).

    From the interpreter's audit hook, so ``open()``, ``io.open`` and
    ``Path.read_text`` are seen as well as ``os.open``.
    """
    return record_opens(monkeypatch)


def _special_pyproject(kind: str, directory: Path) -> Path:
    path = directory / "pyproject.toml"
    if kind == "fifo":
        os.mkfifo(path)
    else:
        path.symlink_to("/dev/null")
    return path


SPECIAL_PYPROJECTS = [
    pytest.param("fifo", marks=needs_fifo, id="fifo"),
    pytest.param("dev-null", marks=needs_dev_null, id="link-to-dev-null"),
]


class TestDiscoveryOpensOnlyRegularFiles:
    """Discovery opens a pyproject.toml only when it is a regular file.

    Opening a device can act on it even when nothing is read: a watchdog arms,
    a tape rewinds, and a tty opened by a process with no controlling terminal
    can become its controlling terminal. A pyproject.toml that is not a regular
    file is therefore refused, or ignored behind a higher-precedence source,
    by its file type and without being opened.
    """

    @pytest.mark.parametrize("kind", SPECIAL_PYPROJECTS)
    def test_one_that_would_be_selected_is_refused_unopened(
        self, tmp_path, monkeypatch, kind
    ):
        pyproject = _special_pyproject(kind, tmp_path)
        opened = _record_opens(monkeypatch)

        # In a thread with a deadline: an open of the FIFO without O_NONBLOCK
        # would block the test rather than fail it.
        error = _returns_promptly(
            lambda: config_sources.discover_config_source(tmp_path), pyproject
        )

        assert isinstance(error, ASHConfigSourceError), error
        assert "not a regular file" in str(error)
        assert [p for p, _ in opened if p.name == pyproject.name] == []

    @pytest.mark.parametrize("kind", SPECIAL_PYPROJECTS)
    def test_one_behind_a_dedicated_file_is_ignored_unopened(
        self, tmp_path, monkeypatch, kind
    ):
        (tmp_path / ".ash.yaml").write_text("project_name: x\n", encoding="utf-8")
        pyproject = _special_pyproject(kind, tmp_path)
        opened = _record_opens(monkeypatch)
        found = {}

        def discover():
            found["discovery"] = config_sources.discover_config_source(tmp_path)

        assert _returns_promptly(discover, pyproject) is None
        discovery = found["discovery"]
        assert discovery.selected.path == tmp_path / ".ash.yaml"
        assert discovery.ignored == []
        assert [p for p, _ in opened if p.name == pyproject.name] == []

    def test_control_the_recorder_sees_a_builtin_open(self, tmp_path, monkeypatch):
        path = tmp_path / "seen.txt"
        path.write_text("x", encoding="utf-8")
        opened = _record_opens(monkeypatch)

        path.read_text(encoding="utf-8")

        assert path in [p for p, _ in opened]

    def test_control_a_regular_pyproject_is_read(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "from-pyproject"\n', encoding="utf-8"
        )

        assert resolve_config(source_dir=tmp_path).project_name == "from-pyproject"

    def test_a_config_file_is_opened_without_becoming_a_controlling_terminal(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: x\n", encoding="utf-8")
        opened = _record_opens(monkeypatch)

        read_config_file(path)

        noctty = getattr(os, "O_NOCTTY", 0)
        flags = [f for p, f in opened if p == path]
        assert flags and all(f & noctty == noctty for f in flags), flags


needs_permissions = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions that root ignores",
)


class TestDiscoveryThatCannotLookIsRefused:
    """A config name whose existence cannot be told is refused, not taken as absent.

    os.path.lexists answers False for any error, so a ``.ash/`` directory the
    scan cannot search hid the ``.ash/.ash.yaml`` inside it and the scan ran with
    the defaults without a word.
    """

    @needs_permissions
    def test_an_unsearchable_ash_directory_is_refused(self, tmp_path):
        dot_ash = tmp_path / ".ash"
        dot_ash.mkdir()
        (dot_ash / ".ash.yaml").write_text(
            "project_name: from-dot-ash\nfail_on_findings: false\n", encoding="utf-8"
        )
        dot_ash.chmod(0)
        try:
            with pytest.raises(ASHConfigSourceError) as excinfo:
                resolve_config(source_dir=tmp_path)
        finally:
            dot_ash.chmod(0o755)

        assert ".ash" in str(excinfo.value)
        assert "Permission denied" in str(excinfo.value)

    @needs_permissions
    def test_control_an_unsearchable_unrelated_directory_does_not_matter(
        self, tmp_path
    ):
        other = tmp_path / "vendor"
        other.mkdir()
        other.chmod(0)
        try:
            config = resolve_config(source_dir=tmp_path)
        finally:
            other.chmod(0o755)

        assert config.project_name == "ash-scan"

    def test_control_an_ash_that_is_a_file_holds_no_config(self, tmp_path):
        (tmp_path / ".ash").write_text("not a directory\n", encoding="utf-8")

        assert resolve_config(source_dir=tmp_path).project_name == "ash-scan"


def _swap_in_a_new_file(path: Path, text: str) -> None:
    """Replace `path` by a different file (a new inode), as a racing writer would."""
    replacement = path.with_name(path.name + ".new")
    replacement.write_text(text, encoding="utf-8")
    os.replace(replacement, path)


class TestTheFileReadIsTheFileThatWasChecked:
    """A file replaced between the check and the read is refused, not read.

    The check (a permit decision, a regular-file check) is made on what the name
    led to then; the read opens the name again. After the open, the descriptor's
    device and inode are compared with the ones the check saw.
    """

    def test_read_config_bytes_refuses_a_file_that_is_not_the_one_expected(
        self, tmp_path
    ):
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: checked\n", encoding="utf-8")
        checked = config_sources.file_identity(path)
        _swap_in_a_new_file(path, "project_name: swapped\n")

        with pytest.raises(OSError, match="changed after it was checked"):
            config_sources.read_config_bytes(path, expect=checked)

    def test_control_the_same_file_is_read(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        # Bytes: the assertion below compares the bytes read, and text mode
        # would write CRLF on Windows.
        path.write_bytes(b"project_name: checked\n")

        assert config_sources.read_config_bytes(
            path, expect=config_sources.file_identity(path)
        ) == (b"project_name: checked\n")

    def test_an_extends_base_replaced_after_its_check_is_refused(
        self, tmp_path, monkeypatch
    ):
        base = tmp_path / "base.yaml"
        base.write_text("project_name: checked\n", encoding="utf-8")
        child = tmp_path / ".ash.yaml"
        child.write_text("extends: base.yaml\n", encoding="utf-8")
        real_resolve_base_path = config_sources._resolve_base_path

        def resolve_then_swap(*args, **kwargs):
            result = real_resolve_base_path(*args, **kwargs)
            _swap_in_a_new_file(base, "project_name: swapped\n")
            return result

        monkeypatch.setattr(config_sources, "_resolve_base_path", resolve_then_swap)

        with pytest.raises(ASHConfigSourceError, match="changed after it was checked"):
            resolve_config(config_path=child, source_dir=tmp_path)

    def test_mcp_get_config_raw_refuses_a_file_replaced_after_its_check(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.cli.mcp import sandbox
        from automated_security_helper.cli.mcp_tools import mcp_get_config

        path = tmp_path / ".ash.yaml"
        path.write_text("project_name: checked\n", encoding="utf-8")
        real_validate = sandbox.validate_config_input

        def validate_then_swap(*args, **kwargs):
            refusal = real_validate(*args, **kwargs)
            _swap_in_a_new_file(path, "project_name: swapped\n")
            return refusal

        monkeypatch.setattr(sandbox, "validate_config_input", validate_then_swap)

        result = mcp_get_config(config_path=str(path), raw=True)

        assert result.get("success") is False, result
        assert "swapped" not in str(result)


class TestAPathThatLedNowhereIsHeldToThat:
    """No identity is not an identity to hold to.

    A caller that judges a path takes ``identity_to_hold``. For a path that leads
    nowhere then, ``file_identity`` gives None, which as ``expect`` means "no
    identity was taken": the read would be held to nothing, and a link made at
    the name after it was judged would be read. ``identity_to_hold`` gives the
    identity no file has, so such a file is refused like a swapped one.
    """

    def test_a_path_that_leads_nowhere_has_an_identity_to_hold(self, tmp_path):
        absent = tmp_path / "absent.yaml"

        assert config_sources.file_identity(absent) is None, "premise: it is absent"
        assert config_sources.identity_to_hold(absent) is not None
        assert config_sources.identity_to_hold(absent) == config_sources.ABSENT_FILE

    def test_control_a_file_is_held_to_its_own_identity(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: checked\n", encoding="utf-8")

        assert config_sources.identity_to_hold(path) == config_sources.file_identity(
            path
        )
        assert config_sources.identity_to_hold(path) != config_sources.ABSENT_FILE

    def test_no_file_has_the_absent_identity(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: checked\n", encoding="utf-8")
        dev, ino = config_sources.file_identity(path)

        assert (dev, ino) != config_sources.ABSENT_FILE
        assert min(config_sources.ABSENT_FILE) < 0 <= min(dev, ino)

    def test_a_file_that_appears_where_the_path_led_nowhere_is_not_read(self, tmp_path):
        path = tmp_path / "cfg.yaml"
        held = config_sources.identity_to_hold(path)
        path.write_text("project_name: appeared\n", encoding="utf-8")

        with pytest.raises(OSError, match="changed after it was checked"):
            config_sources.read_config_bytes(path, expect=held)

    def test_control_a_read_held_to_nothing_reads_the_file_that_appeared(
        self, tmp_path
    ):
        """What the None identity did: the premise that the guard is needed."""
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: appeared\n", encoding="utf-8")

        assert config_sources.read_config_bytes(path, expect=None) == (
            b"project_name: appeared\n"
        )

    def test_an_extends_base_that_appears_after_its_check_is_refused(
        self, tmp_path, monkeypatch
    ):
        base = tmp_path / "base.yaml"
        child = tmp_path / ".ash.yaml"
        child.write_text("extends: base.yaml\n", encoding="utf-8")
        real_resolve_base_path = config_sources._resolve_base_path
        led_nowhere = []

        def resolve_then_create(*args, **kwargs):
            result = real_resolve_base_path(*args, **kwargs)
            led_nowhere.append(not base.exists())
            base.write_text("project_name: appeared\n", encoding="utf-8")
            return result

        monkeypatch.setattr(config_sources, "_resolve_base_path", resolve_then_create)

        with pytest.raises(ASHConfigSourceError, match="changed after it was checked"):
            resolve_config(config_path=child, source_dir=tmp_path)

        assert led_nowhere == [True], "premise: the base led nowhere at its check"

    def test_a_pyproject_that_appears_after_its_identity_was_taken_is_refused(
        self, tmp_path, monkeypatch
    ):
        pyproject = tmp_path / "pyproject.toml"
        real_identity = config_sources.file_identity
        taken = []

        def identity_then_create(candidate):
            identity = real_identity(candidate)
            taken.append(identity)
            pyproject.write_text("[tool.ash]\nproject_name = 'x'\n", encoding="utf-8")
            return identity

        monkeypatch.setattr(config_sources, "file_identity", identity_then_create)

        with pytest.raises(OSError, match="changed after it was checked"):
            config_sources.pyproject_has_ash_table(pyproject)

        assert taken == [None], "premise: it led nowhere when its identity was taken"


class TestAPyprojectThatIsNotUtf8IsScannedAsTheFileItWasRead:
    """pyproject_has_ash_table reads a file twice when its first read finds it
    is not UTF-8: the second read, for the ``tool.ash`` pattern, is held to the
    file the first read opened."""

    def _declaring_latin1_pyproject(self, tmp_path: Path) -> Path:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_bytes("[tool.ash]\nproject_name = 'café'\n".encode("latin-1"))
        return pyproject

    def test_a_file_swapped_in_after_the_first_read_is_refused(
        self, tmp_path, monkeypatch
    ):
        pyproject = self._declaring_latin1_pyproject(tmp_path)
        real_read_toml_text = config_sources._read_toml_text

        def read_then_swap(path, *args, **kwargs):
            try:
                return real_read_toml_text(path, *args, **kwargs)
            finally:
                _swap_in_a_new_file(path, "[tool.other]\nx = 1\n")

        monkeypatch.setattr(config_sources, "_read_toml_text", read_then_swap)

        with pytest.raises(OSError, match="changed after it was checked"):
            config_sources.pyproject_has_ash_table(pyproject)

    def test_control_the_same_file_is_scanned(self, tmp_path):
        pyproject = self._declaring_latin1_pyproject(tmp_path)

        with pytest.raises(ASHConfigSourceError, match="could not be parsed"):
            config_sources.pyproject_has_ash_table(pyproject)


class TestAChangedFileIsToldByItsTypeAndNotByItsErrno:
    """A read refused for a changed file raises ``ConfigFileChangedError``.

    ESTALE is also what a file system reports for a stale handle, so a caller
    that took the errno for "the file changed since it was checked" called a
    network file system's failure a swap. The type says it, a wrapper that raised
    from the refusal keeps it in its cause, and a rewording that drops the cause
    on purpose (a base the environment chose) carries a mark.
    """

    def test_a_file_that_is_not_the_checked_one_raises_the_dedicated_error(
        self, tmp_path
    ):
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: checked\n", encoding="utf-8")
        checked = config_sources.file_identity(path)
        _swap_in_a_new_file(path, "project_name: swapped\n")

        with pytest.raises(config_sources.ConfigFileChangedError) as refused:
            config_sources.read_config_bytes(path, expect=checked)

        assert refused.value.errno == errno.ESTALE, "kept for callers that test it"
        assert isinstance(refused.value, OSError)
        assert config_sources.config_file_changed(refused.value)

    def test_a_stale_handle_the_file_system_reports_is_not_a_changed_file(self):
        stale = OSError(errno.ESTALE, "Stale file handle")

        assert not config_sources.config_file_changed(stale)

    def test_a_wrapper_raised_from_the_refusal_is_a_changed_file(self):
        refused = config_sources.ConfigFileChangedError(errno.ESTALE, "changed")
        try:
            try:
                raise refused
            except OSError as cause:
                raise ASHConfigSourceError("Base config could not be read") from cause
        except ASHConfigSourceError as wrapper:
            assert config_sources.config_file_changed(wrapper)

    def test_an_error_with_no_cause_and_no_mark_is_not_a_changed_file(self):
        assert not config_sources.config_file_changed(ASHConfigSourceError("no cause"))
        assert not config_sources.config_file_changed(None)

    def test_a_base_the_environment_chose_keeps_the_fact_through_its_rewording(
        self, tmp_path, monkeypatch
    ):
        """The rewording of a hidden base's read failure carries no cause, so the
        cause walk finds nothing; the fact rides on the error's mark. The message
        names neither the file nor its path."""
        hidden_dir = tmp_path / "hidden-dir-canary-5528"
        hidden_dir.mkdir()
        base = hidden_dir / "base.yaml"
        base.write_text("project_name: checked\n", encoding="utf-8")
        monkeypatch.setenv("ASH_HIDDEN_BASE_UNDER_TEST", base.as_posix())
        root = tmp_path / ".ash.yaml"
        root.write_text("extends:\n- ${ASH_HIDDEN_BASE_UNDER_TEST}\n", encoding="utf-8")
        real_resolve_base_path = config_sources._resolve_base_path

        def resolve_then_swap(*args, **kwargs):
            result = real_resolve_base_path(*args, **kwargs)
            _swap_in_a_new_file(base, "project_name: swapped\n")
            return result

        monkeypatch.setattr(config_sources, "_resolve_base_path", resolve_then_swap)

        with pytest.raises(ASHConfigSourceError) as refused:
            config_sources.resolve_config_document(root, confine_to=tmp_path)

        assert refused.value.__cause__ is None, "premise: the cause was dropped"
        assert "hidden-dir-canary-5528" not in str(refused.value), str(refused.value)
        assert config_sources.config_file_changed(refused.value)

    def test_control_a_hidden_base_that_fails_for_another_reason_is_not_changed(
        self, tmp_path, monkeypatch
    ):
        hidden_dir = tmp_path / "hidden-dir-canary-5528"
        hidden_dir.mkdir()
        base = hidden_dir / "base.yaml"
        base.write_text("project_name: checked\n", encoding="utf-8")
        monkeypatch.setenv("ASH_HIDDEN_BASE_UNDER_TEST", base.as_posix())
        root = tmp_path / ".ash.yaml"
        root.write_text("extends:\n- ${ASH_HIDDEN_BASE_UNDER_TEST}\n", encoding="utf-8")
        real_read_config_text = config_sources.read_config_text

        def read_but_fail_the_base(path, expect=None):
            if Path(path).name == "base.yaml":
                raise OSError(errno.EIO, "Input/output error")
            return real_read_config_text(path, expect=expect)

        monkeypatch.setattr(config_sources, "read_config_text", read_but_fail_the_base)

        with pytest.raises(ASHConfigSourceError) as refused:
            config_sources.resolve_config_document(root, confine_to=tmp_path)

        assert refused.value.__cause__ is None, "premise: the reworded arm ran"
        assert not config_sources.config_file_changed(refused.value)


class TestTheReadItselfBlocks:
    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Windows has no O_NONBLOCK, and os.get_blocking rejects a file there",
    )
    def test_o_nonblock_is_cleared_once_the_file_is_known_to_be_regular(
        self, tmp_path, monkeypatch
    ):
        """O_NONBLOCK is there for the open; a regular file is then read normally."""
        path = tmp_path / "cfg.yaml"
        path.write_text("project_name: x\n", encoding="utf-8")
        blocking = []
        real_read = os.read

        def recording_read(fd, n):
            blocking.append(os.get_blocking(fd))
            return real_read(fd, n)

        monkeypatch.setattr(os, "read", recording_read)

        assert config_sources.read_config_bytes(path) == b"project_name: x\n"
        assert blocking and all(blocking), blocking


class TestAPyprojectLinkThatCannotBeFollowedIsNamedForWhatItIs:
    """Each was reported as "a symbolic link to nothing"."""

    def test_a_link_that_leads_back_to_itself(self, tmp_path):
        link = tmp_path / "pyproject.toml"
        link.symlink_to(link)

        with pytest.raises(ASHConfigSourceError) as excinfo:
            config_sources.discover_config_source(tmp_path)

        assert "leads back to itself" in str(excinfo.value)
        assert "link to nothing" not in str(excinfo.value)

    @needs_permissions
    def test_a_link_into_a_directory_that_cannot_be_searched(self, tmp_path):
        locked = tmp_path / "locked"
        locked.mkdir()
        (locked / "pyproject.toml").write_text("[tool.ash]\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").symlink_to(locked / "pyproject.toml")
        locked.chmod(0)
        try:
            with pytest.raises(ASHConfigSourceError) as excinfo:
                config_sources.discover_config_source(tmp_path)
        finally:
            locked.chmod(0o755)

        assert "Permission denied" in str(excinfo.value)
        assert "link to nothing" not in str(excinfo.value)

    def test_control_a_link_to_nothing_is_still_named_so(self, tmp_path):
        (tmp_path / "pyproject.toml").symlink_to(tmp_path / "absent.toml")

        with pytest.raises(ASHConfigSourceError, match="link to nothing"):
            config_sources.discover_config_source(tmp_path)


class TestTheFileTypeChecksDoNotUsePathIsFile:
    """Before Python 3.14, Path.is_file() raises for an error other than "not found".

    Every check of a config path's type uses os.stat instead, so a check never
    lets a bare OSError out. 3.14's is_file returns False for any error, so the
    older behavior is reproduced by patching is_file to raise.
    """

    @pytest.fixture(autouse=True)
    def _is_file_raises(self, monkeypatch):
        def raising_is_file(self):
            raise PermissionError(13, "Permission denied", str(self))

        monkeypatch.setattr(Path, "is_file", raising_is_file)

    def test_naming_a_pyproject_for_a_message(self, tmp_path):
        path = tmp_path / "pyproject.toml"
        path.write_text('[tool.ash]\nproject_name = "x"\n', encoding="utf-8")

        assert describe_config_path(path) == f"{path.as_posix()} [tool.ash] (line 1)"

    def test_reading_an_extends_base(self, tmp_path):
        (tmp_path / "base.yaml").write_text("project_name: base\n", encoding="utf-8")
        child = tmp_path / ".ash.yaml"
        child.write_text("extends: base.yaml\n", encoding="utf-8")

        assert resolve_config(config_path=child, source_dir=tmp_path).project_name == (
            "base"
        )

    def test_the_wizards_guard(self, tmp_path):
        from typer.testing import CliRunner

        from automated_security_helper.cli.config import config_app

        path = tmp_path / ".ash.yaml"
        path.write_text("project_name: x\n", encoding="utf-8")

        result = CliRunner().invoke(
            config_app, ["wizard", "--config", str(path)], input="\n" * 200
        )

        assert not isinstance(result.exception, PermissionError), result.output

    def test_the_mcp_chain_check(self, tmp_path, monkeypatch):
        from automated_security_helper.cli.mcp import sandbox

        monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
        monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
        child = tmp_path / ".ash.yaml"
        child.write_text("project_name: x\n", encoding="utf-8")

        assert sandbox.validate_config_chain(child, source_dir=tmp_path) is None


class TestEncodings:
    def test_a_json_config_with_a_utf8_byte_order_mark_is_read(self, tmp_path):
        """As YAML and TOML already are; Windows PowerShell 5 writes the mark."""
        (tmp_path / ".ash.json").write_bytes(
            b'\xef\xbb\xbf{"project_name": "with-bom"}'
        )

        assert resolve_config(source_dir=tmp_path).project_name == "with-bom"

    def test_control_a_yaml_config_with_a_byte_order_mark_is_read(self, tmp_path):
        (tmp_path / ".ash.yaml").write_bytes(b"\xef\xbb\xbfproject_name: with-bom\n")

        assert resolve_config(source_dir=tmp_path).project_name == "with-bom"


class TestMessages:
    def test_a_symbolic_link_to_itself_is_reported_as_a_loop(self, tmp_path):
        link = tmp_path / ".ash.yaml"
        link.symlink_to(link)

        with pytest.raises(ASHConfigSourceError, match="leads back to itself"):
            resolve_config(source_dir=tmp_path)

    def test_an_ash_config_variable_of_only_whitespace_is_named_as_such(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_CONFIG", "  ")

        with pytest.raises(ASHConfigSourceError, match="only whitespace"):
            resolve_config(source_dir=tmp_path)


class TestUnforeseenFailuresAreRefused:
    """resolve_config's catch-all refuses rather than returning the defaults.

    A flow sequence nested 50,000 deep is a config file a YAML parser gives up on
    with RecursionError, which is not a YAML error, so it reaches the catch-all.
    """

    DEEP = "project_name: x\nscanners: " + "[" * 50_000 + "\n"

    def test_a_discovered_file_is_refused(self, tmp_path):
        (tmp_path / ".ash.yaml").write_text(self.DEEP, encoding="utf-8")

        with pytest.raises(ASHConfigValidationError, match="RecursionError"):
            resolve_config(source_dir=tmp_path)

    def test_a_named_file_is_refused(self, tmp_path):
        path = tmp_path / "deep.yaml"
        path.write_text(self.DEEP, encoding="utf-8")

        with pytest.raises(ASHConfigValidationError, match="RecursionError"):
            resolve_config(config_path=path, source_dir=tmp_path)
