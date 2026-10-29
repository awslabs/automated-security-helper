# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The agent install scripts must add ASH to a user's MCP config, not replace it.

Why this file exists
--------------------
The Cline and Windsurf MCP configs are user-level and shared by every MCP server the
user runs, so the install scripts merge ASH into them: overwriting one with
`cat > "$TARGET"` would delete every other server and setting in it, with nothing
kept to restore from. The Goose script does not append to `config.yaml`, which would
glue ASH's `extensions:` key onto the last line of a file that does not end in a
newline and leave YAML that does not parse. The Gemini script installs into an
existing file, since that is the one file Gemini reads.

What is asserted
----------------
The committed scripts are run, not the transpiler functions that generate them:
the scripts are what a user executes, and `agentic-plugins check` already holds
them byte-equal to the generator. Each case gets its own HOME.

For the JSON configs (Cline, Windsurf, Gemini):

* other servers and other top-level settings survive, byte for byte as values;
* an existing `ash` entry is replaced by the current one;
* a missing file is created;
* a file that does not parse, or whose `mcpServers` is not an object, is refused
  and left untouched;
* a changed file is backed up first, and a second run changes nothing;
* a symlinked config stays a symlink and its target is updated.

For Goose's YAML, where the standard library has no parser, the script only appends
when the file has no `extensions:` block, and refuses otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGINS = REPO_ROOT / "ash-agent-plugins" / "agentic-coding" / "plugins"
BASE_MCP = (
    REPO_ROOT
    / "ash-agent-plugins"
    / "agentic-coding"
    / "transpiler"
    / "_base"
    / "mcp.json"
)

# The scripts are bash and support macOS and Linux only (Cline's refuses any other
# uname). Same convention as the buildspec tests under tests/unit/deploy.
pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="executes a bash install script that supports macOS and Linux only",
)


def _expected_entry() -> dict:
    return json.loads(BASE_MCP.read_text(encoding="utf-8"))["mcpServers"]["ash"]


def _cline_target(home: Path) -> Path:
    if platform.system() == "Darwin":
        base = home / "Library" / "Application Support" / "Code"
    else:
        base = home / ".config" / "Code"
    return (
        base
        / "User"
        / "globalStorage"
        / "saoudrizwan.claude-dev"
        / "settings"
        / "cline_mcp_settings.json"
    )


# platform -> where its install.sh writes, relative to HOME
JSON_TARGETS = {
    "cline": _cline_target,
    "windsurf": lambda home: home / ".codeium" / "windsurf" / "mcp_config.json",
    "gemini": lambda home: home / ".gemini" / "settings.json",
}

OTHER_SERVER = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-github"],
    "env": {"LOG_LEVEL": "debug"},
}


def _home(tmp_path: Path, platform_name: str) -> tuple[Path, Path]:
    home = tmp_path / "home"
    target = JSON_TARGETS[platform_name](home)
    # Cline's script requires the extension's settings directory to exist already.
    target.parent.mkdir(parents=True, exist_ok=True)
    return home, target


def _run(platform_name: str, home: Path, path: str | None = None):
    bash = shutil.which("bash")
    assert bash, "bash is required to run the install scripts"
    env = {"HOME": str(home), "PATH": path or os.environ.get("PATH", "")}
    return subprocess.run(
        [bash, str(PLUGINS / platform_name / "install.sh")],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _siblings(target: Path) -> set[str]:
    return {entry.name for entry in target.parent.iterdir()}


@pytest.mark.integration
@pytest.mark.parametrize("platform_name", sorted(JSON_TARGETS))
class TestJsonConfigMerge:
    def test_other_servers_and_settings_are_kept(self, tmp_path, platform_name):
        home, target = _home(tmp_path, platform_name)
        original = {"theme": "dark", "mcpServers": {"github": OTHER_SERVER}}
        original_text = json.dumps(original)
        target.write_text(original_text, encoding="utf-8")

        result = _run(platform_name, home)

        assert result.returncode == 0, result.stderr
        merged = json.loads(target.read_text(encoding="utf-8"))
        assert merged["theme"] == "dark", f"a top-level setting was lost: {merged}"
        assert merged["mcpServers"]["github"] == OTHER_SERVER, (
            "installing ASH removed or altered another MCP server in the user's "
            f"config: {merged}"
        )
        assert merged["mcpServers"]["ash"] == _expected_entry()

        backups = [
            path
            for path in target.parent.iterdir()
            if path.name != target.name and path.name.startswith(target.name)
        ]
        assert len(backups) == 1, (
            f"expected one backup of the replaced file beside it, found {backups}"
        )
        assert backups[0].read_text(encoding="utf-8") == original_text

    def test_a_stale_ash_entry_is_replaced(self, tmp_path, platform_name):
        home, target = _home(tmp_path, platform_name)
        stale = {
            "command": "uvx",
            "args": ["--from=git+https://example.invalid", "ash", "mcp"],
        }
        target.write_text(
            json.dumps({"mcpServers": {"ash": stale, "github": OTHER_SERVER}}),
            encoding="utf-8",
        )

        result = _run(platform_name, home)

        assert result.returncode == 0, result.stderr
        merged = json.loads(target.read_text(encoding="utf-8"))
        assert merged["mcpServers"]["ash"] == _expected_entry()
        assert merged["mcpServers"]["github"] == OTHER_SERVER

    def test_a_missing_config_is_created(self, tmp_path, platform_name):
        home, target = _home(tmp_path, platform_name)

        result = _run(platform_name, home)

        assert result.returncode == 0, result.stderr
        assert json.loads(target.read_text(encoding="utf-8")) == {
            "mcpServers": {"ash": _expected_entry()}
        }
        assert _siblings(target) == {target.name}, "a backup was made of nothing"

    @pytest.mark.parametrize(
        "content",
        [
            '{"mcpServers": {"github": ',  # truncated
            '{"mcpServers": {}, // a comment\n}',  # JSONC, not JSON
            '{"mcpServers": {"a": {}, "a": {}}}',  # duplicate key, last one would win
            "[]",  # not an object
            '{"mcpServers": []}',  # mcpServers not an object
        ],
        ids=[
            "truncated",
            "comment",
            "duplicate-key",
            "top-level-array",
            "servers-array",
        ],
    )
    def test_a_config_it_cannot_merge_is_refused_untouched(
        self, tmp_path, platform_name, content
    ):
        home, target = _home(tmp_path, platform_name)
        target.write_text(content, encoding="utf-8")

        result = _run(platform_name, home)

        assert result.returncode != 0, (
            f"a config the script cannot merge must be refused, not overwritten; "
            f"exit 0 with stdout {result.stdout!r}"
        )
        assert target.read_text(encoding="utf-8") == content, "the file was modified"
        assert _siblings(target) == {target.name}, "files were written beside it"
        assert str(target) in result.stderr, result.stderr
        assert '"--from=git+' in result.stderr, (
            "the refusal should print the entry to add by hand: " + result.stderr
        )

    def test_a_second_run_changes_nothing(self, tmp_path, platform_name):
        home, target = _home(tmp_path, platform_name)
        target.write_text(
            json.dumps({"mcpServers": {"github": OTHER_SERVER}}), encoding="utf-8"
        )

        first = _run(platform_name, home)
        assert first.returncode == 0, first.stderr
        after_first = target.read_bytes()
        files_after_first = _siblings(target)

        second = _run(platform_name, home)

        assert second.returncode == 0, second.stderr
        assert target.read_bytes() == after_first
        assert _siblings(target) == files_after_first, "the re-run made another backup"

    def test_a_symlinked_config_stays_a_symlink(self, tmp_path, platform_name):
        home, target = _home(tmp_path, platform_name)
        real = tmp_path / "dotfiles" / "mcp.json"
        real.parent.mkdir()
        real.write_text(
            json.dumps({"mcpServers": {"github": OTHER_SERVER}}), encoding="utf-8"
        )
        target.symlink_to(real)

        result = _run(platform_name, home)

        assert result.returncode == 0, result.stderr
        assert target.is_symlink(), "the user's symlink was replaced by a regular file"
        merged = json.loads(real.read_text(encoding="utf-8"))
        assert merged["mcpServers"]["github"] == OTHER_SERVER
        assert merged["mcpServers"]["ash"] == _expected_entry()

    def test_without_python3_nothing_is_written(self, tmp_path, platform_name):
        home, target = _home(tmp_path, platform_name)
        original = json.dumps({"mcpServers": {"github": OTHER_SERVER}})
        target.write_text(original, encoding="utf-8")

        # A PATH holding only the external commands the scripts call besides python3.
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        for tool in ("bash", "cat", "dirname", "mkdir", "uname"):
            found = shutil.which(tool)
            assert found, f"{tool} is required to build the restricted PATH"
            (bin_dir / tool).symlink_to(found)

        result = _run(platform_name, home, path=str(bin_dir))

        assert result.returncode != 0, result.stdout
        assert target.read_text(encoding="utf-8") == original
        assert '"--from=git+' in result.stderr, result.stderr

    @pytest.mark.parametrize("mode", [0o600, 0o644], ids=oct)
    def test_the_file_mode_is_kept_on_the_rewrite_and_the_backup(
        self, tmp_path, platform_name, mode
    ):
        """Another server's env block can hold a token, so 0600 has to survive.

        0644 as well: 0600 is what mkstemp creates the temporary file with, so on
        its own it would pass with the chmod deleted.
        """
        home, target = _home(tmp_path, platform_name)
        target.write_text(json.dumps({"mcpServers": {"github": OTHER_SERVER}}))
        target.chmod(mode)

        result = _run(platform_name, home)

        assert result.returncode == 0, result.stderr
        files = list(target.parent.iterdir())
        assert len(files) == 2, files
        for path in files:
            assert stat.S_IMODE(path.stat().st_mode) == mode, (
                f"{path.name} is {oct(stat.S_IMODE(path.stat().st_mode))}, not {oct(mode)}"
            )

    def test_a_utf8_bom_is_read_and_kept(self, tmp_path, platform_name):
        """Editors on Windows save JSON with a byte order mark; json.loads refuses one."""
        home, target = _home(tmp_path, platform_name)
        original = b"\xef\xbb\xbf" + json.dumps(
            {"mcpServers": {"github": OTHER_SERVER}}
        ).encode("utf-8")
        target.write_bytes(original)

        result = _run(platform_name, home)

        assert result.returncode == 0, result.stderr
        written = target.read_bytes()
        assert written.startswith(b"\xef\xbb\xbf"), "the byte order mark was dropped"
        merged = json.loads(written.decode("utf-8-sig"))
        assert merged["mcpServers"]["github"] == OTHER_SERVER
        assert merged["mcpServers"]["ash"] == _expected_entry()
        (backup,) = [p for p in target.parent.iterdir() if p != target]
        assert backup.read_bytes() == original

    def test_a_symlinked_configs_backup_is_written_beside_the_link(
        self, tmp_path, platform_name
    ):
        """Not beside the target, which is often inside a dotfiles git repository."""
        home, target = _home(tmp_path, platform_name)
        dotfiles = tmp_path / "dotfiles"
        dotfiles.mkdir()
        real = dotfiles / "mcp.json"
        original = json.dumps({"mcpServers": {"github": OTHER_SERVER}})
        real.write_text(original, encoding="utf-8")
        target.symlink_to(real)

        result = _run(platform_name, home)

        assert result.returncode == 0, result.stderr
        assert {p.name for p in dotfiles.iterdir()} == {"mcp.json"}, (
            "the backup or a temporary file was left in the link's target directory"
        )
        backups = [p for p in target.parent.iterdir() if p != target]
        assert len(backups) == 1, backups
        assert backups[0].name.startswith(target.name + ".ash-backup-")
        assert not backups[0].is_symlink()
        assert backups[0].read_text(encoding="utf-8") == original


MERGE_PROGRAM = (
    REPO_ROOT
    / "ash-agent-plugins"
    / "agentic-coding"
    / "transpiler"
    / "transpiler"
    / "mcp_config_merge.py"
)


def _merge_program():
    """The merge program the scripts embed verbatim, loaded from its source file.

    `agentic-plugins check` holds the embedded copies byte-equal to this file, so
    a fault injected here reaches the same code a user runs.
    """
    spec = importlib.util.spec_from_file_location(
        "ash_mcp_config_merge_under_test", MERGE_PROGRAM
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.unit
@pytest.mark.parametrize("existing", [True, False], ids=["existing", "new"])
def test_an_unwritable_config_directory_prints_the_entry_not_a_traceback(
    tmp_path, monkeypatch, capsys, existing
):
    """A directory the user cannot write to must not end the script in a traceback.

    The denial is injected at os.open, which the backup and tempfile.mkstemp both
    create files through, rather than made with chmod: root ignores a directory's
    mode, so a chmod case would pass or fail by who runs it.
    """
    merge = _merge_program()
    target = tmp_path / "settings.json"
    original = json.dumps({"mcpServers": {"github": OTHER_SERVER}})
    if existing:
        target.write_text(original, encoding="utf-8")
    real_open = os.open

    def deny_creation_in_the_config_directory(path, flags, *args, **kwargs):
        if flags & os.O_CREAT and Path(path).parent == tmp_path:
            raise PermissionError(13, "Permission denied", str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", deny_creation_in_the_config_directory)
    entry = _expected_entry()

    status = merge.main([str(target), "mcpServers", "ash", json.dumps(entry)])

    monkeypatch.undo()
    stderr = capsys.readouterr().err
    assert status == 1, stderr
    assert "Traceback" not in stderr
    assert str(target) in stderr and "It was not changed" in stderr, stderr
    assert '"--from=git+' in stderr, "the hand-edit entry was not printed: " + stderr
    assert {p.name for p in tmp_path.iterdir()} == (
        {"settings.json"} if existing else set()
    )
    if existing:
        assert target.read_text(encoding="utf-8") == original


def _embedded_program(platform_name: str, tmp_path: Path) -> Path:
    """The merge program as the committed install.sh carries it, written to a file."""
    script = (PLUGINS / platform_name / "install.sh").read_text(encoding="utf-8")
    start = script.index("<<'PY'\n") + len("<<'PY'\n")
    end = script.index("\nPY\n", start)
    program = tmp_path / f"{platform_name}-merge.py"
    program.write_text(script[start:end] + "\n", encoding="utf-8")
    return program


#: Runs the program as `python3 -I -` would, with os.fchmod removed, as on Windows
#: Pythons before 3.13, which have no fchmod.
_WITHOUT_FCHMOD = (
    "import os, runpy, sys; del os.fchmod; sys.argv = sys.argv[1:]; "
    "runpy.run_path(sys.argv[0], run_name='__main__')"
)


@pytest.mark.integration
@pytest.mark.parametrize("platform_name", sorted(JSON_TARGETS))
@pytest.mark.parametrize("mode", [0o600, 0o644], ids=oct)
def test_the_merge_works_without_os_fchmod(tmp_path, platform_name, mode):
    """The docstring says any Python 3.8 or later; Windows ones before 3.13 lack fchmod.

    Without the fallback the program raised AttributeError after creating the
    backup, so the script ended in a traceback and left a 0-byte backup behind.
    """
    program = _embedded_program(platform_name, tmp_path)
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    target = config_dir / "settings.json"
    original = json.dumps({"mcpServers": {"github": OTHER_SERVER}})
    target.write_text(original, encoding="utf-8")
    target.chmod(mode)

    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _WITHOUT_FCHMOD,
            str(program),
            str(target),
            "mcpServers",
            "ash",
            json.dumps(_expected_entry()),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Traceback" not in result.stderr, result.stderr
    merged = json.loads(target.read_text(encoding="utf-8"))
    assert merged["mcpServers"]["github"] == OTHER_SERVER
    assert merged["mcpServers"]["ash"] == _expected_entry()
    (backup,) = [p for p in config_dir.iterdir() if p != target]
    assert backup.read_text(encoding="utf-8") == original, "the backup is incomplete"
    assert stat.S_IMODE(backup.stat().st_mode) == mode
    assert stat.S_IMODE(target.stat().st_mode) == mode


@pytest.mark.unit
def test_a_backup_that_cannot_be_written_is_removed(tmp_path, monkeypatch, capsys):
    """A failed backup must not leave a partial copy that looks like a good one."""
    merge = _merge_program()
    target = tmp_path / "settings.json"
    original = json.dumps({"mcpServers": {"github": OTHER_SERVER}})
    target.write_text(original, encoding="utf-8")
    real_open, real_fdopen = os.open, os.fdopen
    backup_fds = set()

    def record_backup_fds(path, flags, *args, **kwargs):
        fd = real_open(path, flags, *args, **kwargs)
        if ".ash-backup-" in os.fspath(path):
            backup_fds.add(fd)
        return fd

    class _FailingWrite:
        def __init__(self, handle):
            self._handle = handle

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self._handle.close()
            return False

        def fileno(self):
            return self._handle.fileno()

        def write(self, data):
            self._handle.write(data[:3])
            self._handle.flush()
            raise OSError(28, "No space left on device")

    def fail_writes_to_the_backup(fd, *args, **kwargs):
        handle = real_fdopen(fd, *args, **kwargs)
        return _FailingWrite(handle) if fd in backup_fds else handle

    monkeypatch.setattr(os, "open", record_backup_fds)
    monkeypatch.setattr(os, "fdopen", fail_writes_to_the_backup)

    status = merge.main(
        [str(target), "mcpServers", "ash", json.dumps(_expected_entry())]
    )

    monkeypatch.undo()
    stderr = capsys.readouterr().err
    assert status == 1, stderr
    assert "Traceback" not in stderr and "It was not changed" in stderr, stderr
    assert {p.name for p in tmp_path.iterdir()} == {"settings.json"}, (
        "the partial backup was left behind"
    )
    assert target.read_text(encoding="utf-8") == original


@pytest.mark.integration
def test_cline_names_an_unsupported_os(
    tmp_path,
):
    """The message names no $BASE, which is unset there and would make `set -u` abort."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_uname = bin_dir / "uname"
    fake_uname.write_text("#!/bin/sh\necho FreeBSD\n")
    fake_uname.chmod(0o755)
    path = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"

    result = _run("cline", tmp_path / "home", path=path)

    assert result.returncode == 1, result.stderr
    assert "Unsupported OS: FreeBSD" in result.stderr, result.stderr
    assert "unbound variable" not in result.stderr, result.stderr


GOOSE_SCRIPT_TARGET = Path(".config") / "goose" / "config.yaml"


@pytest.mark.integration
class TestGooseConfig:
    def _target(self, tmp_path: Path) -> tuple[Path, Path]:
        home = tmp_path / "home"
        target = home / GOOSE_SCRIPT_TARGET
        target.parent.mkdir(parents=True)
        return home, target

    def test_appends_cleanly_to_a_file_without_a_final_newline(self, tmp_path):
        home, target = self._target(tmp_path)
        target.write_text("GOOSE_PROVIDER: openai", encoding="utf-8")

        result = _run("goose", home)

        assert result.returncode == 0, result.stderr
        loaded = yaml.safe_load(target.read_text(encoding="utf-8"))
        assert loaded["GOOSE_PROVIDER"] == "openai"
        assert loaded["extensions"]["ash"]["cmd"] == "uvx"
        backups = [p for p in target.parent.iterdir() if p.name != target.name]
        assert len(backups) == 1
        assert backups[0].read_text(encoding="utf-8") == "GOOSE_PROVIDER: openai"

    def test_creates_the_file_when_absent(self, tmp_path):
        home, target = self._target(tmp_path)

        result = _run("goose", home)

        assert result.returncode == 0, result.stderr
        assert "ash" in yaml.safe_load(target.read_text(encoding="utf-8"))["extensions"]

    def test_an_existing_extensions_block_is_refused_untouched(self, tmp_path):
        home, target = self._target(tmp_path)
        content = "extensions:\n  developer:\n    enabled: true\n"
        target.write_text(content, encoding="utf-8")

        result = _run("goose", home)

        assert result.returncode != 0, result.stdout
        assert target.read_text(encoding="utf-8") == content
        assert "automated-security-helper" in result.stderr, result.stderr

    def test_a_stale_ash_pin_is_reported_not_called_current(self, tmp_path):
        """It does not say "already lists ASH; nothing to change" for any version."""
        home, target = self._target(tmp_path)
        current = next(
            arg for arg in _expected_entry()["args"] if arg.startswith("--from=")
        )
        # The current argument with an older tag. Built rather than written out, so
        # the repository's walk for stale install references does not read this
        # fixture as one a user would follow.
        stale = current.rsplit("@", 1)[0] + "@v3.5.0"
        content = (
            "extensions:\n"
            "  ash:\n"
            "    cmd: uvx\n"
            "    args:\n"
            f'      - "{stale}"\n'
            '      - "ash"\n'
            '      - "mcp"\n'
        )
        target.write_text(content, encoding="utf-8")

        result = _run("goose", home)

        assert result.returncode != 0, result.stdout
        assert target.read_text(encoding="utf-8") == content
        assert "nothing to change" not in result.stdout + result.stderr
        assert stale.split("/")[-1] in result.stderr, result.stderr
        assert current in result.stderr, result.stderr

    def test_a_commented_current_pin_does_not_hide_an_active_stale_one(self, tmp_path):
        """A commented-out line is not configuration; only the active pin counts."""
        home, target = self._target(tmp_path)
        current = next(
            arg for arg in _expected_entry()["args"] if arg.startswith("--from=")
        )
        stale = current.rsplit("@", 1)[0] + "@v3.5.0"
        content = (
            "extensions:\n"
            "  ash:\n"
            "    cmd: uvx\n"
            "    args:\n"
            f'      # - "{current}"\n'
            f'      - "{stale}"\n'
            '      - "ash"\n'
            '      - "mcp"\n'
        )
        target.write_text(content, encoding="utf-8")

        result = _run("goose", home)

        assert result.returncode == 1, result.stdout + result.stderr
        assert "nothing to change" not in result.stdout + result.stderr
        assert stale.split("/")[-1] in result.stderr, result.stderr
        assert target.read_text(encoding="utf-8") == content

    def test_a_commented_stale_pin_is_not_an_entry(self, tmp_path):
        """With ASH only in a comment, there is no entry to update: add one by hand."""
        home, target = self._target(tmp_path)
        current = next(
            arg for arg in _expected_entry()["args"] if arg.startswith("--from=")
        )
        stale = current.rsplit("@", 1)[0] + "@v3.5.0"
        content = (
            f'extensions:\n  developer:\n    enabled: true\n  # was: - "{stale}"\n'
        )
        target.write_text(content, encoding="utf-8")

        result = _run("goose", home)

        assert result.returncode == 1, result.stdout + result.stderr
        assert "lists ASH as" not in result.stderr, result.stderr
        assert "by hand" in result.stderr, result.stderr
        assert target.read_text(encoding="utf-8") == content

    def test_a_second_run_changes_nothing(self, tmp_path):
        home, target = self._target(tmp_path)
        target.write_text("GOOSE_PROVIDER: openai\n", encoding="utf-8")

        first = _run("goose", home)
        assert first.returncode == 0, first.stderr
        after_first = target.read_bytes()
        files_after_first = {p.name for p in target.parent.iterdir()}

        second = _run("goose", home)

        assert second.returncode == 0, second.stderr
        assert target.read_bytes() == after_first
        assert {p.name for p in target.parent.iterdir()} == files_after_first
