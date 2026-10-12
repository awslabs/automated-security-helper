"""Every file ASH writes below an output directory goes through ``fs_guard``.

``fs_guard.open_for_write`` and ``atomic_write.write_text_atomically`` never follow a
symlink below a registered output directory and refuse a file another name refers
to. A plain ``open(path, "w")``, ``Path.write_text`` or ``logging.FileHandler`` does
neither, and the default output directory is inside the scanned tree.

This test reads every module under ``automated_security_helper`` and lists each call
that can create or change a file. A call found here either writes outside every
output directory, and is listed in ``WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY`` with where
it writes, or it is a defect: write it with ``fs_guard.open_for_write`` (or
``write_text_atomically``). An entry that no longer matches a call fails too, so the
list stays the list of real exceptions.

The controls run the same detector on small sources: a write below an output
directory is found, the guarded spellings and a read are not.
"""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

#: open() modes that create or change a file.
_WRITE_MODE_CHARS = set("wax+")
#: Methods that write the file they are called on.
_WRITE_METHODS = {"write_text", "write_bytes", "touch", "symlink_to", "hardlink_to"}
#: Module functions that create, replace or link a file.
_WRITE_FUNCTIONS = {
    ("os", "replace"),
    ("os", "rename"),
    ("os", "symlink"),
    ("os", "link"),
    ("os", "mkfifo"),
    ("shutil", "copy"),
    ("shutil", "copy2"),
    ("shutil", "copyfile"),
    ("shutil", "copytree"),
    ("shutil", "move"),
}
_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC"}

Site = Tuple[str, str, str]  # (module, enclosing function, kind)


def _literal_mode(call: ast.Call, position: int):
    """The call's mode argument, or None when it is absent; "?" when not a literal."""
    mode = None
    if len(call.args) > position:
        mode = call.args[position]
    for keyword in call.keywords:
        if keyword.arg == "mode":
            mode = keyword.value
    if mode is None:
        return None
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return mode.value
    return "?"


def _writes_by_mode(mode) -> bool:
    return mode == "?" or (mode is not None and bool(_WRITE_MODE_CHARS & set(mode)))


def _names_a_write_flag(node: ast.AST) -> bool:
    return any(
        (isinstance(n, ast.Attribute) and n.attr in _WRITE_FLAGS)
        or (isinstance(n, ast.Name) and n.id in _WRITE_FLAGS)
        for n in ast.walk(node)
    )


def _kind(call: ast.Call):
    """What kind of write ``call`` is, or None."""
    func = call.func
    if isinstance(func, ast.Name):
        if func.id == "open" and _writes_by_mode(_literal_mode(call, 1)):
            return "open"
        if func.id == "FileHandler":
            return "FileHandler"
        return None
    if not isinstance(func, ast.Attribute):
        return None
    owner = func.value.id if isinstance(func.value, ast.Name) else None
    if func.attr in _WRITE_METHODS:
        return func.attr
    if func.attr == "open":
        if owner in ("io", "codecs") and _writes_by_mode(_literal_mode(call, 1)):
            return "open"
        if owner == "os":
            flags = call.args[1] if len(call.args) > 1 else None
            return (
                "os.open" if flags is not None and _names_a_write_flag(flags) else None
            )
        # Path.open(mode)
        if _writes_by_mode(_literal_mode(call, 0)):
            return "Path.open"
        return None
    if func.attr == "fdopen" and owner == "os":
        return "os.fdopen" if _writes_by_mode(_literal_mode(call, 1)) else None
    if func.attr == "FileHandler":
        return "FileHandler"
    if (owner, func.attr) in _WRITE_FUNCTIONS:
        return f"{owner}.{func.attr}"
    return None


def write_sites(source: str, module: str) -> List[Site]:
    """Every write call in ``source``, with the function that makes it."""
    tree = ast.parse(source)
    sites: List[Site] = []

    def visit(node: ast.AST, scope: List[str]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, [*scope, child.name])
                continue
            if isinstance(child, ast.Call):
                kind = _kind(child)
                if kind is not None:
                    sites.append((module, ".".join(scope) or "<module>", kind))
            visit(child, scope)

    visit(tree, [])
    return sites


def _package_sites() -> Counter:
    found: Counter = Counter()
    for path in sorted(PACKAGE.rglob("*.py")):
        module = path.relative_to(PACKAGE.parent).as_posix()
        found.update(write_sites(path.read_text(encoding="utf-8"), module))
    return found


_ASH = "automated_security_helper"
_INSTALLER = f"{_ASH}/assets/install-pinned-tool.py"
_INSTALLS = "the standalone tool installer: the install and staging directories"
_CONFIG = "the config file the operator names or ASH resolved"
_DOWNLOADS = "tool installs, download staging and the asset cache under ASH's home"
_ATOMIC = (
    "write_text_atomically itself: below an output directory it writes through "
    "open_parent_beneath, and these calls are that path and the one outside"
)
_FS_GUARD = "fs_guard itself: open() only for a path below no registered root"
_MCP_SESSIONS = (
    "the MCP server's workspace root: session markers and the lock files that "
    "record live servers and scans"
)
_CDK_NAG_CHILD = (
    "the worker child's response file, created exclusively in the fresh "
    "directory its parent made and wrote the request into with fs_guard"
)
_DETECT_SECRETS_CHILD = (
    "the worker child's output file, created exclusively after its parent "
    "wrote the request beside it with fs_guard and removed the name"
)

#: (module, function, kind) -> (number of such calls, where they write). Each writes
#: outside every output directory, or is the guarded implementation itself.
WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY: Dict[Site, Tuple[int, str]] = {
    (_INSTALLER, "download", "Path.open"): (1, _INSTALLS),
    (_INSTALLER, "extract_member", "Path.open"): (4, _INSTALLS),
    (_INSTALLER, "install", "shutil.move"): (1, _INSTALLS),
    (_INSTALLER, "publish_third_party", "shutil.move"): (1, _INSTALLS),
    (_INSTALLER, "stage_third_party", "shutil.copyfile"): (1, _INSTALLS),
    (_INSTALLER, "stage_third_party", "write_text"): (1, _INSTALLS),
    (_INSTALLER, "verify_third_party", "write_text"): (1, _INSTALLS),
    (f"{_ASH}/cli/config.py", "_apply_fixes", "write_text"): (1, _CONFIG),
    (f"{_ASH}/cli/config.py", "_apply_unused_fixes", "write_text"): (1, _CONFIG),
    (f"{_ASH}/cli/config.py", "init", "write_text"): (2, _CONFIG),
    (f"{_ASH}/cli/config.py", "update", "write_text"): (1, _CONFIG),
    (f"{_ASH}/cli/config.py", "wizard", "write_text"): (2, _CONFIG),
    (f"{_ASH}/config/ash_config.py", "AshConfig.save", "open"): (1, _CONFIG),
    (f"{_ASH}/config/ash_config.py", "_rewrite_config_with_entry", "open"): (
        1,
        _CONFIG,
    ),
    (f"{_ASH}/config/ash_config.py", "add_suppression_to_config", "write_text"): (
        3,
        _CONFIG,
    ),
    (f"{_ASH}/cli/entrypoint.py", "_reattach", "os.fdopen"): (
        1,
        "the process's own standard stream",
    ),
    (f"{_ASH}/cli/main.py", "get_genai_guide", "write_text"): (
        1,
        "the file the operator names for the guide",
    ),
    (f"{_ASH}/cli/mcp/source_delivery.py", "_write_next_sequence", "write_text"): (
        1,
        "the MCP upload workspace, where a client's source is assembled",
    ),
    (f"{_ASH}/cli/mcp/source_delivery.py", "set_source_zip_chunk", "Path.open"): (
        1,
        "the MCP upload workspace, where a client's source is assembled",
    ),
    (f"{_ASH}/cli/mcp/session_paths.py", "mark_session_workspace", "touch"): (
        1,
        _MCP_SESSIONS,
    ),
    (f"{_ASH}/cli/mcp/sessions.py", "ScanPresence.__enter__", "open"): (
        1,
        _MCP_SESSIONS,
    ),
    (f"{_ASH}/cli/mcp/sessions.py", "StdioServerPresence.__enter__", "open"): (
        2,
        _MCP_SESSIONS,
    ),
    (f"{_ASH}/cli/mcp/sessions.py", "StdioServerPresence.__exit__", "open"): (
        1,
        _MCP_SESSIONS,
    ),
    (
        f"{_ASH}/cli/mcp/sessions.py",
        "StdioServerPresence._another_server_is_live",
        "open",
    ): (1, _MCP_SESSIONS),
    (f"{_ASH}/cli/mcp/sessions.py", "_a_scan_holds", "open"): (1, _MCP_SESSIONS),
    (f"{_ASH}/cli/mcp/sessions.py", "_scan_presence_guard", "open"): (
        1,
        _MCP_SESSIONS,
    ),
    (f"{_ASH}/cli/mcp_tools.py", "mcp_validate_config", "write_text"): (
        1,
        "a TemporaryDirectory of its own",
    ),
    (
        f"{_ASH}/plugin_modules/ash_builtin/converters/jupyter_converter.py",
        "JupyterConverter._stage_notebook",
        "write_bytes",
    ): (1, "the converter's own TemporaryDirectory for nbconvert"),
    (f"{_ASH}/schemas/generate_schemas.py", "generate_schemas", "write_text"): (
        1,
        "the JSON schemas in the source checkout, a development step",
    ),
    (f"{_ASH}/utils/version_management.py", "update_version_in_pyproject", "open"): (
        1,
        "pyproject.toml in the source checkout, a release step",
    ),
    (f"{_ASH}/utils/atomic_write.py", "_replace", "os.replace"): (1, _ATOMIC),
    (f"{_ASH}/utils/atomic_write.py", "_write_beneath", "os.fdopen"): (1, _ATOMIC),
    (f"{_ASH}/utils/atomic_write.py", "_write_beneath", "os.replace"): (1, _ATOMIC),
    (f"{_ASH}/utils/atomic_write.py", "write_text_atomically", "open"): (1, _ATOMIC),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_write", "open"): (1, _FS_GUARD),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_write", "os.fdopen"): (
        2,
        _FS_GUARD,
    ),
    (f"{_ASH}/utils/cdk_nag_worker.py", "main", "open"): (1, _CDK_NAG_CHILD),
    (f"{_ASH}/utils/detect_secrets_worker.py", "main", "open"): (
        1,
        _DETECT_SECRETS_CHILD,
    ),
    (f"{_ASH}/utils/cdk_nag_wrapper.py", "run_cdk_nag_against_cfn_template", "open"): (
        1,
        "os.devnull",
    ),
    (f"{_ASH}/utils/download_utils.py", "_extract_single_member", "Path.open"): (
        2,
        _DOWNLOADS,
    ),
    (f"{_ASH}/utils/download_utils.py", "_extract_single_member._stage", "os.fdopen"): (
        1,
        _DOWNLOADS,
    ),
    (f"{_ASH}/utils/download_utils.py", "_finalize_staged", "os.replace"): (
        1,
        _DOWNLOADS,
    ),
    (f"{_ASH}/utils/download_utils.py", "_replace_atomically", "os.fdopen"): (
        1,
        _DOWNLOADS,
    ),
    (f"{_ASH}/utils/download_utils.py", "_restore_cached_asset", "open"): (
        1,
        _DOWNLOADS,
    ),
    (f"{_ASH}/utils/download_utils.py", "_store_cached_asset", "os.fdopen"): (
        1,
        _DOWNLOADS,
    ),
    (f"{_ASH}/utils/download_utils.py", "_store_cached_asset", "os.replace"): (
        1,
        _DOWNLOADS,
    ),
    (f"{_ASH}/utils/download_utils.py", "write_receipt", "write_text"): (
        1,
        "the install receipts under ASH's home",
    ),
    (f"{_ASH}/utils/file_lock.py", "exclusive_lock", "os.open"): (
        1,
        "lock files in the content-database cache",
    ),
    (f"{_ASH}/utils/pre_installed_tool.py", "_stage_nix_metadata", "shutil.copyfile"): (
        1,
        "a TemporaryDirectory the nix check creates",
    ),
    (f"{_ASH}/utils/sandbox/backends.py", "SandboxExecBackend.plan", "write_text"): (
        1,
        "the trust-roots file in a mkdtemp directory of the sandbox's own",
    ),
    (f"{_ASH}/utils/sandbox/backends.py", "_link_policy_paths_into", "symlink_to"): (
        1,
        "the sandbox's private home, a temporary directory",
    ),
}


def test_the_detector_finds_a_write_below_an_output_directory():
    source = (
        "from pathlib import Path\n"
        "import json, logging, os\n"
        "def emit(output_dir):\n"
        "    with open(output_dir / 'a.json', 'w') as f:\n"
        "        json.dump({}, f)\n"
        "    (output_dir / 'b.txt').write_text('b')\n"
        "    (output_dir / 'c.log').open('a')\n"
        "    logging.FileHandler(output_dir / 'd.log')\n"
        "    os.open(output_dir / 'e', os.O_WRONLY | os.O_CREAT)\n"
        "    os.replace(output_dir / 'f.tmp', output_dir / 'f')\n"
        "    open(output_dir / 'g', mode)\n"
    )

    found = write_sites(source, "probe.py")

    assert sorted(kind for _module, _function, kind in found) == sorted(
        [
            "open",
            "write_text",
            "Path.open",
            "FileHandler",
            "os.open",
            "os.replace",
            "open",
        ]
    )
    assert {function for _module, function, _kind in found} == {"emit"}


def test_the_detector_passes_the_guarded_writes_and_reads():
    source = (
        "from automated_security_helper.utils.sandbox.fs_guard import open_for_write\n"
        "from automated_security_helper.utils.atomic_write import write_text_atomically\n"
        "import os\n"
        "def emit(output_dir):\n"
        "    with open_for_write(output_dir / 'a.json') as f:\n"
        "        f.write('{}')\n"
        "    write_text_atomically(output_dir / 'b.json', '{}')\n"
        "    with open(output_dir / 'c.json') as f:\n"
        "        f.read()\n"
        "    with open(output_dir / 'd.json', 'rb') as f:\n"
        "        f.read()\n"
        "    os.open(output_dir / 'e', os.O_RDONLY)\n"
        "    'a-b'.replace('-', '_')\n"
    )

    assert write_sites(source, "probe.py") == []


def test_every_write_in_the_package_is_guarded_or_listed():
    found = _package_sites()
    listed = Counter(
        {
            site: count
            for site, (count, _where) in WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY.items()
        }
    )

    unlisted = sorted((found - listed).elements())
    stale = sorted((listed - found).elements())

    assert not unlisted, (
        "These calls write a file without fs_guard. Write them with "
        "fs_guard.open_for_write or write_text_atomically, or, if one writes "
        "outside every output directory, add it to "
        f"WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY with where it writes: {unlisted}"
    )
    assert not stale, f"Listed writes that no longer exist: {stale}"


@pytest.mark.parametrize("site", sorted(WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY))
def test_each_listed_write_says_where_it_writes(site):
    count, where = WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY[site]
    assert count >= 1 and where.strip(), site
