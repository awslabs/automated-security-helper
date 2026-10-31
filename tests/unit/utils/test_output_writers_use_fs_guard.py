"""Every file ASH writes below an output directory goes through ``fs_guard``.

``fs_guard.open_for_write``, ``fs_guard.open_for_atomic_write`` and its caller
``atomic_write.write_text_atomically`` never follow a
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
from typing import Dict, List, Optional, Tuple

import pytest

pytestmark = pytest.mark.unit

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


#: Name -> every value bound to it in one scope; None for a binding with no value
#: to follow (a parameter, a loop variable, an import, a def).
Bindings = Dict[str, List[Optional[ast.AST]]]


def _own_nodes(owner: ast.AST):
    """Every node of a module or function body that belongs to its own scope.

    A nested function, class or lambda is yielded (its name is bound here) but not
    entered."""
    pending = list(ast.iter_child_nodes(owner))
    while pending:
        node = pending.pop()
        yield node
        if not isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            pending.extend(ast.iter_child_nodes(node))


def _bindings(owner: ast.AST) -> Bindings:
    """The names a module, function or lambda binds, with the values it gives them.

    A store the reader does not follow binds the name to None, so the value is
    unreadable: a parameter, a loop variable, a ``with ... as`` name, an
    ``except ... as`` name, an import, a ``def`` or ``class``. So does a name that
    this scope or any scope below it declares ``global`` or ``nonlocal``: that code
    assigns it from statements these bindings do not show."""
    found: Bindings = {}

    def bind(target: ast.AST, value: Optional[ast.AST]) -> None:
        if isinstance(target, ast.Name):
            found.setdefault(target.id, []).append(value)
        elif isinstance(target, (ast.Tuple, ast.List, ast.Starred)):
            for inner in ast.iter_child_nodes(target):
                bind(inner, None)

    if isinstance(owner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = owner.args
        for argument in [
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
            arguments.vararg,
            arguments.kwarg,
        ]:
            if argument is not None:
                found.setdefault(argument.arg, []).append(None)
    for node in _own_nodes(owner):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        elif isinstance(node, ast.AnnAssign):
            bind(node.target, node.value)
        elif isinstance(node, ast.AugAssign):
            bind(node.target, node.value)
        elif isinstance(node, ast.NamedExpr):
            bind(node.target, node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            bind(node.target, None)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            bind(node.optional_vars, None)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                found.setdefault((alias.asname or alias.name).split(".")[0], []).append(
                    None
                )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.setdefault(node.name, []).append(None)
        elif isinstance(node, ast.ExceptHandler) and node.name is not None:
            found.setdefault(node.name, []).append(None)
    for node in ast.walk(owner):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                found.setdefault(name, []).append(None)
    return found


def _flag_names(node: ast.AST, frames: List[Bindings], seen=frozenset()):
    """The ``O_*`` names an os.open flags expression is built from.

    None when any part of it cannot be followed to such a name: a parameter, a call
    result, an attribute of something else, a number other than 0. Names are followed
    through the enclosing functions and the module, and a name with several
    bindings stands for all of them."""
    if isinstance(node, ast.Constant):
        return set() if node.value == 0 else None
    if isinstance(node, ast.Attribute):
        return {node.attr} if node.attr.startswith("O_") else None
    if isinstance(node, ast.Name):
        if node.id in seen:
            return set()
        for frame in reversed(frames):
            if node.id in frame:
                names: set = set()
                for value in frame[node.id]:
                    if value is None:
                        return None
                    part = _flag_names(value, frames, seen | {node.id})
                    if part is None:
                        return None
                    names |= part
                return names
        return {node.id} if node.id.startswith("O_") else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        left = _flag_names(node.left, frames, seen)
        right = _flag_names(node.right, frames, seen)
        return None if left is None or right is None else left | right
    if isinstance(node, ast.IfExp):
        body = _flag_names(node.body, frames, seen)
        other = _flag_names(node.orelse, frames, seen)
        return None if body is None or other is None else body | other
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) in (2, 3)
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
        and node.args[1].value.startswith("O_")
    ):
        names = {node.args[1].value}
        if len(node.args) == 3:
            default = _flag_names(node.args[2], frames, seen)
            if default is None:
                return None
            names |= default
        return names
    return None


def _may_write_by_flags(call: ast.Call, frames: List[Bindings]) -> bool:
    """True unless the os.open flags are provably built from read-only ``O_*`` names.

    Flags the detector cannot follow count as a write: a call that is not seen is the
    failure that lets an unguarded write in, and a read it cannot prove is one is listed
    in NOT_WRITES with why."""
    flags = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "flags":
            flags = keyword.value
    if flags is None:
        return True
    names = _flag_names(flags, frames)
    return names is None or bool(names & _WRITE_FLAGS)


def _kind(call: ast.Call, frames: List[Bindings]):
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
            return "os.open" if _may_write_by_flags(call, frames) else None
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

    def visit(node: ast.AST, scope: List[str], frames: List[Bindings]) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, [*scope, child.name], [*frames, _bindings(child)])
                continue
            if isinstance(child, ast.Lambda):
                # Its parameters are its own: a name it takes is not the enclosing
                # function's name of the same spelling.
                visit(child, scope, [*frames, _bindings(child)])
                continue
            if isinstance(child, ast.ClassDef):
                visit(child, [*scope, child.name], frames)
                continue
            if isinstance(child, ast.Call):
                kind = _kind(child, frames)
                if kind is not None:
                    sites.append((module, ".".join(scope) or "<module>", kind))
            visit(child, scope, frames)

    visit(tree, [], [_bindings(tree)])
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
_RULES_INSTALLS = (
    "the cfn-guard rules directory beside the tool installs (rules_bundles.rules_root): "
    "a staging directory made in it, renamed into place"
)
_ATOMIC = (
    "fs_guard.open_for_atomic_write itself, which write_text_atomically calls: a "
    "staging file it created exclusively, renamed over the target, relative to the "
    "guarded directory's descriptor below an output directory and by name outside"
)
_FS_GUARD = "fs_guard itself: open() only for a path below no registered root"
_FS_GUARD_OPEN_REGULAR = (
    "fs_guard itself: the file open_for_write opens below a registered root, "
    "relative to the guarded directory's descriptor (or by name where there is "
    "none), then checked on the descriptor: a regular file with one name"
)
_WRITE_PROBE = (
    "a probe file made in the directory being checked (O_CREAT | O_EXCL, not "
    "through a link, mode 0600) and removed at once"
)
_MCP_SESSIONS = (
    "the MCP server's workspace root: session markers and the lock files that "
    "record live servers and scans"
)
_OPERATOR_DESTINATION = (
    "fs_guard.replace_without_following: a destination the operator names, written "
    "as a new file renamed over it, with a symlink there refused"
)
_CDK_NAG_CHILD = (
    "the worker child's response file, created exclusively in the fresh "
    "directory its parent made and wrote the request into with fs_guard"
)
_DETECT_SECRETS_CHILD = (
    "the worker child's output file, created exclusively with mode 0600 (os.open "
    "O_EXCL|O_NOFOLLOW, then os.fdopen) after its parent wrote the request beside "
    "it with fs_guard and removed the name"
)
_MCP_PROFILE_COPY = (
    "the MCP server's workspace root: a session's profile copy, saved to a "
    "staging name and renamed over it"
)
_TOOL_CONFIG_DIR = (
    "a scanner run's own tool-config directory, new from mkdtemp with mode 0700 "
    "(in the temporary directory, or under the output directory when that is the "
    "private place outside the scanned tree), each file in it created with O_EXCL "
    "and O_NOFOLLOW"
)
_PROJECT_ASH_DIR = (
    "the project's .ash directory: the .gitignore that keeps scan output out of git, "
    "written with a new project config; not a file in an output directory"
)
_STDOUT_DIVERSION = (
    "os.devnull, opened to be duplicated over the process's standard output when "
    "standard error cannot be: no file is written"
)
_STDERR_DIVERSION = (
    "os.devnull, opened to be duplicated over the Landlock wrapper's standard error "
    "after a write to it failed: no file is written"
)
_MCP_PROFILE_SNAPSHOT = (
    "the MCP server's workspace root: the copy of a session's profile that one scan "
    "loads, beside the profile, taken exclusively at mode 0600"
)
_CONFIG_STAGED = (
    "the config file the operator names: a staging file beside it, created "
    "exclusively, synced, read back, and renamed over the resolved target"
)
_CONTAINER_STATE_DIR = (
    "the user's ASH state directory, written relative to its own descriptor opened "
    "with O_NOFOLLOW: a staging file created exclusively, renamed within it"
)
_CONTAINER_ENV_DIR = (
    "a new mode 0700 mkdtemp directory outside the source and output directories "
    "(the function refuses one inside either), the file created with O_EXCL at 0600"
)
_MCP_SESSION_WORKSPACE = (
    "the MCP server's workspace root: a session's workspace directory, renamed to a "
    "hidden sibling under the registry lock before it is removed; the rename moves "
    "the directory entry and follows no link"
)

#: (module, function, kind) -> (number of such calls, where they write). Each writes
#: outside every output directory, or is the guarded implementation itself.
WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY: Dict[Site, Tuple[int, str]] = {
    # Of the two Path.open calls in `download`, this one writes: the file
    # `target.open("wb")` creates. The other is in NOT_WRITES.
    (_INSTALLER, "download", "Path.open"): (1, _INSTALLS),
    (_INSTALLER, "extract_member", "Path.open"): (4, _INSTALLS),
    (_INSTALLER, "_prepare_executable", "shutil.copyfile"): (1, _INSTALLS),
    (_INSTALLER, "_commit_executable", "os.replace"): (1, _INSTALLS),
    (_INSTALLER, "_rename_or_copy", "os.replace"): (1, _INSTALLS),
    (_INSTALLER, "_rename_or_copy", "shutil.copytree"): (2, _INSTALLS),
    (_INSTALLER, "publish_third_party", "os.replace"): (1, _INSTALLS),
    (_INSTALLER, "publish_third_party", "shutil.copytree"): (1, _INSTALLS),
    # The KEPT marker written into a license work directory that still holds the
    # earlier entry, so a later publish of the same tool can remove it.
    (_INSTALLER, "publish_third_party", "write_text"): (1, _INSTALLS),
    (_INSTALLER, "stage_third_party", "shutil.copyfile"): (1, _INSTALLS),
    (_INSTALLER, "stage_third_party", "write_text"): (1, _INSTALLS),
    (_INSTALLER, "verify_third_party", "write_text"): (1, _INSTALLS),
    # The config writes of init, update, the wizard and the lint fixers
    # (_write_config_text, _write_config_bytes) are not listed: they write through
    # fs_guard.open_for_atomic_write, with fs_guard.open_for_write as the fallback
    # for a place the staged write cannot use, so neither makes a bare write.
    (f"{_ASH}/cli/config.py", "_ensure_output_gitignore", "write_text"): (
        1,
        _PROJECT_ASH_DIR,
    ),
    (f"{_ASH}/config/ash_config.py", "AshConfig.save", "open"): (1, _CONFIG),
    (f"{_ASH}/config/ash_config.py", "AshConfig.save", "write_text"): (1, _CONFIG),
    (f"{_ASH}/config/ash_config.py", "_staged_beside", "os.open"): (
        1,
        _CONFIG_STAGED,
    ),
    (f"{_ASH}/config/ash_config.py", "_write_checked", "os.fdopen"): (
        1,
        _CONFIG_STAGED,
    ),
    (f"{_ASH}/config/ash_config.py", "_write_checked", "os.replace"): (
        1,
        _CONFIG_STAGED,
    ),
    (f"{_ASH}/cli/entrypoint.py", "_reattach", "os.fdopen"): (
        1,
        "the process's own standard stream",
    ),
    (f"{_ASH}/interactions/container_leftovers.py", "record_container", "os.open"): (
        1,
        _CONTAINER_STATE_DIR,
    ),
    (f"{_ASH}/interactions/container_leftovers.py", "record_container", "os.fdopen"): (
        1,
        _CONTAINER_STATE_DIR,
    ),
    (f"{_ASH}/interactions/container_leftovers.py", "record_container", "os.rename"): (
        1,
        _CONTAINER_STATE_DIR,
    ),
    (f"{_ASH}/interactions/container_leftovers.py", "record_env_dir", "os.open"): (
        1,
        _CONTAINER_STATE_DIR,
    ),
    (f"{_ASH}/interactions/container_leftovers.py", "record_env_dir", "os.fdopen"): (
        1,
        _CONTAINER_STATE_DIR,
    ),
    (f"{_ASH}/interactions/container_leftovers.py", "record_env_dir", "os.rename"): (
        1,
        _CONTAINER_STATE_DIR,
    ),
    (f"{_ASH}/interactions/run_ash_container.py", "_write_env_file", "os.open"): (
        1,
        _CONTAINER_ENV_DIR,
    ),
    (f"{_ASH}/interactions/run_ash_container.py", "_write_env_file", "os.fdopen"): (
        1,
        _CONTAINER_ENV_DIR,
    ),
    (f"{_ASH}/cli/mcp/source_delivery.py", "_write_next_sequence", "write_text"): (
        1,
        "the MCP upload workspace, where a client's source is assembled",
    ),
    (f"{_ASH}/cli/mcp/source_delivery.py", "_append_zip_chunk", "Path.open"): (
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
    (
        f"{_ASH}/cli/mcp/sessions.py",
        "StdioServerPresence.a_server_is_live",
        "open",
    ): (1, _MCP_SESSIONS),
    (f"{_ASH}/cli/mcp/sessions.py", "_a_scan_holds", "open"): (1, _MCP_SESSIONS),
    (
        f"{_ASH}/cli/mcp/profile_registry.py",
        "_replace_staged",
        "os.replace",
    ): (1, _MCP_PROFILE_COPY),
    (f"{_ASH}/cli/mcp/sessions.py", "_scan_presence_guard", "open"): (
        1,
        _MCP_SESSIONS,
    ),
    (
        f"{_ASH}/cli/mcp/sessions.py",
        "MCPSessionRegistry._rename_for_removal_locked",
        "os.rename",
    ): (1, _MCP_SESSION_WORKSPACE),
    # The source-delivery end of a session: the same rename of the session's
    # workspace directory to its hidden delete name, from the delivery module
    # (source_delivery.py, main's since #830).
    (
        f"{_ASH}/cli/mcp/source_delivery.py",
        "_set_aside_for_removal",
        "os.rename",
    ): (1, _MCP_SESSION_WORKSPACE),
    (f"{_ASH}/cli/mcp_tools.py", "mcp_validate_config", "write_text"): (
        1,
        "a TemporaryDirectory of its own",
    ),
    (f"{_ASH}/cli/mcp_tools.py", "_snapshot_profile_for_scan", "os.open"): (
        1,
        _MCP_PROFILE_SNAPSHOT,
    ),
    (f"{_ASH}/cli/mcp_tools.py", "_snapshot_profile_for_scan", "os.fdopen"): (
        1,
        _MCP_PROFILE_SNAPSHOT,
    ),
    (
        f"{_ASH}/plugin_modules/ash_builtin/converters/jupyter_converter.py",
        "JupyterConverter._stage_notebook",
        "write_bytes",
    ): (1, "the converter's own TemporaryDirectory for nbconvert"),
    (f"{_ASH}/schemas/generate_schemas.py", "_write_if_changed", "os.open"): (
        1,
        "the JSON schemas in the source checkout, a development step",
    ),
    (f"{_ASH}/schemas/generate_schemas.py", "_write_if_changed", "os.fdopen"): (
        1,
        "the JSON schemas in the source checkout, a development step",
    ),
    (f"{_ASH}/schemas/generate_schemas.py", "_write_if_changed", "os.replace"): (
        1,
        "the JSON schemas in the source checkout, a development step",
    ),
    (f"{_ASH}/utils/atomic_write.py", "_replace", "os.replace"): (1, _ATOMIC),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_atomic_write", "os.open"): (
        2,
        _ATOMIC,
    ),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_atomic_write", "os.fdopen"): (
        1,
        _ATOMIC,
    ),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_atomic_write", "os.replace"): (
        1,
        _ATOMIC,
    ),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_write", "open"): (1, _FS_GUARD),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_write", "os.open"): (1, _FS_GUARD),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "_open_regular", "os.open"): (
        2,
        _FS_GUARD_OPEN_REGULAR,
    ),
    (f"{_ASH}/utils/sandbox/fs_guard.py", "open_for_write", "os.fdopen"): (
        2,
        _FS_GUARD,
    ),
    # A destination the operator names (ash get-genai-guide --output): a symlink
    # there is refused, and the file is a new one renamed over it.
    (f"{_ASH}/utils/sandbox/fs_guard.py", "replace_without_following", "os.open"): (
        1,
        _OPERATOR_DESTINATION,
    ),
    (
        f"{_ASH}/utils/sandbox/fs_guard.py",
        "replace_without_following",
        "os.fdopen",
    ): (1, _OPERATOR_DESTINATION),
    (
        f"{_ASH}/utils/sandbox/fs_guard.py",
        "replace_without_following",
        "os.replace",
    ): (1, _OPERATOR_DESTINATION),
    (f"{_ASH}/utils/cdk_nag_worker.py", "main", "open"): (1, _CDK_NAG_CHILD),
    (f"{_ASH}/utils/tool_config_dir.py", "write_tool_config", "os.open"): (
        2,
        _TOOL_CONFIG_DIR,
    ),
    (f"{_ASH}/utils/tool_config_dir.py", "write_tool_config", "os.fdopen"): (
        1,
        _TOOL_CONFIG_DIR,
    ),
    (f"{_ASH}/utils/detect_secrets_worker.py", "_write_output", "os.open"): (
        1,
        _DETECT_SECRETS_CHILD,
    ),
    (f"{_ASH}/utils/detect_secrets_worker.py", "_write_output", "os.fdopen"): (
        1,
        _DETECT_SECRETS_CHILD,
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
    # One open creates: the read-write open, with O_CREAT. The read-only fallback
    # for a lock file another account made does not ask to create, so it is no
    # write and the detector does not count it.
    (f"{_ASH}/utils/file_lock.py", "_open_lock_file", "os.open"): (
        1,
        "lock files in the content-database cache",
    ),
    (f"{_ASH}/utils/directory_refusals.py", "_write_refused", "os.open"): (
        1,
        _WRITE_PROBE,
    ),
    (f"{_ASH}/utils/pre_installed_tool.py", "_stage_nix_metadata", "shutil.copyfile"): (
        1,
        "a TemporaryDirectory the nix check creates",
    ),
    # The sandbox-exec plan is built in _plan; plan only makes the private TMPDIR
    # and removes everything on a failure part way through.
    (f"{_ASH}/utils/sandbox/backends.py", "SandboxExecBackend._plan", "write_text"): (
        1,
        "the trust-roots file in a mkdtemp directory of the sandbox's own",
    ),
    (f"{_ASH}/utils/sandbox/backends.py", "_link_policy_paths_into", "symlink_to"): (
        1,
        "the sandbox's private home, a temporary directory",
    ),
    # The cfn-guard rules bundle, installed beside the tools: staged under the
    # rules directory and renamed into place.
    (_INSTALLER, "install_bundle", "Path.open"): (2, _INSTALLS),
    (_INSTALLER, "install_bundle", "os.replace"): (2, _INSTALLS),
    (_INSTALLER, "install_bundle", "write_text"): (1, _INSTALLS),
    (f"{_ASH}/utils/rules_bundles.py", "extract_bundle", "Path.open"): (
        1,
        _RULES_INSTALLS,
    ),
    (f"{_ASH}/utils/rules_bundles.py", "extract_bundle", "os.open"): (
        1,
        _RULES_INSTALLS,
    ),
    (f"{_ASH}/utils/rules_bundles.py", "extract_bundle", "os.fdopen"): (
        1,
        _RULES_INSTALLS,
    ),
    # Three renames: the old bundle aside, the staged one into place, and the old
    # one back when that rename fails.
    (f"{_ASH}/utils/rules_bundles.py", "_install_locked", "os.replace"): (
        3,
        _RULES_INSTALLS,
    ),
    (f"{_ASH}/utils/rules_bundles.py", "_install_locked", "write_text"): (
        1,
        _RULES_INSTALLS,
    ),
    # gitleaks' re-scan copies of the files a .gitleaksignore names.
    (
        f"{_ASH}/plugin_modules/ash_builtin/scanners/gitleaks_scanner.py",
        "_write_private_copy",
        "os.open",
    ): (1, _TOOL_CONFIG_DIR),
    (
        f"{_ASH}/plugin_modules/ash_builtin/scanners/gitleaks_scanner.py",
        "_write_private_copy",
        "os.fdopen",
    ): (1, _TOOL_CONFIG_DIR),
}


_NULL_DEVICE = "the null device (os.devnull): no file is written"
_READS_WITH_COMPUTED_FLAGS = (
    "nothing: a read (O_RDONLY) whose other flags are added from names looked up "
    "at run time, which the detector cannot follow"
)

#: (module, function, kind) -> (number of such calls, why none of them writes a
#: file). Calls the detector cannot tell from a write: an open() whose mode it cannot
#: read, and an os.open() whose flags it cannot follow to read-only ``O_*`` names.
#: Kept apart from the writes so that table lists only real writes, and limited to the
#: three kinds that can be mistaken for one (see the test of the kinds below): a
#: ``write_text`` or an ``os.replace`` is never a read, so none may be listed here.
NOT_WRITES: Dict[Site, Tuple[int, str]] = {
    # The other Path.open in `download`: the urllib opener's `opener.open(url, ...)`,
    # a network call.
    (_INSTALLER, "download", "Path.open"): (
        1,
        "nothing: the urllib opener's opener.open(url, ...), a network call",
    ),
    # `zf.open(info)` opens a zip member for reading; the detector cannot read the
    # mode of an open() whose first argument is not a literal.
    (f"{_ASH}/cli/mcp/source_delivery.py", "_finalize_zip_upload", "Path.open"): (
        1,
        "nothing: it reads a member of the uploaded zip",
    ),
    (f"{_ASH}/cli/mcp_server.py", "_keep_stdout_off_the_wire", "os.open"): (
        1,
        _STDOUT_DIVERSION,
    ),
    (f"{_ASH}/cli/report.py", "report_command", "os.open"): (1, _STDOUT_DIVERSION),
    (f"{_ASH}/utils/sandbox/landlock_exec.py", "_give_up_stderr", "os.open"): (
        1,
        _STDERR_DIVERSION,
    ),
    (f"{_ASH}/utils/cdk_nag_wrapper.py", "run_cdk_nag_against_cfn_template", "open"): (
        1,
        _NULL_DEVICE,
    ),
    (f"{_ASH}/cli/entrypoint.py", "_reserve_descriptor", "os.open"): (
        1,
        _NULL_DEVICE + "; the caller passes the flags",
    ),
    (f"{_ASH}/cli/mcp/__init__.py", "_auth_value_from_file", "os.open"): (
        1,
        _READS_WITH_COMPUTED_FLAGS,
    ),
    (f"{_ASH}/cli/mcp/progress_monitor.py", "_read_scanner_severity", "os.open"): (
        1,
        _READS_WITH_COMPUTED_FLAGS,
    ),
    # Both opens are of a directory for reading; the flags take the caller's extra.
    (f"{_ASH}/utils/scanned_tree.py", "_open_directory", "os.open"): (
        2,
        "nothing: O_RDONLY on a directory, with a caller's extra flags",
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


def test_an_os_open_whose_flags_it_cannot_follow_counts_as_a_write():
    """Flags held in a parameter, built by a call or looked up at run time are not
    shown to be read-only, so the open is found; at the base only a literal
    ``os.O_*`` expression was read and every one of these was passed over."""
    source = (
        "import os\n"
        "def from_a_parameter(path, flags):\n"
        "    return os.open(path, flags)\n"
        "def from_a_call(path):\n"
        "    return os.open(path, compute())\n"
        "def looked_up_at_run_time(path, names):\n"
        "    flags = os.O_RDONLY\n"
        "    for name in names:\n"
        "        flags |= getattr(os, name, 0)\n"
        "    return os.open(path, flags)\n"
        "def by_keyword(path, flags):\n"
        "    return os.open(path, flags=flags)\n"
        "def a_number(path):\n"
        "    return os.open(path, 577)\n"
    )

    found = write_sites(source, "probe.py")

    assert sorted(function for _module, function, _kind in found) == sorted(
        [
            "from_a_parameter",
            "from_a_call",
            "looked_up_at_run_time",
            "by_keyword",
            "a_number",
        ]
    )
    assert {kind for _module, _function, kind in found} == {"os.open"}


def test_an_os_open_whose_flags_are_followed_to_a_write_flag_is_found():
    """A write flag held in a name counts, a local one and a module's alike, and one
    binding of the name among several is enough."""
    source = (
        "import os\n"
        "_CREATE = os.O_WRONLY | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)\n"
        "def from_a_module_constant(path):\n"
        "    return os.open(path, _CREATE)\n"
        "def from_a_local(path):\n"
        "    flags = os.O_RDONLY\n"
        "    flags |= os.O_CREAT\n"
        "    return os.open(path, flags)\n"
        "def one_binding_of_two(path, exclusive):\n"
        "    flags = os.O_RDONLY\n"
        "    if exclusive:\n"
        "        flags = os.O_RDWR | os.O_EXCL\n"
        "    return os.open(path, flags, 0o600)\n"
        "def through_a_conditional(path, writing):\n"
        "    return os.open(path, os.O_WRONLY if writing else os.O_RDONLY)\n"
    )

    found = write_sites(source, "probe.py")

    assert sorted(function for _module, function, _kind in found) == sorted(
        [
            "from_a_module_constant",
            "from_a_local",
            "one_binding_of_two",
            "through_a_conditional",
        ]
    )


def test_an_os_open_whose_flags_are_followed_to_read_only_names_is_not_found():
    source = (
        "import os\n"
        "_READ = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)\n"
        "_DIRECTORY = getattr(os, 'O_DIRECTORY', 0)\n"
        "def from_a_module_constant(path):\n"
        "    return os.open(path, _READ)\n"
        "def from_names(path):\n"
        "    return os.open(path, os.O_RDONLY | _DIRECTORY)\n"
        "def from_a_local(path, dir_fd):\n"
        "    flags = os.O_RDONLY\n"
        "    flags |= _DIRECTORY\n"
        "    return os.open(path, flags, dir_fd=dir_fd)\n"
        "def a_name_that_rebinds_itself(path):\n"
        "    flags = os.O_RDONLY\n"
        "    flags = flags | _DIRECTORY\n"
        "    return os.open(path, flags=flags)\n"
        "def a_read_through_the_path_flag(path):\n"
        "    return os.open(path, os.O_PATH | os.O_CLOEXEC)\n"
    )

    assert write_sites(source, "probe.py") == []


def _opens(source: str):
    return [kind for _module, _function, kind in write_sites(source, "probe.py")]


def test_a_lambda_takes_its_own_parameters():
    """``flags`` in the lambda is its parameter, whatever the enclosing function binds
    under that spelling: the lookup went past the lambda to the function's read-only
    assignment and passed the call."""
    source = (
        "import os\n"
        "def build(path):\n"
        "    flags = os.O_RDONLY\n"
        "    return lambda flags: os.open(path, flags)\n"
    )

    assert _opens(source) == ["os.open"]


def test_control_a_lambda_reads_the_enclosing_functions_flags():
    source = (
        "import os\n"
        "def build(path):\n"
        "    flags = os.O_RDONLY\n"
        "    return lambda: os.open(path, flags)\n"
    )

    assert _opens(source) == []


@pytest.mark.parametrize(
    "rebinding",
    [
        pytest.param("flags, extra = os.O_WRONLY, 0", id="tuple-unpacking"),
        pytest.param("for flags in choices: pass", id="for-over-a-variable"),
        pytest.param("with source() as flags: pass", id="with-as"),
        pytest.param("(flags := compute())", id="walrus"),
        pytest.param(
            "try:\n        pass\n    except ImportError as flags:\n        pass",
            id="except-as",
        ),
        pytest.param("from elsewhere import flags", id="import"),
        pytest.param("import flags", id="import-module"),
        pytest.param("def flags(): pass", id="def"),
    ],
)
def test_a_store_the_reader_does_not_follow_leaves_the_flags_unreadable(rebinding):
    """``flags`` is read from the one assignment the reader follows; a second store
    it does not follow, whatever its form, leaves the value unreadable and the call
    counted. An ``except ... as`` store was skipped without a word, so the call read
    as the first assignment."""
    source = (
        "import os\n"
        "def emit(path, choices, source, compute):\n"
        "    flags = os.O_RDONLY\n"
        f"    {rebinding}\n"
        "    os.open(path, flags)\n"
    )

    assert _opens(source) == ["os.open"]


def test_a_name_declared_global_is_not_the_value_assigned_in_this_function():
    """``flags |= ...`` after ``global flags`` widens the module's value, which the
    module's own assignment does not show; only the added flag was read."""
    source = (
        "import os\n"
        "flags = os.O_RDONLY\n"
        "def widen(path):\n"
        "    global flags\n"
        "    flags |= getattr(os, 'O_NOFOLLOW', 0)\n"
        "    return os.open(path, flags)\n"
    )

    assert _opens(source) == ["os.open"]


def test_a_module_name_another_function_assigns_through_global_is_unreadable():
    """The module binds ``flags`` to a read, and ``enable_writes`` replaces it at run
    time; ``look`` reads whatever is there then."""
    source = (
        "import os\n"
        "flags = os.O_RDONLY\n"
        "def enable_writes():\n"
        "    global flags\n"
        "    flags = os.O_WRONLY | os.O_CREAT\n"
        "def look(path):\n"
        "    return os.open(path, flags)\n"
    )

    assert _opens(source) == ["os.open"]


def test_an_enclosing_name_an_inner_function_assigns_through_nonlocal_is_unreadable():
    source = (
        "import os\n"
        "def outer(path):\n"
        "    flags = os.O_RDONLY\n"
        "    def widen():\n"
        "        nonlocal flags\n"
        "        flags = os.O_WRONLY | os.O_CREAT\n"
        "    widen()\n"
        "    return os.open(path, flags)\n"
    )

    assert _opens(source) == ["os.open"]


def test_control_a_name_no_function_declares_global_stays_a_read():
    source = (
        "import os\n"
        "flags = os.O_RDONLY\n"
        "other = 0\n"
        "def bump():\n"
        "    global other\n"
        "    other = 1\n"
        "def look(path):\n"
        "    return os.open(path, flags)\n"
    )

    assert _opens(source) == []


def test_every_write_in_the_package_is_guarded_or_listed():
    found = _package_sites()
    listed = Counter()
    for table in (WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY, NOT_WRITES):
        for site, (count, _where) in table.items():
            listed[site] += count

    unlisted = sorted((found - listed).elements())
    stale = sorted((listed - found).elements())

    assert not unlisted, (
        "These calls write a file without fs_guard, or open one in a way the "
        "detector cannot show to be a read. Write them with "
        "fs_guard.open_for_write, fs_guard.open_for_atomic_write or "
        "write_text_atomically; if one writes outside every output directory, add it "
        "to WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY with where it writes; if it writes "
        f"nothing, add it to NOT_WRITES with why: {unlisted}"
    )
    assert not stale, f"Listed calls that no longer exist: {stale}"


@pytest.mark.parametrize("site", sorted(WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY))
def test_each_listed_write_says_where_it_writes(site):
    count, where = WRITES_OUTSIDE_THE_OUTPUT_DIRECTORY[site]
    assert count >= 1 and where.strip(), site
    assert not where.startswith("nothing"), (
        f"{site} says it writes nothing; it belongs in NOT_WRITES"
    )


@pytest.mark.parametrize("site", sorted(NOT_WRITES))
def test_each_listed_non_write_says_why_and_is_a_kind_that_can_be_mistaken(site):
    count, why = NOT_WRITES[site]
    assert count >= 1 and why.strip(), site
    assert site[2] in {"open", "Path.open", "os.open"}, (
        f"{site}: a {site[2]} is a write whatever it is called on, so it cannot be "
        "listed as a call that writes nothing"
    )
