#!/usr/bin/env bash
# Install ASH MCP customization for Cline (VS Code).
# Adds the ash server to the existing MCP config, keeping every other server and setting.
# The previous file is saved beside it first. Re-running changes nothing once the entry is current.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

EXT_DIR="User/globalStorage/saoudrizwan.claude-dev/settings"
case "$(uname -s)" in
  Darwin) BASE="$HOME/Library/Application Support/Code" ;;
  Linux) BASE="$HOME/.config/Code" ;;
  *) echo "Unsupported OS: $(uname -s). Add the ash entry to Cline's cline_mcp_settings.json by hand." >&2; exit 1 ;;
esac
TARGET="$BASE/$EXT_DIR/cline_mcp_settings.json"
if [[ ! -d "$BASE/$EXT_DIR" ]]; then
  echo "Cline VS Code extension not detected at $BASE/$EXT_DIR" >&2
  echo "Install Cline first, then re-run this script." >&2
  exit 1
fi
ASH_MCP_ENTRY='{
  "command": "uvx",
  "args": [
    "--from=git+https://github.com/awslabs/automated-security-helper@v3.7.1",
    "ash",
    "mcp"
  ],
  "env": {
    "FASTMCP_LOG_LEVEL": "ERROR"
  },
  "timeout": 120000,
  "disabled": false
}'
if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is not on PATH. It is needed to add ASH to $TARGET without replacing the MCP servers already in it, so $TARGET was not changed." >&2
  echo 'Add this entry under "mcpServers" in that file by hand:' >&2
  printf '"ash": %s\n' "$ASH_MCP_ENTRY" >&2
  exit 1
fi
python3 -I - "$TARGET" mcpServers ash "$ASH_MCP_ENTRY" <<'PY'
"""Add one MCP server entry to a client's JSON config file without touching the rest.

This file is not imported by the transpiler. `install_scripts.py` embeds its source
verbatim into the generated install.sh of every platform whose MCP config is a
user-level JSON file shared with other servers (Cline, Windsurf, Gemini CLI), and
the script runs it as `python3 -I - TARGET SERVERS_KEY NAME ENTRY_JSON`.

Why it exists: writing the file with `cat > "$TARGET"` would delete every other
MCP server and setting the user has in it.

What it does:

* Keeps every other key, at every level, and replaces only SERVERS_KEY[NAME].
* Refuses, without writing anything, a file that is not a JSON object, whose
  SERVERS_KEY is not an object, that repeats a key (the last copy would silently
  win on rewrite), or that is not plain JSON (comments, trailing commas).
* Copies the old file to `<file>.ash-backup-<UTC time>` before changing it, with
  the file's own mode, beside the path it was given: for a symlinked config that
  is beside the link, not in the directory the link points into, which is often a
  dotfiles git repository.
* Writes through a temporary file in the same directory and renames it into place,
  so an interrupted run leaves the old file rather than half of a new one.
* Follows a symlinked config and updates the file it points at, so a dotfiles
  link stays a link.
* Reads a file that starts with a UTF-8 byte order mark, as some Windows editors
  save JSON, and writes the mark back.
* When the file or its directory cannot be written, says so and prints the entry
  to add by hand, as for a refused file, rather than ending in a traceback.
* Does nothing, and makes no backup, when the entry is already current.

Known limitation: the rewritten file is formatted with two-space indentation, so a
user's own formatting is not kept. The backup is.

It runs under whatever `python3` the user has, not the transpiler's interpreter:
standard library only, and nothing newer than Python 3.8.
"""

import codecs
import json
import os
import stat
import sys
import tempfile
import time


class Refused(Exception):
    """The file cannot be merged safely, so it is left exactly as it was."""


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("the key %r appears more than once in one object" % key)
        result[key] = value
    return result


def _load(path):
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        raise Refused("could not be read (%s)" % exc)
    try:
        # utf-8-sig drops a leading byte order mark, which json.loads refuses.
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise Refused("is not UTF-8 text")
    if not text.strip():
        return raw, {}
    try:
        config = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except ValueError as exc:
        raise Refused(
            "is not plain JSON that this script can rewrite safely (%s)" % exc
        )
    return raw, config


def _backup_path(path):
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    candidate = "%s.ash-backup-%s" % (path, stamp)
    counter = 1
    while os.path.lexists(candidate):
        candidate = "%s.ash-backup-%s-%d" % (path, stamp, counter)
        counter += 1
    return candidate


def _new_file_mode():
    umask = os.umask(0)
    os.umask(umask)
    return 0o666 & ~umask


def _write(path, text, mode):
    directory = os.path.dirname(path) or "."
    fd, temporary = tempfile.mkstemp(
        dir=directory, prefix="." + os.path.basename(path) + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        if os.path.lexists(temporary):
            os.unlink(temporary)
        raise


def merge(target, servers_key, name, entry):
    """Merge `entry` into `target` and return a list of lines describing the result."""
    path = os.path.realpath(target)
    exists = os.path.lexists(target)

    if exists and not os.path.exists(path):
        raise Refused("is a symlink to %s, which does not exist" % path)
    if exists and not os.path.isfile(path):
        raise Refused("is not a regular file")

    if exists:
        raw, config = _load(path)
    else:
        raw, config = None, {}

    if not isinstance(config, dict):
        raise Refused("does not hold a JSON object at the top level")
    servers = config.get(servers_key, {})
    if not isinstance(servers, dict):
        raise Refused('has a "%s" that is not a JSON object' % servers_key)

    if servers.get(name) == entry:
        return [
            "%s already has the current %r MCP server; nothing to change."
            % (target, name)
        ]

    action = "Updated" if name in servers else "Added"
    servers[name] = entry
    # Keeps the key's place when it existed, and appends it when it did not.
    config[servers_key] = servers
    text = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    if raw is not None and raw.startswith(codecs.BOM_UTF8):
        text = "\ufeff" + text

    # The file may hold credentials (an env block of another server), so the
    # backup and the rewrite get its mode. The backup is created no wider than
    # 0600 and then given the mode exactly, so it is never readable by more
    # people than the file, whatever the umask. os.fchmod is missing on Windows
    # Pythons before 3.13, which some of these scripts reach through Git Bash;
    # there the mode is set by path once the copy is written.
    mode = stat.S_IMODE(os.stat(path).st_mode) if exists else _new_file_mode()
    fchmod = getattr(os, "fchmod", None)

    lines = []
    backup = None
    try:
        if raw is not None and raw.strip():
            backup = _backup_path(os.path.abspath(target))
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode & 0o600)
            try:
                with os.fdopen(fd, "wb") as handle:
                    if fchmod is not None:
                        fchmod(handle.fileno(), mode)
                    handle.write(raw)
                if fchmod is None:
                    os.chmod(backup, mode)
            except BaseException:
                # A partial copy would look like a good backup; take it away.
                try:
                    os.unlink(backup)
                except OSError:
                    pass
                backup = None
                raise
            lines.append("The previous file is saved as %s." % backup)
        _write(path, text, mode)
    except OSError as exc:
        detail = "could not be written (%s)" % exc
        if backup is not None and os.path.lexists(backup):
            detail += "; the copy saved before the attempt is %s" % backup
        raise Refused(detail)

    others = len(servers) - 1
    lines.insert(
        0,
        "%s the %r MCP server in %s; %d other server(s) left as they were."
        % (action, name, target, others),
    )
    return lines


def main(argv):
    if len(argv) != 4:
        print(
            "usage: python3 -I - TARGET SERVERS_KEY NAME ENTRY_JSON",
            file=sys.stderr,
        )
        return 2
    target, servers_key, name, entry_text = argv
    entry = json.loads(entry_text)
    try:
        lines = merge(target, servers_key, name, entry)
    except Refused as exc:
        print("%s %s. It was not changed." % (target, exc), file=sys.stderr)
        print(
            'Add this entry under "%s" in that file by hand:' % servers_key,
            file=sys.stderr,
        )
        print(
            "%s: %s" % (json.dumps(name), json.dumps(entry, indent=2)), file=sys.stderr
        )
        return 1
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
PY
echo "Reload the VS Code window for changes to take effect."
