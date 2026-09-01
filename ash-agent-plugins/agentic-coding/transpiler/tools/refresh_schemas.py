"""Refresh the cached external JSON Schemas declared in schemas/schemas.json.

Run via the package entrypoint:
    uv run --project agentic-coding/transpiler refresh-schemas

For each entry in schemas.json:
  - kind: "direct" — fetches the URL with HTTP, validates response is a JSON
    object, writes to schemas/<filename>
  - kind: "zod-converted" — clones the source repo into a temp dir, runs
    tools/zod_to_json_schema.mjs to convert the named Zod schema to JSON
    Schema, writes to schemas/<filename>

Direct entries require curl. Zod-converted entries require Node >=18 and git.
Both pre-conditions are checked at startup; missing tools fail with an
actionable error message.

After refresh, run `uv run --project agentic-coding/transpiler transpile --check`
to confirm the new schemas still validate the generated outputs.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent          # transpiler/tools
TRANSPILER_DIR = HERE.parent                     # transpiler/
SCHEMAS_DIR = TRANSPILER_DIR / "schemas"
SCHEMAS_INDEX = SCHEMAS_DIR / "schemas.json"
ZOD_CONVERTER = HERE / "zod_to_json_schema.mjs"


def _require_tool(name: str, install_hint: str) -> str:
    """Resolve *name* on PATH, or exit 2 with *install_hint*.

    Returns the absolute path, which is what callers must put in argv[0]. A bare
    name there is resolved a second time by the child process against whatever
    PATH it inherits, so the tool that runs need not be the one this check found.
    """
    resolved = shutil.which(name)
    if resolved is None:
        sys.stderr.write(f"ERROR: {name} not found on PATH. {install_hint}\n")
        sys.exit(2)
    return resolved


def _fetch_direct(url: str, dest: Path) -> None:
    """HTTP GET the schema and write to dest. Validates the response parses
    as a JSON object — refuses to write garbage to the cache.

    Sets a User-Agent header because some hosts (notably opencode.ai) reject
    the default urllib UA with 403 Forbidden."""
    print(f"  fetching {url}")
    # Reject non-HTTP(S) schemes before opening. urlopen also honours file:// and
    # custom openers, so a schema URL sourced from config must be constrained or it
    # becomes a local-file read primitive (bandit B310).
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        sys.stderr.write(f"ERROR: refusing to fetch non-HTTP(S) URL: {url}\n")
        sys.exit(1)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "agentic-coding-transpiler/0.1 (schema-refresh)"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # nosec B310 - scheme checked above
        data = resp.read()
    parsed = json.loads(data)  # raises if not JSON
    if not isinstance(parsed, dict):
        sys.stderr.write(f"ERROR: {url} did not return a JSON object\n")
        sys.exit(1)
    dest.write_bytes(data if data.endswith(b"\n") else data + b"\n")
    print(f"    -> {dest.name} ({len(data)} bytes)")


def _convert_zod(entry: dict, dest: Path) -> None:
    """Clone the source repo into a temp dir, run the Node converter, copy
    the resulting JSON Schema to dest."""
    node = _require_tool("node", "Install Node.js >=18 (https://nodejs.org).")
    _require_tool("npm", "Install npm (typically bundled with Node).")
    git = _require_tool("git", "Install git.")

    repo_url = entry["source_url"]
    # Constrained before it reaches git, for the same reason _fetch_direct
    # constrains its URL: this value comes from schemas.json, so it is
    # configuration rather than a literal. git clone accepts far more than an HTTP
    # URL -- `ext::<command>` makes it run a command, `file://` and a bare
    # relative path make it read the local disk, and a value beginning with `-` is
    # read as an option rather than a URL. Requiring an HTTP(S) scheme excludes
    # all four.
    scheme = urllib.parse.urlparse(repo_url).scheme.lower()
    if scheme not in ("http", "https"):
        sys.stderr.write(
            f"ERROR: refusing to clone non-HTTP(S) source_url: {repo_url}\n"
        )
        sys.exit(1)
    print(f"  cloning {repo_url}")
    with tempfile.TemporaryDirectory() as tmp:
        clone_dir = Path(tmp) / "repo"
        subprocess.run(
            [git, "clone", "--depth", "1", "--", repo_url, str(clone_dir)],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        # Run the Node converter pointed at the cloned repo, output goes
        # straight into the schemas/ cache.
        subprocess.run(
            [node, str(ZOD_CONVERTER), str(clone_dir), str(dest)],
            check=True,
        )
    print(f"    -> {dest.name} ({dest.stat().st_size} bytes)")


def main() -> int:
    if not SCHEMAS_INDEX.exists():
        sys.stderr.write(f"ERROR: {SCHEMAS_INDEX} not found\n")
        return 1
    index = json.loads(SCHEMAS_INDEX.read_text())

    failures: list[str] = []
    for entry in index["schemas"]:
        filename = entry["filename"]
        kind = entry["kind"]
        dest = SCHEMAS_DIR / filename
        print(f"\nRefreshing {filename} (kind={kind})")
        try:
            if kind == "direct":
                _fetch_direct(entry["source_url"], dest)
            elif kind == "zod-converted":
                _convert_zod(entry, dest)
            else:
                sys.stderr.write(f"  ERROR: unknown kind '{kind}' for {filename}\n")
                failures.append(filename)
        except subprocess.CalledProcessError as e:
            sys.stderr.write(f"  ERROR: subprocess failed for {filename}: {e}\n")
            failures.append(filename)
        except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
            sys.stderr.write(f"  ERROR: refresh failed for {filename}: {e}\n")
            failures.append(filename)

    print()
    if failures:
        print(f"FAILED: {len(failures)} schema(s) could not be refreshed: {failures}")
        return 1
    print("All schemas refreshed. Review the diff and re-run --check:")
    print("  git diff agentic-coding/transpiler/schemas/")
    print("  uv run --project agentic-coding/transpiler transpile --check")
    return 0


if __name__ == "__main__":
    sys.exit(main())
