# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every bounded read of a tool's log goes through one helper, package-wide.

The failure this pins
---------------------
Three sites each grew their own bounded read of a tool's stderr log, and
each re-created the same leak independently: a value split at the read's
edge survives whole-spelling redaction, so every raw read needs the bound
plus one byte (a KNOWN cut), the edge trim, and -- for a message excerpt --
redaction before the cut and a continuation marker naming the log. The
helpers own that pipeline: ``plugin_base.read_log_bounded`` returns bounded
text, and ``plugin_base.log_says`` answers a phrase question without
returning text at all. A raw ``read_bytes_at_most`` call, or a raw sized
``.read(n)``, anywhere else in the package is a fourth copy waiting to
leak. An earlier revision of this guard walked only the three base modules
that had leaked; a raw read added to any other module passed it, so the
walk now covers every module in the package.

Scope, stated precisely: this guard walks the AST of every ``*.py`` under
``automated_security_helper/`` and fails on

* any call of ``read_bytes_at_most`` outside an allowlisted function, and
* any ``.read(...)`` or ``.readline(...)`` call WITH a size argument --
  positional or keyword -- outside an allowlisted function (a bare
  ``.read()`` is a whole-file read with no edge to split a value at, a
  bare ``.readline()`` ends at a line break, and both are left to review;
  a SIZED readline cuts mid-line exactly as a sized read does).

The allowlist below names each reviewed site as (module, enclosing
function) with a one-line reason, where the function is the dotted stack
of class and def names; a new raw read fails until its site is reviewed
and added here with its reason. The guard does NOT see dynamic access
(``getattr(fs_guard, name)``), aliased imports of the function object, or
reads outside the package; those stay the review's to catch.

The other half of the pipeline -- redact-before-cut at sites that slice
text they already hold -- cannot be told apart from an ordinary slice by
shape, so it stays review-by-reading. The reviewed slice sites, named by
their enclosing functions so the list survives edits around them:
``utils/pre_installed_tool.py`` (``_verify``'s probe-output excerpt and
``_first_cause``'s redact-then-unwrap of uv's clause),
``plugin_modules/ash_builtin/scanners/npm_audit_scanner.py``
(``_audit_failure``'s stderr-line cuts, ``_yarn_error_detail``'s per-line
and whole-detail cuts, ``_parse_yarn_audit``'s problems fallback, and
``NpmAuditScanner.scan``'s yarn version-probe excerpt, redacted then cut),
``utils/content_db_staleness.py`` (``_run_json``'s and
``_built_from_grype``'s record-text cuts), ``base/uv_tool_mixin.py``
(``_explain_offline_resolve_failure``'s excerpt cuts), and
``base/scanner_plugin.py`` (``_describe_scan_failure``'s stderr excerpt at
_STDERR_EXCERPT_LIMIT). A new slice of tool text belongs in
``shown_excerpt``/``shown_tool_stderr`` rather than on that list.
"""

import ast
import re
from pathlib import Path

import pytest

import automated_security_helper

pytestmark = pytest.mark.unit

_PACKAGE_DIR = Path(automated_security_helper.__file__).parent

# Reviewed callers of read_bytes_at_most. Everything else must use
# read_log_bounded (text) or log_says (verdict).
_ALLOWED_HELPER_CALLS = {
    (
        "base/plugin_base.py",
        "read_log_bounded",
    ): "the sanctioned log pipeline itself: bound+1, edge trim, marker",
    (
        "base/scanner_plugin.py",
        "_error_notifications",
    ): "bounded+1 read of the tool's SARIF results file for its error-level "
    "notification texts, dropped whole over the cap; what is shown of them is "
    "redacted with the run's values before the excerpt cut",
    (
        "base/scanner_plugin.py",
        "ScannerPluginBase._read_results_file",
    ): "bounded+1 read of the tool's results file for grading, refused over "
    "the cap and parsed as JSON; structured results, no text shown",
    (
        "plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py",
        "DetectSecretsScanner._scan_in_worker",
    ): "bounded+1 read of the worker's findings JSON, refused over the cap; "
    "structured results, not log text",
    (
        "plugin_modules/ash_builtin/scanners/zizmor_scanner.py",
        "_declares_a_github_action",
    ): "the head of an action metadata file at _ACTION_PROBE_LIMIT + 1, parsed "
    "for an action declaration; operator input, not tool output (listed under "
    "both shapes so the sized-read and guarded-read spellings are each reviewed)",
}

# Reviewed sized .read(n) sites. Each reads bytes that are hashed, copied,
# counted or parsed -- not tool-output text shown to anyone -- or is one of
# the two sanctioned readers' own bodies.
_ALLOWED_SIZED_READS = {
    (
        "assets/install-pinned-tool.py",
        "download",
    ): "chunked download into a hash and a file; network bytes, never shown",
    ("assets/install-pinned-tool.py", "_sha256_file"): "whole-file hash in chunks",
    ("assets/install-pinned-tool.py", "_sha256_of"): "whole-file hash in chunks",
    (
        "assets/install-pinned-tool.py",
        "install_bundle",
    ): "chunked copy of each bundle member into staging while hashing, under "
    "the member and total byte caps; archive bytes written and digested, "
    "never shown",
    (
        "base/plugin_base.py",
        "log_says",
    ): "the verdict-only reader: returns a bool, no text leaves it",
    (
        "cli/inspect/inspect_findings_app.py",
        "_offset_of_line",
    ): "byte-offset seek under its own byte budget; bytes counted, not shown",
    (
        "cli/inspect/inspect_findings_app.py",
        "_read_lines",
    ): "chunked readline of the operator's own source file for display, "
    "under the source-read budget; only each line's head is kept, cut at "
    "SNIPPET_LINE_CHARS + 1 characters",
    (
        "cli/inspect/inspect_findings_app.py",
        "_read_chunk",
    ): "the chunk reader behind _offset_of_line and _read_lines, under the "
    "caller's byte budget; bytes counted or cut per line, not shown",
    (
        "cli/mcp/__init__.py",
        "_read_bounded",
    ): "the --auth-header-value-file descriptor read in a loop capped at "
    "_AUTH_VALUE_MAX_BYTES + 1, refused over the cap by its caller; a "
    "credential value, never shown",
    (
        "cli/mcp/progress_monitor.py",
        "_read_scanner_severity",
    ): "ASH's own scan-results JSON on a regular-file descriptor opened without "
    "following links, _MAX_SCANNER_RESULTS_BYTES + 1, refused over the cap; "
    "parsed, not shown",
    (
        "cli/mcp/source_delivery.py",
        "_finalize_zip_upload",
    ): "sha chunks over the operator's own uploaded archive, and the name "
    "of a refused symlink target from it; not tool output (the work behind "
    "set_source_zip_finalize, whose own body holds no read)",
    (
        "cli/scan.py",
        "_marker_head",
    ): "a 64 KiB head of an output-directory file compared with the ASH marker "
    "shapes; bytes compared, not shown",
    (
        "config/client_scanner_exclusions.py",
        "_trivy_ignore_exclusions",
    ): "the project's trivy ignore file at _MAX_IGNORE_FILE_BYTES + 1, refused "
    "over the cap; operator config, not tool output",
    (
        "config/config_sources.py",
        "read_opened_config_bytes",
    ): "the operator's config file in 1 MiB chunks, the total bounded by "
    "ASH_CONFIG_MAX_FILE_BYTES + 1 and refused over it",
    (
        "config/config_sources.py",
        "read_config_bytes",
    ): "the operator's config file in 1 MiB chunks, the total bounded by "
    "ASH_CONFIG_MAX_FILE_BYTES + 1 and refused over it",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_zip_directory_start",
    ): "4-byte zip signature reads at computed offsets; bytes compared, not shown",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_zip_has_more_entries_than",
    ): "46-byte central-directory headers, the walk bounded by the declared "
    "directory size; entries counted, not shown",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_BoundedTarStream.block_at",
    ): "one 512-byte tar block at an offset; parsed as a header, not shown",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_BoundedTarStream.read",
    ): "the bounded tar stream's own read: the size is capped by _TAR_READ_CAP "
    "and charged to the header allowance",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_GzipMembersStream.seek",
    ): "a forward seek that reads at most _COPY_CHUNK at a time through the "
    "stream's own bounded read; bytes discarded, not shown",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_GzipMembersStream._fill",
    ): "64 KiB compressed chunks fed to the decompressor",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_tar_stream",
    ): "one 512-byte block to recognize a tar header",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_gzip_holds_a_tar",
    ): "one 512-byte block of the decompressed head, compared with the tar "
    "header shape",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_holds_a_tar",
    ): "one 512-byte block of the decompressed head, compared with the tar "
    "header shape",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "_copy_at_most",
    ): "chunked copy bounded by the extraction limit it is given",
    (
        "plugin_modules/ash_builtin/converters/archive_converter.py",
        "ArchiveConverter.convert",
    ): "an _LFS_POINTER_MAX_BYTES head of a member to recognize a git-lfs "
    "pointer; bytes compared, not shown",
    (
        "plugin_modules/ash_builtin/converters/jupyter_converter.py",
        "JupyterConverter._would_hand_to_nbconvert",
    ): "the notebook at _NOTEBOOK_MAX_BYTES + 1, refused over the cap and parsed "
    "to decide the hand-off; source input, not tool output",
    (
        "plugin_modules/ash_builtin/converters/jupyter_converter.py",
        "JupyterConverter.convert",
    ): "the same notebook read before conversion, refused over the cap",
    (
        "plugin_modules/ash_builtin/scanners/cfn_guard_scanner.py",
        "CfnGuardScanner._read_rule",
    ): "one operator rules file through open_in_scanned_tree, bound+1, "
    "RulesBundleUnavailable over the cap; operator input, not tool output",
    (
        "plugin_modules/ash_builtin/scanners/gitleaks_scanner.py",
        "GitleaksScanner._read_tree_ignore_file",
    ): "the tree's .gitleaksignore at MAX_IGNORE_FILE_BYTES + 1, raised over the "
    "cap; operator input, not tool output",
    (
        "plugin_modules/ash_builtin/scanners/zizmor_scanner.py",
        "_declares_a_github_action",
    ): "the head of an action metadata file at _ACTION_PROBE_LIMIT, parsed for "
    "an action declaration; operator input, not tool output",
    (
        "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
        "_copy_stream",
    ): "chunked copy of source files into the staging tree",
    (
        "plugin_modules/ash_snyk_plugins/snyk_code_scanner.py",
        "_excludes",
    ): "a tree exclusion file through open_in_scanned_tree at "
    "_MAX_EXCLUSION_FILE_BYTES + 1; over the cap counts as an exclusion; "
    "operator input, not tool output",
    (
        "utils/cdk_nag_worker.py",
        "_read_response",
    ): "bounded+1 read of the worker's structured response in chunks; the "
    "complete lines inside the cap are kept and parsed as JSON lines, the "
    "line that crosses it and everything after are dropped",
    ("utils/download_utils.py", "sha256_file"): "whole-file hash in chunks",
    (
        "utils/download_utils.py",
        "_replace_atomically",
    ): "chunked copy-and-hash into a staging file",
    (
        "utils/download_utils.py",
        "_extract_single_member._stage",
    ): "chunked copy-and-hash of one archive member",
    (
        "utils/download_utils.py",
        "_copy_whole_body",
    ): "chunked copy of a download's body into a hash and a file; network "
    "bytes, never shown",
    (
        "utils/download_utils.py",
        "_sha256_of_open_file",
    ): "whole-file hash in chunks over an open descriptor",
    (
        "utils/download_utils.py",
        "_restore_cached_asset",
    ): "chunked copy-and-hash of a cache entry back into place",
    (
        "utils/inner_run_outcome.py",
        "read_refusal_outcome",
    ): "ASH's own inner-run outcome JSON on a regular-file descriptor opened "
    "without following links, _MAX_OUTCOME_BYTES + 1, refused over the cap; "
    "parsed, not tool text",
    (
        "utils/pre_installed_tool.py",
        "_read_head",
    ): "bounded head of a wrapper script for interpreter detection; what is "
    "shown of the probe's output goes through _verify's reviewed excerpt",
    (
        "utils/pre_installed_tool.py",
        "find_tool_interpreter",
    ): "shebang line of the probed copy, parsed for an interpreter name; "
    "not tool output",
    (
        "utils/rules_bundles.py",
        "extract_bundle",
    ): "chunked copy of each bundle member into place; archive bytes written, "
    "never shown",
    (
        "utils/sandbox/policy.py",
        "_shebang_interpreter",
    ): "shebang line of a script, parsed for the interpreter it names; not tool output",
    (
        "utils/sandbox/fs_guard.py",
        "read_bytes_at_most",
    ): "the bounded-read primitive's own chunk loop",
    (
        "utils/scan_source.py",
        "_gitfile_shaped",
    ): "fixed-length magic-prefix compare; bytes compared, not shown",
    (
        "utils/scan_source.py",
        "_read_gitdir_record",
    ): "bounded+1 read of a gitdir record, refused over the cap",
    (
        "workspace/aggregation.py",
        "stamp_run_record",
    ): "ASH's own aggregated-results header line, read back in bounded pieces "
    "from the file ASH wrote one write() earlier, to copy it into the atomic "
    "rewrite; never a tool log",
    (
        "workspace/aggregation.py",
        "rewrite_workspace_block",
    ): "ASH's own aggregated-results file, read in bounded pieces to find and "
    "drop the old workspace block before the replacement is written; never a "
    "tool log",
}


def _raw_read_sites(root, allowed_helper_calls, allowed_sized_reads):
    """Walk every module under root and return the unreviewed read sites.

    A site is named ``<relpath>:<line> (<kind> in <function>)``. The
    enclosing function is the dotted stack of class and def names (lambdas
    inside a def belong to that def), so a method named like a reviewed
    module-level function is a different site; module-level code has the
    function name ``<module>``, which no allowlist entry uses. A read is
    sized whether the size is positional or a keyword, and a sized
    ``readline`` counts the same as a sized ``read``: both cut at the size,
    where a value can split.
    """
    sites = []
    for path in sorted(root.rglob("*.py")):
        relpath = path.relative_to(root).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        stack = []

        class _Walker(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                stack.append(node.name)
                self.generic_visit(node)
                stack.pop()

            visit_AsyncFunctionDef = visit_FunctionDef
            visit_ClassDef = visit_FunctionDef

            def visit_Call(self, node):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                where = (relpath, ".".join(stack) or "<module>")
                sized = bool(node.args or node.keywords)
                if name == "read_bytes_at_most":
                    if where not in allowed_helper_calls:
                        sites.append(
                            f"{relpath}:{node.lineno} "
                            f"(read_bytes_at_most in {where[1]})"
                        )
                elif name in ("read", "readline") and sized:
                    if where not in allowed_sized_reads:
                        sites.append(
                            f"{relpath}:{node.lineno} (sized .{name} in {where[1]})"
                        )
                self.generic_visit(node)

        _Walker().visit(tree)
    return sites


def _write_module(root, relpath, text):
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_every_bounded_log_read_in_the_package_is_a_reviewed_site():
    stray = _raw_read_sites(_PACKAGE_DIR, _ALLOWED_HELPER_CALLS, _ALLOWED_SIZED_READS)
    assert stray == [], (
        "raw bounded read outside the reviewed sites -- route tool-log text "
        "through read_log_bounded or log_says (bound+1, edge trim, marker), "
        "or review the site and add it to this guard's allowlist with its "
        f"reason: {stray}"
    )


def test_every_allowlist_key_names_a_live_read_site():
    """A key whose site was removed or renamed is a review nobody can check:
    the walker never visits it, the package-wide cell stays green, and the
    stale entry would silently cover a NEW read added under the old name.
    Every key must match a read site the walker actually finds today."""
    found = {
        (relpath, function)
        for relpath, function in (
            re.match(
                r"(.+?):\d+ \((?:read_bytes_at_most|sized \.(?:read|readline))"
                r" in (.+)\)$",
                site,
            ).groups()
            for site in _raw_read_sites(_PACKAGE_DIR, {}, {})
        )
    }
    stale = sorted(
        key
        for key in {**_ALLOWED_HELPER_CALLS, **_ALLOWED_SIZED_READS}
        if key not in found
    )
    assert stale == [], (
        "allowlist keys that name no read site in the package -- remove the "
        f"entry or re-point it at the live site: {stale}"
    )


def test_a_raw_helper_call_in_any_module_is_caught(tmp_path):
    _write_module(
        tmp_path,
        "utils/freshly_added.py",
        "def collect(path):\n    return read_bytes_at_most(path, 4096)\n",
    )
    sites = _raw_read_sites(tmp_path, {}, {})
    assert sites == ["utils/freshly_added.py:2 (read_bytes_at_most in collect)"]


def test_a_raw_sized_read_in_any_module_is_caught(tmp_path):
    _write_module(
        tmp_path,
        "plugin_modules/other/reader.py",
        "def peek(handle):\n    return handle.read(65536)\n",
    )
    sites = _raw_read_sites(tmp_path, {}, {})
    assert sites == ["plugin_modules/other/reader.py:2 (sized .read in peek)"]


def test_an_allowlisted_site_passes_and_its_neighbor_does_not(tmp_path):
    _write_module(
        tmp_path,
        "utils/hashing.py",
        "def hasher(handle):\n"
        "    return handle.read(1024)\n"
        "\n"
        "def shower(handle):\n"
        "    return handle.read(1024)\n",
    )
    allowed = {("utils/hashing.py", "hasher"): "chunked hash, reviewed"}
    sites = _raw_read_sites(tmp_path, {}, allowed)
    assert sites == ["utils/hashing.py:5 (sized .read in shower)"]


def test_a_bare_read_and_a_lambda_inside_a_reviewed_def_pass(tmp_path):
    _write_module(
        tmp_path,
        "utils/edges.py",
        "def whole(handle):\n"
        "    return handle.read()\n"
        "\n"
        "def whole_line(handle):\n"
        "    return handle.readline()\n"
        "\n"
        "def chunked(handle):\n"
        "    return iter(lambda: handle.read(4096), b'')\n",
    )
    allowed = {("utils/edges.py", "chunked"): "chunk loop, reviewed"}
    assert _raw_read_sites(tmp_path, {}, allowed) == []


def test_a_class_method_named_like_a_reviewed_function_is_caught(tmp_path):
    """The allowlist names an enclosing FUNCTION; a method of the same name
    inside a class is a different site, and a walker that ignores class
    names hands the method the function's review for free."""
    _write_module(
        tmp_path,
        "utils/hashing.py",
        "def hasher(handle):\n"
        "    return handle.read(1024)\n"
        "\n"
        "class Reader:\n"
        "    def hasher(self, handle):\n"
        "        return handle.read(1024)\n",
    )
    allowed = {("utils/hashing.py", "hasher"): "chunked hash, reviewed"}
    sites = _raw_read_sites(tmp_path, {}, allowed)
    assert sites == ["utils/hashing.py:6 (sized .read in Reader.hasher)"]


def test_a_keyword_sized_read_is_caught(tmp_path):
    """``handle.read(size=n)`` is the same bounded read as ``read(n)``; a
    guard that looks only at positional arguments misses it."""
    _write_module(
        tmp_path,
        "plugin_modules/other/kwreader.py",
        "def peek(handle):\n    return handle.read(size=65536)\n",
    )
    sites = _raw_read_sites(tmp_path, {}, {})
    assert sites == ["plugin_modules/other/kwreader.py:2 (sized .read in peek)"]


def test_a_sized_readline_is_caught(tmp_path):
    """``readline(n)`` cuts mid-line at the size, the same edge a sized
    ``read`` has; a bare ``readline()`` ends at a line break and stays
    review's. Both positional and keyword sizes count."""
    _write_module(
        tmp_path,
        "plugin_modules/other/linereader.py",
        "def head(handle):\n"
        "    return handle.readline(4096)\n"
        "\n"
        "def head_kw(handle):\n"
        "    return handle.readline(size=4096)\n",
    )
    sites = _raw_read_sites(tmp_path, {}, {})
    assert sites == [
        "plugin_modules/other/linereader.py:2 (sized .readline in head)",
        "plugin_modules/other/linereader.py:5 (sized .readline in head_kw)",
    ]
