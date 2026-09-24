#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Source delivery for the MCP server.

Two delivery channels are supported:

1. ``set_source_git`` — clone a remote repository (optionally at a specific
   ref) into a per-session workspace via ``git clone --depth``. SSH keys are
   resolved from a server-side keyring identifier; raw private keys are never
   accepted over the wire.
2. ``set_source_zip_chunk`` + ``set_source_zip_finalize`` — accept a zipped
   source tree as base64-encoded chunks (≤ 1 MiB each), reassemble in a
   per-session ``incoming/`` directory, verify a sha256 checksum at finalize
   time, and extract under the session workspace after rejecting any
   path-traversal entries (absolute paths, ``..`` components, symlinks
   pointing outside the workspace). Extraction builds a staging sibling and
   renames it over ``source/`` only once it has succeeded, so a re-delivery that
   is refused leaves the previously delivered tree in place.

Both the ``session_id`` and the ``upload_id`` arriving over the protocol have to
name exactly one path component, and that is enforced by the one validator in
``session_identity`` rather than re-derived per call site. Every path built from
an ``upload_id`` goes through :func:`_upload_path`; every path built from a
``session_id`` goes through :func:`_session_workspace`.

Hard limits guard against pathological inputs:

* ``_MAX_ZIP_BYTES``       — total finalized zip size (default 100 MiB)
* ``_MAX_EXTRACTED_BYTES`` — total uncompressed size after extraction (default 500 MiB)
* ``_MAX_FILES``           — total entry count in the zip (default 50 000)

Workspace root resolution order:

1. ``ASH_MCP_WORKSPACE_ROOT`` environment variable
2. ``$XDG_CACHE_HOME/ash-mcp/``
3. ``~/.cache/ash-mcp/``

Each session lives under ``<workspace_root>/<session_id>/``. ``clear_source``
recursively removes that directory.

The session ↔ source_dir binding is persisted in a process-local registry
(``_SESSION_SOURCE_DIRS``); when the larger session-state class lands
(Track 10.3 / cascade-73), this dict is meant to be replaced by an attribute
on the per-session object.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess  # nosec B404 - git is invoked as a subprocess; see _validate_clone_url
import zipfile
from pathlib import Path
from typing import Dict, Optional

from automated_security_helper.cli.mcp.session_identity import (
    validate_path_component,
)
from automated_security_helper.utils.path_containment import (
    validate_contained_path,
)

# ---------------------------------------------------------------------------
# Hard limits — enforced at finalize time.
# ---------------------------------------------------------------------------

_MAX_ZIP_BYTES: int = 100 * 1024 * 1024  # 100 MiB on-disk zip
_MAX_EXTRACTED_BYTES: int = 500 * 1024 * 1024  # 500 MiB uncompressed
_MAX_FILES: int = 50_000  # entry count
_MAX_CHUNK_BYTES: int = 1 * 1024 * 1024  # 1 MiB per chunked b64 upload (decoded)

# Extraction builds here and is renamed onto "source" only once it has
# succeeded, so a refused re-delivery cannot destroy the tree it failed to
# replace. A sibling of "source" rather than a subdirectory of it, so the rename
# is within one directory and therefore atomic.
_STAGING_DIR_NAME = ".source.incoming"

# ZipInfo external_attr bits for a symlink (S_IFLNK == 0xA000) shifted into
# the high half of external_attr.
_S_IFLNK_SHIFTED = 0xA000 << 16
_S_IFMT_SHIFTED = 0xF000 << 16


# ---------------------------------------------------------------------------
# Per-process session → source_dir registry.
#
# Track 10.3 (cascade-73) is expected to land an MCPSession class; when that
# happens, this dict should move onto that object as ``session.source_dir``.
# Until then, we keep a process-local mapping keyed by session id.
# ---------------------------------------------------------------------------

_SESSION_SOURCE_DIRS: Dict[str, Path] = {}


def get_session_source_dir(session_id: str) -> Optional[Path]:
    """Return the recorded ``source_dir`` for ``session_id``, or ``None``."""

    return _SESSION_SOURCE_DIRS.get(session_id)


def delivered_session_count() -> int:
    """Return how many sessions currently have a recorded ``source_dir``.

    Deliberately a count and not the ids. The one caller is a diagnostic that
    needs to distinguish "nobody has delivered anything" from "somebody
    delivered, but not the session asking" -- the second being the signature of
    a caller whose session id is not stable between calls. Returning the ids
    would tell one tenant that another exists and what it is called, which the
    diagnostic does not need.
    """

    return len(_SESSION_SOURCE_DIRS)


def _set_session_source_dir(session_id: str, source_dir: Path) -> None:
    _SESSION_SOURCE_DIRS[session_id] = source_dir


def _drop_session_source_dir(session_id: str) -> None:
    _SESSION_SOURCE_DIRS.pop(session_id, None)


# ---------------------------------------------------------------------------
# Workspace root + per-session workspace resolution.
# ---------------------------------------------------------------------------


def resolve_workspace_root() -> Path:
    """Resolve the configured MCP workspace root.

    Resolution order:

    1. ``$ASH_MCP_WORKSPACE_ROOT``
    2. ``$XDG_CACHE_HOME/ash-mcp/``
    3. ``~/.cache/ash-mcp/``
    """

    env_root = os.environ.get("ASH_MCP_WORKSPACE_ROOT")
    if env_root:
        return Path(env_root).expanduser()

    xdg = os.environ.get("XDG_CACHE_HOME")
    if xdg:
        return Path(xdg).expanduser() / "ash-mcp"

    return Path.home() / ".cache" / "ash-mcp"


def _session_workspace(workspace_root: Path, session_id: str) -> Path:
    """Return the per-session workspace path under ``workspace_root``.

    The session id is treated as opaque and has to name exactly one directory:
    that keeps the session sandbox flat and stops a caller escaping into a
    sibling session's workspace with ``../<other-session>``.

    The rule is :func:`validate_path_component`, shared with the transport
    boundary rather than re-derived here. This function used to re-implement
    three of its predicates and was the weaker copy -- it missed the length cap,
    control characters, and the drive specifier that made ``clear_source('C:')``
    remove every session's workspace on Windows. It is a boundary in its own
    right, not merely a second opinion: the ``mcp_tools`` wrappers take
    ``session_id`` as an argument, so a caller can reach here without having gone
    through ``resolve_session_id``.

    Raises:
        ValueError: if ``session_id`` does not name a single path component.
    """

    validate_path_component(session_id, "session_id")
    session_dir = workspace_root / session_id
    # Post-condition on the join rather than a second check on the id: no value
    # the validator accepts can collapse it, which the tests assert directly
    # against both POSIX and Windows path semantics. It stays because the
    # collapse is silent -- on Windows the join returns the workspace root
    # itself, and the caller goes on to rmtree it -- so a later widening of the
    # charset must not be able to reintroduce that quietly. No test can redden
    # this branch while the validator runs first, which is the point.
    if session_dir.parent != workspace_root:
        raise ValueError(
            f"session_id does not name a directory inside the workspace root: "
            f"{session_id!r} joined onto {str(workspace_root)!r} yields "
            f"{str(session_dir)!r}"
        )
    return session_dir


def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


# ---------------------------------------------------------------------------
# SSH key resolution (placeholder).
# ---------------------------------------------------------------------------


def _resolve_ssh_key(ssh_key_id: Optional[str]) -> Optional[Path]:
    """Resolve an ``ssh_key_id`` to a key file on disk.

    The actual server-side keyring backend is out of scope for this track —
    cascade-73 / a future security-track will own the real implementation.
    For now this function returns ``None`` for any input, which causes the
    git clone to fall back to whatever credentials the host process already
    has access to (e.g. an agent-forwarded SSH key, or none).

    Raw private-key material must never be accepted over the wire; only the
    opaque identifier is accepted, by design.
    """

    if ssh_key_id is None:
        return None
    # TODO(track-10.x security): wire this up to the real keyring backend.
    return None


# ---------------------------------------------------------------------------
# git-ref delivery.
# ---------------------------------------------------------------------------

# git reads any argument beginning with "-" as an option, so passing a
# caller-supplied url or ref straight to the command line is an
# argument-injection sink and not merely a shell-injection one. Building argv as
# a list stops the *shell* from re-parsing the value; it does nothing to stop
# git from treating it as a flag. Two concrete escalations:
#
#   url = "--upload-pack=<cmd>"   -> git executes <cmd>
#   url = "ext::sh -c <cmd>"      -> the ext:: transport executes <cmd>
#
# These values arrive over MCP from a remote client, so they are untrusted by
# construction. This repository has already been bitten by this class of bug
# once (see the GitPython argument-injection dependency patches), so the guards
# below reject the option-like shape outright rather than trying to escape it.
_DANGEROUS_URL_PREFIXES = ("ext::",)


def _reject_option_like(value: str, what: str) -> str:
    """Reject a caller-supplied git argument that git would parse as an option.

    Args:
        value: The caller-supplied value.
        what: Name of the parameter, used in the error message.

    Returns:
        ``value`` unchanged when it is safe to pass as a positional argument.

    Raises:
        ValueError: if ``value`` begins with ``-``.
    """

    if value.startswith("-"):
        raise ValueError(
            f"{what} must not begin with '-': git would parse "
            f"{value!r} as an option rather than a value"
        )
    return value


def _validate_clone_url(url: str) -> str:
    """Reject clone URLs that let git execute an arbitrary command.

    Args:
        url: The caller-supplied remote URL.

    Returns:
        ``url`` unchanged when it is safe to clone from.

    Raises:
        ValueError: if ``url`` is option-like or uses a command-executing
            transport.
    """

    _reject_option_like(url, "url")
    lowered = url.lower()
    for prefix in _DANGEROUS_URL_PREFIXES:
        if lowered.startswith(prefix):
            raise ValueError(
                f"refusing url with {prefix!r} transport: it instructs git to "
                f"execute an arbitrary command"
            )
    return url


def set_source_git(
    url: str,
    ref: Optional[str] = None,
    *,
    ssh_key_id: Optional[str] = None,
    depth: int = 1,
    workspace_root: Optional[Path] = None,
    session_id: str,
) -> Path:
    """Clone ``url`` (optionally at ``ref``) into the session workspace.

    Args:
        url: Remote URL to clone (https or ssh).
        ref: Optional branch/tag/commit to check out. When ``None``, the
            remote default branch is used.
        ssh_key_id: Opaque identifier resolved server-side via
            :func:`_resolve_ssh_key`. Raw private keys are not accepted.
        depth: Shallow-clone depth. Defaults to 1 (latest commit only).
        workspace_root: Override workspace root; defaults to
            :func:`resolve_workspace_root`.
        session_id: MCP session identifier used to scope the clone.

    Returns:
        The absolute path of the cloned working tree.

    Raises:
        ValueError: if ``session_id`` is invalid, or if ``url``/``ref`` is
            option-like or uses a command-executing git transport.
        RuntimeError: if ``git clone`` (or the optional ``git checkout``
            for an explicit ref) fails.
    """

    # Validate before touching the filesystem so a rejected request leaves no
    # session directory behind.
    url = _validate_clone_url(url)
    if ref:
        ref = _reject_option_like(ref, "ref")

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = _ensure_dir(_session_workspace(root, session_id))

    # Wipe any previous source for this session before cloning a fresh one;
    # callers are expected to call clear_source explicitly, but cloning over
    # an existing tree is a footgun we'd rather avoid.
    target = session_dir / "source"
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)
    _ensure_dir(target)

    env = os.environ.copy()
    key_path = _resolve_ssh_key(ssh_key_id)
    if key_path is not None:
        env["GIT_SSH_COMMAND"] = (
            f"ssh -i {str(key_path)} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
        )

    cmd = [
        "git",
        "clone",
        "--depth",
        str(int(depth)),
        # End-of-options marker, so even a future change that loosens
        # _validate_clone_url cannot turn the url into a git flag.
        "--",
        url,
        str(target),
    ]
    result = subprocess.run(  # nosec B603 - list-form argv, literal "git" executable, url validated by _validate_clone_url and fenced behind "--"
        cmd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        shutil.rmtree(target, ignore_errors=True)
        raise RuntimeError(
            f"git clone failed (exit {result.returncode}): {result.stderr.strip() or result.stdout.strip()}"
        )

    if ref:
        # ``--depth 1`` may not have fetched the requested ref. Fetch it
        # explicitly before checking out so non-default refs work reliably.
        fetch_cmd = [
            "git",
            "-C",
            str(target),
            "fetch",
            "--depth",
            str(int(depth)),
            "origin",
            ref,
        ]
        fetch_res = subprocess.run(  # nosec B603 - list-form argv, literal "git" executable, ref validated by _reject_option_like
            fetch_cmd, capture_output=True, text=True, env=env, check=False
        )
        if fetch_res.returncode != 0:
            # Not all refs need an explicit fetch (e.g. a tag already in the
            # initial clone). Don't fail here; let checkout produce the
            # diagnostic.
            pass

        checkout_cmd = ["git", "-C", str(target), "checkout", "--detach", ref]
        co_res = subprocess.run(  # nosec B603 - list-form argv, literal "git" executable, ref validated by _reject_option_like
            checkout_cmd, capture_output=True, text=True, env=env, check=False
        )
        if co_res.returncode != 0:
            shutil.rmtree(target, ignore_errors=True)
            raise RuntimeError(
                f"git checkout {ref!r} failed (exit {co_res.returncode}): "
                f"{co_res.stderr.strip() or co_res.stdout.strip()}"
            )

    _set_session_source_dir(session_id, target)
    return target


# ---------------------------------------------------------------------------
# Chunked zip upload.
# ---------------------------------------------------------------------------


def _incoming_dir(session_dir: Path) -> Path:
    return _ensure_dir(session_dir / "incoming")


def _upload_path(session_dir: Path, upload_id: str, suffix: str) -> Path:
    """Build the one path in this session's ``incoming/`` naming this upload.

    Every upload path is built here so that the validation cannot be attached to
    one builder and missed by the others. That is exactly what had happened:
    ``_part_path`` carried the only check and has a single caller, on the chunk
    path, while ``set_source_zip_finalize`` built through ``_final_zip_path`` and
    reached ``stat()``, ``read()`` and ``unlink()`` on an unvalidated path. An
    absolute ``upload_id`` left no trace of the workspace root in the result --
    ``Path('<incoming>') / '/etc/cron.d/x.zip'`` is ``/etc/cron.d/x.zip`` -- and
    the function's only precondition is that the file exists, which an attacker
    satisfies by naming a file that already does.

    Two separate guards, because neither implies the other:

    * ``upload_id`` must name one path component, which is what stops the
      traversal and the absolute path from being built at all.
    * the built path must be contained in ``incoming/`` and must not itself be a
      symlink. Containment is the assertion that holds even if the component rule
      is later loosened, and the symlink half is not a containment question: a
      link inside ``incoming/`` is contained, and following it would hash and
      then unlink whatever it points at. This is the same call the zip member
      handling makes for symlink entries.

    The unresolved join is returned rather than the canonical path the check
    produced, so the file this names is byte-identical to what the previous
    implementation named; the check is a gate, not a rewrite.

    Raises:
        ValueError: if ``upload_id`` does not name a single path component, or if
            the built path is not a non-symlink inside ``incoming/``.
    """

    validate_path_component(upload_id, "upload_id")

    name = f"{upload_id}{suffix}"
    incoming = _incoming_dir(session_dir)
    result = validate_contained_path(name, incoming.resolve())
    if result.error is not None:
        raise ValueError(
            f"upload_id {upload_id!r} does not name a file inside the session's "
            f"incoming directory: {result.error.message}"
        )
    return incoming / name


def _part_path(session_dir: Path, upload_id: str) -> Path:
    return _upload_path(session_dir, upload_id, ".zip.part")


def _meta_path(session_dir: Path, upload_id: str) -> Path:
    return _upload_path(session_dir, upload_id, ".next")


def _final_zip_path(session_dir: Path, upload_id: str) -> Path:
    return _upload_path(session_dir, upload_id, ".zip")


def _read_next_sequence(session_dir: Path, upload_id: str) -> int:
    meta = _meta_path(session_dir, upload_id)
    if not meta.exists():
        return 0
    try:
        return int(meta.read_text().strip() or "0")
    except ValueError:
        return 0


def _write_next_sequence(session_dir: Path, upload_id: str, value: int) -> None:
    _meta_path(session_dir, upload_id).write_text(str(value))


def set_source_zip_chunk(
    upload_id: str,
    sequence: int,
    data_b64: str,
    last: bool,
    *,
    workspace_root: Optional[Path] = None,
    session_id: str,
) -> Dict[str, object]:
    """Append a base64-encoded chunk to an in-flight zip upload.

    Args:
        upload_id: Caller-chosen identifier scoping a single upload.
        sequence: Zero-based sequence number; chunks must arrive in order.
        data_b64: Base64-encoded chunk payload (≤ 1 MiB decoded).
        last: ``True`` on the final chunk; subsequent chunks for the same
            ``upload_id`` are rejected.
        workspace_root: Override workspace root.
        session_id: MCP session identifier used to scope the upload.

    Returns:
        ``{"received": <bytes-so-far>, "next_sequence": <int>, "last": <bool>}``

    Raises:
        ValueError: on out-of-order sequence, oversize chunk, malformed b64
            payload, or duplicate ``last=True``.
    """

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = _ensure_dir(_session_workspace(root, session_id))
    part = _part_path(session_dir, upload_id)
    _ensure_dir(part.parent)

    expected = _read_next_sequence(session_dir, upload_id)
    if sequence != expected:
        raise ValueError(
            f"out-of-order chunk: expected sequence {expected}, got {sequence}"
        )

    try:
        decoded = base64.b64decode(data_b64, validate=True)
    except Exception as exc:  # noqa: BLE001 — re-raise as a typed error
        raise ValueError(f"invalid base64 payload: {exc}") from exc

    if len(decoded) > _MAX_CHUNK_BYTES:
        raise ValueError(f"chunk too large: {len(decoded)} > {_MAX_CHUNK_BYTES} bytes")

    # Append. Open in "ab" so successive chunks accumulate.
    with part.open("ab") as f:
        f.write(decoded)

    new_total = part.stat().st_size
    if new_total > _MAX_ZIP_BYTES:
        # Refuse to keep growing past the hard cap.
        part.unlink(missing_ok=True)
        _meta_path(session_dir, upload_id).unlink(missing_ok=True)
        raise ValueError(
            f"upload exceeds max zip size {_MAX_ZIP_BYTES} bytes (got {new_total})"
        )

    next_seq = sequence + 1
    if last:
        # Promote the .part to .zip; finalize() will verify checksum and
        # extract.
        final = _final_zip_path(session_dir, upload_id)
        if final.exists():
            final.unlink()
        part.rename(final)
        _meta_path(session_dir, upload_id).unlink(missing_ok=True)
    else:
        _write_next_sequence(session_dir, upload_id, next_seq)

    return {"received": new_total, "next_sequence": next_seq, "last": bool(last)}


# ---------------------------------------------------------------------------
# Zip finalize + safe extraction.
# ---------------------------------------------------------------------------


def _is_symlink_zipinfo(info: zipfile.ZipInfo) -> bool:
    """Detect symlink entries via Unix mode bits in ``external_attr``.

    Zip stores Unix file mode in the high half of ``external_attr``. A
    symlink has S_IFMT == S_IFLNK (0xA000).
    """

    return (info.external_attr & _S_IFMT_SHIFTED) == _S_IFLNK_SHIFTED


def _validate_zip_member(name: str) -> None:
    """Reject path-traversal entries before extracting.

    Specifically rejected:

    * absolute paths (``/etc/passwd``, ``C:\\…``)
    * components starting with ``..``
    * any component equal to ``..``
    """

    if not name:
        raise ValueError("zip entry has empty name")
    # Normalize separators for the pure-text checks below.
    normalized = name.replace("\\", "/")
    if os.path.isabs(normalized) or normalized.startswith("/"):
        raise ValueError(f"absolute path in zip: {name!r}")
    if normalized.startswith("../") or normalized == ".." or "/../" in normalized:
        raise ValueError(f"path traversal in zip: {name!r}")
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    for p in parts:
        if p == "..":
            raise ValueError(f"path traversal in zip: {name!r}")


def set_source_zip_finalize(
    upload_id: str,
    expected_sha256: str,
    *,
    workspace_root: Optional[Path] = None,
    session_id: str,
) -> Path:
    """Finalize a chunked upload: verify checksum and extract.

    Args:
        upload_id: Identifier matching the prior ``set_source_zip_chunk`` calls.
        expected_sha256: Hex sha256 the assembled zip must hash to.
        workspace_root: Override workspace root.
        session_id: MCP session identifier.

    Returns:
        Absolute path of the extracted source tree (the session's
        ``source_dir``). Unchanged on every failure path: extraction goes to a
        staging sibling and is renamed into place only after it succeeds, so a
        refused re-delivery leaves the previously delivered tree intact rather
        than leaving the session registered against an empty directory.

    Raises:
        FileNotFoundError: if the upload never received its final chunk.
        ValueError: if ``upload_id`` does not name a single path component, or on
            sha256 mismatch, oversize zip, oversize extraction, too-many-files,
            or path-traversal/symlink-out-of-tree entries.
        zipfile.BadZipFile: if the assembled bytes are not a zip archive. The
            checksum matching means the client sent what it meant to send, so
            this is a client-side packaging error rather than corruption.
    """

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = _ensure_dir(_session_workspace(root, session_id))
    final = _final_zip_path(session_dir, upload_id)
    if not final.exists():
        raise FileNotFoundError(
            f"no finalized zip for upload_id={upload_id!r} "
            f"(did the last chunk arrive with last=True?)"
        )

    # Hard limit on the on-disk zip size.
    actual_size = final.stat().st_size
    if actual_size > _MAX_ZIP_BYTES:
        final.unlink(missing_ok=True)
        raise ValueError(f"zip too large: {actual_size} > {_MAX_ZIP_BYTES} bytes")

    # Verify checksum before opening the archive.
    digest = hashlib.sha256()
    with final.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    actual_sha = digest.hexdigest()
    if actual_sha.lower() != expected_sha256.lower():
        final.unlink(missing_ok=True)
        raise ValueError(
            f"sha256 mismatch: expected {expected_sha256}, got {actual_sha}"
        )

    # Extract into a staging sibling and swap, rather than clearing the
    # delivered tree first. The checksum and size guards above do precede any
    # write, but the four guards a hostile or malformed archive trips -- entry
    # count, member traversal, uncompressed total, symlink member -- all run
    # after the archive is open, and so did ``zipfile.ZipFile`` itself raising
    # BadZipFile. Removing the tree before that point left the session
    # registered and pointing at an empty directory, which a scan then reports
    # as clean: the false-negative shape, and the worst outcome available to a
    # security scanner. Costs one delivery's worth of extra peak disk, since the
    # old and new trees coexist until the rename.
    target = session_dir / "source"
    staging = session_dir / _STAGING_DIR_NAME
    if staging.exists():
        # Left behind by a delivery that died between extraction and the swap.
        # It is scratch space and never the delivered tree, so removing it
        # cannot lose anything a caller can still reach.
        shutil.rmtree(staging, ignore_errors=True)
    _ensure_dir(staging)

    swapped = False
    try:
        # Pre-extraction validation pass: walk the namelist and the zipinfo
        # list, rejecting absolute paths, traversal components, oversize totals,
        # and symlinks that would resolve outside the session sandbox.
        with zipfile.ZipFile(final) as zf:
            infos = zf.infolist()
            if len(infos) > _MAX_FILES:
                raise ValueError(f"too many files in zip: {len(infos)} > {_MAX_FILES}")

            total_uncompressed = 0
            for info in infos:
                _validate_zip_member(info.filename)
                total_uncompressed += info.file_size
                if total_uncompressed > _MAX_EXTRACTED_BYTES:
                    raise ValueError(
                        f"extracted size exceeds {_MAX_EXTRACTED_BYTES} bytes "
                        f"(at entry {info.filename!r})"
                    )
                if _is_symlink_zipinfo(info):
                    # Reject ALL symlink entries — not just those whose target
                    # resolves outside the sandbox. Pre-extraction resolve()
                    # of a link under (target/info.filename).parent races
                    # extraction: an earlier zip entry that materializes a
                    # directory which is itself a symlink (or a leftover-from-
                    # prior-upload directory that resolves elsewhere) would
                    # let a later symlink entry pass validation but still
                    # escape once extractall() runs.
                    #
                    # Source tree shipping over MCP does not need symlinks.
                    # Refusing them outright eliminates the pre/post-write
                    # divergence. See DA r6 #5.
                    link_target = zf.read(info).decode("utf-8", errors="replace")
                    raise ValueError(
                        f"symlink {info.filename!r} -> {link_target!r}: "
                        f"symlinks are not allowed in MCP source delivery zips"
                    )

            # Validation passed; extract into staging.
            zf.extractall(staging)

        # Swap. The old tree only goes away once the new one is complete on
        # disk, and the rename is within one directory so the window in which
        # neither is in place is two syscalls wide rather than the whole
        # validate-and-extract pass.
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        staging.rename(target)
        swapped = True
    finally:
        if not swapped:
            shutil.rmtree(staging, ignore_errors=True)

    _set_session_source_dir(session_id, target)
    # The on-disk zip is no longer needed.
    final.unlink(missing_ok=True)
    return target


# ---------------------------------------------------------------------------
# Cleanup.
# ---------------------------------------------------------------------------


def clear_source(session_id: str, *, workspace_root: Optional[Path] = None) -> None:
    """Wipe the session workspace and forget any recorded ``source_dir``.

    Idempotent: missing workspaces are silently ignored.
    """

    root = workspace_root if workspace_root is not None else resolve_workspace_root()
    session_dir = _session_workspace(root, session_id)
    shutil.rmtree(session_dir, ignore_errors=True)
    _drop_session_source_dir(session_id)
