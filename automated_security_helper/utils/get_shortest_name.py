# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path


# A002 on `input` is suppressed rather than fixed: the parameter name is this
# function's published keyword. Roughly 25 call sites across 12 modules spell it
# `get_shortest_name(input=...)` (base/scanner_plugin.py, utils/normalizers.py,
# utils/cdk_nag_wrapper.py and eight scanner plugins), and one of them already
# carries a `# type: ignore[call-arg]`. This package is published to PyPI and
# exposes a plugin API, so a third-party scanner plugin can be calling it by
# keyword too -- a rename here is a breaking change for a lint nit, and a
# "silent" one, because no caller outside this repository would be updated.
#
# The A001 on the body WAS fixed: reassigning the parameter was never part of any
# contract, and the reassignment also changed the bound type (str -> Path)
# midway, which is worth removing on its own.
#
# `cwd` names the directory the answer is relative to. It defaults to the working
# directory of the calling process. A caller that computes names for another process,
# such as the cdk-nag worker child naming templates against its parent's directory,
# passes that directory: a relative input and the existence check are then resolved
# against it too, so the answer does not depend on where the caller happens to be
# running (or on whether it can enter that directory at all).
def get_shortest_name(input: str | Path, cwd: Path | None = None):  # noqa: A002
    if input == ".":
        # Just return the input, it's already referencing the relative path to CWD
        return input
    in_path = Path(input)
    base = None if cwd is None else Path(cwd).absolute()
    probe = in_path if base is None or in_path.is_absolute() else base / in_path
    if not probe.exists():
        # Not an existing path: returned as given, as text. Callers put the result
        # in str-typed SARIF fields (artifactLocation.uri, working_directory), and a
        # Path handed back unchanged reached them as a Path.
        return input if isinstance(input, str) else input.as_posix()
    if base is None:
        base = Path.cwd().absolute()
    absolute = probe.absolute()
    # Annotated because the two branches bind different types: relative_to() gives a
    # Path, while `input` is still str | Path. Without this mypy infers Path from the
    # first branch and rejects the second -- the union is the honest type here, and
    # Path() accepts either.
    shortest: str | Path
    # Compared by path components, not by text: with the cwd /work/app, the input
    # /work/app-src/f starts with the cwd's text but is not below it, and
    # relative_to() then raised ValueError out of every scanner and converter that
    # names a file this way.
    if absolute != base and absolute.is_relative_to(base):
        # If input is below the cwd, use the relative path
        shortest = absolute.relative_to(base)
    else:
        shortest = input
    return Path(shortest).as_posix()


def home_as_tilde(text: str) -> str:
    """*text* with the user's home directory written as ``~``.

    For text that goes into the results and reports rather than ash.log: a
    scanner's ``missing_reason`` names where ASH looked for its tool (ASH's bin
    directory is under the home directory by default) and, for a uv-run tool, the
    uv executable it found. The home directory is the host-specific part, and the
    reports reach ash.flat.json, MCP clients and the cloud reporters.

    Replaced: the home directory as given and its resolved form, since one is often
    a symlink to the other, and on Windows each with ``/`` for ``\\`` too, since the
    not-found reason writes ``as_posix()`` paths; a drive-letter home is matched
    without regard to case. Only a whole path is replaced: it must start the text or
    follow whitespace or one of ``,;:(='"`[<{`` and end the text or be followed by a
    separator, whitespace, one of ``,;:)'"`]>}``, or a period that ends a sentence
    (one followed by whitespace or the end of the text), so ``/home/a`` is left alone
    inside ``/home/ab``, ``/home/a.bak``, ``/srv/home/a``, ``//home/a`` and
    ``file:///home/a`` and is rewritten in ``looked under /home/a.``. A
    name that goes on with one of those characters is rewritten too, though it is
    not under the home directory: ``/home/a]x/y`` becomes ``~]x/y`` and
    ``/opt/a[/home/a/x`` becomes ``/opt/a[~/x``. This text is for display, and such
    names are rare enough that the boundary is not narrowed for them.

    Left alone: a home that is not absolute (its resolved form would be the working
    directory joined to it, not a home), and a root (``/``, ``C:\\``), since
    replacing either would rewrite other paths. Not recognized: a UNC home
    (``\\\\server\\share\\u``), a ``\\\\?\\``-prefixed path, and a Python repr's
    doubled backslashes; no reason ASH writes uses those forms.
    """
    import os
    import re

    from automated_security_helper.core.constants import usable_home

    home_path = usable_home()
    if home_path is None:
        return text
    home = str(home_path)
    drive = re.compile(r"^[A-Za-z]:[\\/]")
    if not (home.startswith("/") or drive.match(home)):
        return text
    forms: set[str] = set()
    for candidate in {home, os.path.realpath(home)}:
        windows = bool(drive.match(candidate))
        if not (candidate.startswith("/") or windows):
            continue
        stripped = candidate.rstrip("/\\")
        if not stripped or re.fullmatch(r"[A-Za-z]:", stripped):
            continue
        forms.add(stripped)
        if windows:
            forms.add(stripped.replace("\\", "/"))
    before = r"(?<![^\s,;:(='\"`\[<{])"
    # A period is a boundary only when it ends a sentence: `/home/a.bak` names a
    # sibling directory, `/home/a.` ends a reason.
    after = r"(?:(?![^/\\\s,;:)'\"`\]>}])|(?=\.(?:\s|$)))"
    for form in sorted(forms, key=len, reverse=True):
        flags = re.IGNORECASE if drive.match(form) else 0
        text = re.sub(before + re.escape(form) + after, "~", text, flags=flags)
    return text
