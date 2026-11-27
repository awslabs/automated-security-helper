# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one image-reference grammar every surface checks a reference against.

A container image reference reaches the image scanners' command lines (grype,
syft, trivy) from four places: the CLI's ``--image``, the ``run_ash_scan``
API, the MCP ``set_source_image`` tool, and an ``ImageLocator`` built in code.
The tools read text that is NOT a reference as something else: a leading
``-`` as an option, and a path (``/etc``, ``./x``, ``../x``) as a directory or
file to catalog in place of an image. This module is the one place the grammar
is spelled, so the surfaces cannot drift on what they admit, and the argv
builders (``utils/image_tool_targets``, trivy's image dispatch) read it once
more before a reference becomes a token.

The grammar is the distribution reference grammar the tools parse references
with (``github.com/distribution/reference`` v0.6.0, ``regexp.go`` and
``reference.go``)::

    reference       := name [ ":" tag ] [ "@" digest ]
    name            := [ domain "/" ] path-component [ "/" path-component ]*
    domain          := host [ ":" port-number ]
    host            := domain-name | "[" IPv6 "]"
    domain-name     := domain-component [ "." domain-component ]*
    domain-component:= [a-zA-Z0-9] | [a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]
    path-component  := [a-z0-9]+ [ separator [a-z0-9]+ ]*
    separator       := [._] | "__" | "-"+
    tag             := [\\w][\\w.-]{0,127}
    digest          := algorithm ":" hex

with the parser's own limits on top: the repository path is at most 255
characters, a bare 64-hex name is refused (it reads as an image ID), and a
digest is one the tools can verify (sha256, sha384 or sha512 in lowercase hex
of the algorithm's length).

What the grammar cannot settle alone: a reference can also spell a RELATIVE
path (``app``, ``team/app``), and a tool that tries its local sources first
reads such a reference as the file or directory of that name in its working
directory. That is why no target is handed over without its source named
(``docker:``, ``registry:``, ``--input``, or ``--from`` for the schemeless
declared-daemon target; see ``utils/image_tool_targets``).
"""

from __future__ import annotations

import re
from typing import Optional

#: The longest text read as a reference at all. A hostname is at most 253
#: characters and a repository path 255, with a tag or digest on top; 512
#: admits every real reference and bounds the grammar match.
MAX_REFERENCE_CHARS = 512

#: The longest repository path the distribution parser accepts.
MAX_REPOSITORY_PATH_CHARS = 255

_ALPHANUMERIC = r"[a-z0-9]+"
_SEPARATOR = r"(?:[._]|__|[-]+)"
_PATH_COMPONENT = rf"{_ALPHANUMERIC}(?:{_SEPARATOR}{_ALPHANUMERIC})*"
_REMOTE_NAME = rf"{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*"
_DOMAIN_COMPONENT = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
_DOMAIN_NAME = rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*"
_IPV6 = r"\[(?:[a-fA-F0-9:]+)\]"
_DOMAIN_AND_PORT = rf"(?:{_DOMAIN_NAME}|{_IPV6})(?::[0-9]+)?"
_TAG = r"[\w][\w.-]{0,127}"
_DIGEST = r"[A-Za-z][A-Za-z0-9]*(?:[-_+.][A-Za-z][A-Za-z0-9]*)*:[0-9a-fA-F]{32,}"

_REFERENCE = re.compile(
    rf"(?P<name>(?:{_DOMAIN_AND_PORT}/)?{_REMOTE_NAME})"
    rf"(?::(?P<tag>{_TAG}))?"
    rf"(?:@(?P<digest>{_DIGEST}))?",
    re.ASCII,
)
_NAME = re.compile(
    rf"(?:(?P<domain>{_DOMAIN_AND_PORT})/)?(?P<path>{_REMOTE_NAME})", re.ASCII
)

#: The digests a tool can verify, as go-digest validates them.
_VERIFIABLE_DIGEST = re.compile(
    r"sha256:[0-9a-f]{64}|sha384:[0-9a-f]{96}|sha512:[0-9a-f]{128}"
)
_IMAGE_ID = re.compile(r"[a-f0-9]{64}")
_WHITESPACE_OR_CONTROL = re.compile(r"[\s\x00-\x1f\x7f]")

_FORM = (
    "the form is [registry[:port]/]repository[:tag][@digest], with a "
    "lowercase repository path"
)


def image_reference_problem(ref: object) -> Optional[str]:
    """Why *ref* is not an image reference, or None when it is one.

    The answer reads after the value it is about ("'/etc' is not an image
    reference: ..."), so a surface can prefix its own name for the value. Each
    refusal names its reason: a leading ``-`` reads as an option, a leading
    ``/``, ``.``, ``~`` or a backslash reads as a path, and everything else the
    grammar refuses is named with the form a reference takes.
    """
    if not isinstance(ref, str) or not ref.strip():
        return "names no reference: it is empty or whitespace"
    lead = "is not an image reference: "
    if len(ref) > MAX_REFERENCE_CHARS:
        return (
            f"{lead}it is longer than {MAX_REFERENCE_CHARS} characters, which "
            "no image reference is"
        )
    if not ref.isascii():
        return f"{lead}it carries non-ASCII text, which no image reference holds"
    if _WHITESPACE_OR_CONTROL.search(ref):
        return (
            f"{lead}it carries whitespace or a control character, which no "
            "image reference holds"
        )
    if ref.startswith("-"):
        return (
            f"{lead}it starts with '-', so a tool would read it as an option; "
            "no image reference starts with one"
        )
    if ref.startswith(("/", ".", "~")) or "\\" in ref:
        return (
            f"{lead}it reads as a filesystem path, and a tool handed it would "
            f"read that path; {_FORM}"
        )
    match = _REFERENCE.fullmatch(ref)
    if match is None:
        return f"{lead}{_FORM}"
    name = _NAME.fullmatch(match.group("name"))
    path = name.group("path") if name is not None else match.group("name")
    if len(path) > MAX_REPOSITORY_PATH_CHARS:
        return (
            f"{lead}its repository path is longer than "
            f"{MAX_REPOSITORY_PATH_CHARS} characters"
        )
    if _IMAGE_ID.fullmatch(ref):
        return f"{lead}a bare 64-hex name reads as an image ID, not a repository name"
    digest = match.group("digest")
    if digest is not None and _VERIFIABLE_DIGEST.fullmatch(digest) is None:
        return (
            f"{lead}its digest is not one a tool can verify (sha256, sha384 "
            "or sha512, in lowercase hex of the algorithm's length)"
        )
    return None


def checked_image_reference(ref: str) -> str:
    """*ref*, or a ValueError naming why it is not an image reference."""
    problem = image_reference_problem(ref)
    if problem is not None:
        raise ValueError(f"{ref!r} {problem}")
    return ref
