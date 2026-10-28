# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A sandbox refusal names a ``Path`` in POSIX form, whatever the host's separator.

The other messages this layer builds about a config path
(``mcp_tools._exit_message`` and the "could not be checked" text) spell the path
with ``as_posix()``, so a client reads one spelling on every host. ``_refusal``
formatted its ``path`` argument with ``str``, which prints a ``Path`` with the
host separator: on Windows the same refusal named
``C:\\roots\\client-1\\source\\.ash\\.ash.yaml`` while the rest of the layer wrote
``C:/roots/client-1/source/.ash/.ash.yaml``.

A ``str`` argument is the caller's own spelling (the scan target exactly as the
client gave it) and is printed as given. The ``context`` fields are read by
machines and keep the native form.

``PureWindowsPath`` stands in for a Windows ``Path`` so the check does not
depend on the host the suite runs on.
"""

from __future__ import annotations

from pathlib import Path, PureWindowsPath

from automated_security_helper.cli.mcp import sandbox

REMEDY = "Grant the directory."


def test_a_path_in_a_refusal_is_spelled_with_forward_slashes() -> None:
    config = PureWindowsPath(r"C:\roots\client-1\source\.ash\.ash.yaml")

    refusal = sandbox._refusal("Config input", config, Path("/x"), REMEDY)

    message = str(refusal)
    assert "C:/roots/client-1/source/.ash/.ash.yaml" in message
    assert "\\" not in message


def test_a_string_in_a_refusal_is_printed_as_the_caller_gave_it() -> None:
    refusal = sandbox._refusal("Scan target", "client-1\\x", Path("/x"), REMEDY)

    assert "outside the permitted roots: client-1\\x." in str(refusal)


def test_a_refusal_context_keeps_the_native_spelling_of_the_path() -> None:
    config = PureWindowsPath(r"C:\roots\client-1\source\.ash\.ash.yaml")

    refusal = sandbox._refusal("Config input", config, Path("/x"), REMEDY)

    assert refusal.context["directory_path"] == str(config)
    assert refusal.context["resolved_path"] == str(Path("/x"))
