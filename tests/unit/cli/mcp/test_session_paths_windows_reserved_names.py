#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two Windows name forms the allowlist admits by character and the rule refuses.

Windows reads two kinds of name otherwise than written, and both are made of
characters ``session_paths._ALLOWED_COMPONENT`` allows: a name that ends in a
period, which Windows drops when it opens the name (``abc.`` opens the directory
of ``abc``), and the reserved device names (``CON``, ``PRN``, ``AUX``, ``NUL``,
``COM1``-``COM9``, ``LPT1``-``LPT9``), which name a device in every directory,
with or without an extension (``NUL.txt`` is ``NUL``). Admitted, the first would
be two registry entries over one directory and the second a directory that cannot
be made, so ``validated_path_component`` refuses both, on every platform.

The positive controls are the point of the file as much as the refusals: a name
that merely starts with a device name (``CONFIG``), carries one after a period
(``a.con``), or numbers a port Windows does not reserve (``COM10``) is an
ordinary id and stays accepted, as every id the suite already pins does.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp.session_paths import (
    session_directory,
    validated_path_component,
)

pytestmark = pytest.mark.unit

#: Ends in a period: Windows opens the name without it.
TRAILING_PERIOD = ["abc.", "session-a.", "dotted.name.", "a..", "Aux."]

#: Names a Windows device, in any letter case, with or without an extension.
DEVICE_NAMES = [
    "CON",
    "con",
    "Prn",
    "AUX",
    "NUL",
    "nul",
    "COM1",
    "com9",
    "LPT1",
    "lpt9",
    "NUL.txt",
    "con.tar.gz",
    "COM1.zip.part",
]

#: Looks like one of the above and is not: an ordinary id that has to stay admitted.
STILL_ACCEPTED = [
    "CONFIG",
    "console-1",
    "concrete",
    "nullable",
    "a.con",
    "x.nul.txt",
    "COM10",
    "LPT10",
    "COM",
    "LPT",
    "session-a",
    "dotted.name",
    "MiXedCase99",
]


class TestATrailingPeriodIsRefused:
    """``abc.`` and ``abc`` would be one directory on Windows and two sessions here."""

    @pytest.mark.parametrize("value", TRAILING_PERIOD)
    def test_a_name_ending_in_a_period_is_refused(self, value):
        with pytest.raises(ValueError, match="must not end with"):
            validated_path_component(value)

    def test_the_refusal_names_the_field_and_the_name_windows_would_open(self):
        with pytest.raises(ValueError, match="upload_id") as refused:
            validated_path_component("abc.", "upload_id")
        assert "'abc'" in str(refused.value)


class TestAWindowsDeviceNameIsRefused:
    """A device name is a device in every directory, whatever its extension."""

    @pytest.mark.parametrize("value", DEVICE_NAMES)
    def test_a_device_name_is_refused_in_any_case_and_with_any_extension(self, value):
        with pytest.raises(ValueError, match="Windows device name"):
            validated_path_component(value)

    def test_the_refusal_names_the_field(self):
        with pytest.raises(ValueError, match="session_id"):
            validated_path_component("NUL")

    def test_both_layers_refuse_it_before_the_parent_is_examined(self, tmp_path):
        """``session_directory`` is the form callers use; the refusal reaches it."""
        with pytest.raises(ValueError):
            session_directory(tmp_path, "CON")
        with pytest.raises(ValueError):
            session_directory(tmp_path, "abc.")


class TestOrdinaryNamesStayAccepted:
    """Positive control: the two new rules refuse only the two Windows forms."""

    @pytest.mark.parametrize("value", STILL_ACCEPTED)
    def test_a_name_that_only_resembles_a_reserved_one_is_returned_unchanged(
        self, value
    ):
        """The UUID shape production supplies is pinned by ``test_session_paths``."""
        assert validated_path_component(value) == value
