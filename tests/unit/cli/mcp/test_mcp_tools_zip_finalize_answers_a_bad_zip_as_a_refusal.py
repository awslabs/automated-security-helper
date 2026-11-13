# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``set_source_zip_finalize`` answers bytes that are not a zip as a refusal.

The delivery documents ``zipfile.BadZipFile`` for assembled bytes that are not a
zip archive: the checksum matched, so the client sent what it meant to and
packaged it wrong, a client-side error like a checksum mismatch. The tool caught
only ``UploadNotFoundError`` and ``ValueError``, so the archive error left the
tool as an exception, logged as unexpected and answered with its class name. It
is now answered as the other refusals are.
"""

from __future__ import annotations

import zipfile

import pytest

pytestmark = pytest.mark.unit


def test_bytes_that_are_not_a_zip_are_a_refusal_not_an_exception(monkeypatch) -> None:
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.cli.mcp import source_delivery

    def not_a_zip(**kwargs):
        raise zipfile.BadZipFile("File is not a zip file")

    monkeypatch.setattr(source_delivery, "set_source_zip_finalize", not_a_zip)

    response = mcp_tools.mcp_set_source_zip_finalize(
        upload_id="u1", expected_sha256="00", session_id="client-one"
    )

    assert response["success"] is False, response
    assert "zip" in response["error"].lower(), response
    # The same shape as the checksum and oversize refusals: no error_type.
    assert "error_type" not in response, response
