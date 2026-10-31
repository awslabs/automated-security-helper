# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the utils unit tests."""

from __future__ import annotations

import sys
import urllib.request

import pytest


@pytest.fixture(autouse=True)
def _downloads_open_through_urlopen(monkeypatch):
    """Let a test serve a download by patching ``urllib.request.urlopen``.

    ``download_utils`` opens its URL through ``_open_url``, which builds an opener
    that refuses a redirect off https at every hop. Tests of the download paths
    stand in for the network by replacing ``urllib.request.urlopen``, which that
    opener does not call, so here ``_open_url`` forwards to whatever
    ``urllib.request.urlopen`` is at the time of the call. The module that tests
    ``_open_url`` itself overrides this fixture by name.

    Only a module already imported is patched: a test that has not imported
    ``download_utils`` is left to import it as it would have.
    """
    module = sys.modules.get("automated_security_helper.utils.download_utils")
    if module is not None:
        monkeypatch.setattr(
            module,
            "_open_url",
            lambda url, timeout: urllib.request.urlopen(url, timeout=timeout),
        )
