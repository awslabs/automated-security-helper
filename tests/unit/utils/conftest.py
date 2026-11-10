# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures shared by the utils unit tests."""

from __future__ import annotations

import os
import sys
import urllib.request

import pytest


class _ScopedOs:
    """The ``os`` module, with some names replaced, for one module to use.

    ``monkeypatch.setattr(module.os, "replace", fake)`` replaces ``os.replace`` for
    the whole process, since ``module.os`` is the one ``os`` module: pytest's own
    file handling and every other thread read the stand-in too. Setting the
    module's ``os`` name to one of these changes what that module sees and nothing
    else; every name not replaced is the real one.
    """

    def __init__(self, **replaced):
        self.__dict__.update(replaced)

    def __getattr__(self, name):
        return getattr(os, name)


@pytest.fixture
def patch_module_os(monkeypatch):
    """``patch_module_os(module, replace=fake, ...)``: ``module`` sees those names of
    ``os`` replaced for the rest of the test, and no other module does."""

    def patch(module, **replaced):
        monkeypatch.setattr(module, "os", _ScopedOs(**replaced))

    return patch


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
            lambda url, timeout: urllib.request.urlopen(url, timeout=timeout),  # nosec B310
        )


#: Masking suites that run twice, once as they are and once with the lookup plan
#: forced (see ``_mask_plan``). With a few values the index keeps one regex
#: alternation (``_ALTERNATION_MAX_BRANCHES``), so most masking tests never reach
#: the lookups that a report with many secrets uses.
_BOTH_MASK_PLANS = frozenset(
    {
        "test_secret_masking_across_results",
        "test_secret_masking_shape_tokens",
        "test_secret_masking_shapes_in_text",
        "test_secret_masking_more_text_forms",
        "test_secret_masking_regression",
        "test_secret_masking_json_forms",
    }
)


def pytest_generate_tests(metafunc):
    if metafunc.module.__name__.rsplit(".", 1)[-1] in _BOTH_MASK_PLANS:
        metafunc.parametrize(
            "_mask_plan",
            [None, 0],
            ids=["default-plan", "lookup-plan"],
            indirect=True,
        )


@pytest.fixture(autouse=True)
def _mask_plan(request, monkeypatch):
    """Force the lookup plan for the second run of a suite in ``_BOTH_MASK_PLANS``."""
    threshold = getattr(request, "param", None)
    if threshold is not None:
        from automated_security_helper.utils import secret_masking

        monkeypatch.setattr(secret_masking, "_ALTERNATION_MAX_BRANCHES", threshold)
