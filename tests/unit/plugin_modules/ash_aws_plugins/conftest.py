# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fixtures this directory's AWS reporter tests share.

A test module that needs a different ``context`` (a path under ``tmp_path``, say)
defines its own fixture of that name, which takes precedence over this one.
"""

import pytest


@pytest.fixture
def context(test_plugin_context):
    """The plugin context the Bedrock reporter tests build their reporter on."""
    return test_plugin_context
