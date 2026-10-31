# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A clone url whose text before its first ``::`` is scheme-shaped is refused.

git reads a scheme-shaped prefix before ``::`` as a remote helper. The refusal is a
plain string-prefix test, made before the url is read as a host, and it covers every
such prefix, not one spelling. The scp-like ``host:path`` form, with one colon, is
still admitted.
"""

from __future__ import annotations

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("url", ["ext::anything", "rsync::host/path"])
def test_a_scheme_shaped_prefix_before_a_double_colon_is_refused(url) -> None:
    with pytest.raises(ValueError, match="transport"):
        sd._validate_clone_url(url)
    with pytest.raises(ValueError, match="transport"):
        sd.remote_clone_endpoint(url)


def test_the_scp_like_form_with_one_colon_is_admitted() -> None:
    assert sd._validate_clone_url("host:path") == "host:path"
    assert sd.remote_clone_endpoint("host:path") == ("ssh", "host", 22)
