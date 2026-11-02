# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``load_model`` reads the results file as UTF-8, as every writer writes it.

``open(json_path)`` read the file in the platform's locale encoding, so on a
host whose locale is not UTF-8 (Windows) a results file with non-ASCII text
failed to load or came back garbled in ``ash inspect findings``.
"""

from __future__ import annotations

from unittest.mock import mock_open, patch

import pytest

import automated_security_helper.models.asharp_model as asharp_module
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


def test_the_results_file_is_opened_as_utf8(tmp_path):
    json_path = tmp_path / "ash_aggregated_results.json"
    json_path.write_text("{}", encoding="utf-8")
    opened = mock_open(read_data="{}")

    with patch.object(asharp_module, "open", opened, create=True):
        AshAggregatedResults.load_model(json_path)

    assert opened.call_args is not None
    assert opened.call_args.kwargs.get("encoding") == "utf-8", opened.call_args
