# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan's profile copy is named in messages as the file it copies.

The server copies a session's profile beside it for one scan, named
``.ash-scan-<scan id>.<the profile's name>``, and removes the copy when the
run ends. A message that names the copy points at a file the operator never
wrote and that is gone by the time the remedy is read: a lint command naming
it lists nothing, and a refusal names a file the operator cannot find. The
copy holds the profile's own content, so the profile's path is the name a
message should use -- in the path formatter every refusal goes through, and
in the pasteable lint command a refusal ends with.
"""

from pathlib import Path

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.resolve_config import lint_hint

#: A scan id as the writer spells one: str(uuid.uuid4()).
_A_SCAN_ID = "0f0e0d0c-0b0a-4908-8706-050403020100"


@pytest.fixture
def live_copy():
    """A copy a live scan holds: registered as the writer registers it."""
    copy = Path(f"/sessions/one/config/.ash-scan-{_A_SCAN_ID}.ash.yaml")
    config_sources.register_scan_copy(copy)
    yield copy
    config_sources.discard_scan_copy(copy)


def test_a_scan_copys_path_is_described_as_the_file_it_copies(live_copy):
    assert describe_config_path(live_copy) == "/sessions/one/config/ash.yaml"


@pytest.mark.parametrize(
    "name",
    [
        pytest.param(f".ash-scan-{_A_SCAN_ID}", id="no-copied-name"),
        pytest.param(".ash-scan-.ash.yaml", id="empty-scan-id"),
        pytest.param(".ash-scan-", id="prefix-alone"),
        pytest.param("an.ash-scan-shaped.name", id="prefix-not-leading"),
        pytest.param(".ash-scan-a-scan-id.ash.yaml", id="id-not-a-uuid"),
    ],
)
def test_a_name_that_is_not_a_scan_copys_stays_its_own(name):
    """Only the copy's exact shape maps: the prefix, a scan-spelled UUID id,
    a dot, and the copied file's own name. Anything else is some file of the
    operator's, named as written."""
    path = Path("/sessions/one/config") / name
    assert describe_config_path(path) == path.as_posix()


def test_the_lint_command_names_the_file_the_copy_copies(live_copy):
    hint = lint_hint(live_copy)
    assert "--config /sessions/one/config/ash.yaml" in hint, hint
    assert ".ash-scan-" not in hint, hint
