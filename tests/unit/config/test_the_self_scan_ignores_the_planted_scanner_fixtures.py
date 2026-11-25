# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ASH's scan of its own repository must not flag the planted scanner fixtures.

``tests/test_data/scanners`` holds deliberately flagged inputs: a placeholder
password line, a ``shell=True`` call, an insecure bucket template. They are
read by the facets corpus tests and are findings by design. The repository's own
scan configs cover them with the ``tests/test_data/**`` ignore path; this pins
that coverage per fixture, so a narrowing of the ignore (or a fixture moved out
of the directory) reads red here instead of as new actionable findings in the
self-scan.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.utils.path_matching import match_glob

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SELF_SCAN_CONFIGS = (
    REPO_ROOT / ".ash.yaml",
    REPO_ROOT / ".ash" / ".ash_alpha_plugins.yaml",
)
PLANTED_FIXTURES = (
    "tests/test_data/scanners/detect_secrets/fixture_repo/m0_planted.txt",
    "tests/test_data/scanners/semgrep/fixture_repo/m0_flagged.py",
    "tests/test_data/scanners/checkov/fixture_repo/insecure-s3-template.yaml",
)


def _ignore_patterns(config: Path) -> list[str]:
    document = yaml.safe_load(config.read_text(encoding="utf-8"))
    entries = document["global_settings"]["ignore_paths"]
    return [entry["path"] for entry in entries]


@pytest.mark.parametrize("config", SELF_SCAN_CONFIGS, ids=lambda path: path.name)
@pytest.mark.parametrize("fixture", PLANTED_FIXTURES)
def test_a_planted_fixture_is_ignored_by_the_self_scan_config(config, fixture):
    assert (REPO_ROOT / fixture).is_file(), f"{fixture} moved: update this pin"
    patterns = _ignore_patterns(config)

    assert any(match_glob(fixture, pattern) for pattern in patterns), (
        f"{fixture} matches no ignore_paths entry of {config.name}"
    )


def test_the_ignore_does_not_reach_the_product_source():
    # A control: the ignore is the fixture directory, not a broad glob.
    patterns = _ignore_patterns(SELF_SCAN_CONFIGS[0])
    product_file = "automated_security_helper/plugin_modules/ash_builtin/scanners/checkov_scanner.py"

    assert not any(match_glob(product_file, pattern) for pattern in patterns)
