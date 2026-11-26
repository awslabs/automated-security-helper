# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The secret suppressions for the sdist-lock harvest manifests pin the digest line.

Why this exists
---------------
The sdist-lock harvester writes a provenance manifest (``harvest-manifest.json``)
beside each lockfile it extracts, and the default self-scan's hex detector reports
the sdist's sha256 digest in every one of them. ``.ash.yaml`` suppresses that, one
entry per manifest and each pinned to a line, because a secret rule may not be
suppressed by a directory glob (test_no_directory_glob_secret_suppressions.py).

The pin is a line number, and nothing tied it to the code that decides the line.
``HarvestManifest.to_json`` writes the digest on line 6 today. A key added or moved
above ``sdist_sha256`` moves it, and every entry then excuses a line that holds no
finding while the digest is reported again. A pin that excuses nothing reads the
same in the config as one that works.

What this checks
----------------
* ``.ash.yaml`` carries at least one such entry, so the checks below do not pass
  over nothing.
* Each entry's ``line_start`` and ``line_end`` are both the line of the digest in
  the manifest ``to_json`` writes, found by serializing a real manifest. A failure
  names the line to use.
* Each entry names one manifest file in the default output directory's harvest
  layout, spelled from the product's own names: no wildcard, and a package and a
  version that are single path components the harvest itself would accept.

What it does not check
----------------------
That each named package and version is still in a lock file, or that every
manifest a self-scan reports has an entry. The first would fail an entry added
ahead of a version bump, which is the order the comment above the entries asks for
(the required self-scan reads ``.ash.yaml`` from the pull request's base commit).
The second needs the sdists, which only a scan fetches.
"""

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.converters.sdist_lock_harvester import (
    SdistLockHarvesterConverterConfig,
)
from automated_security_helper.utils.scan_output_dirs import DEFAULT_OUTPUT_RELATIVE
from automated_security_helper.utils.sdist_harvest import (
    HARVEST_DIR_NAME,
    HARVEST_MANIFEST_NAME,
    PACKAGE_IDENTIFIER_RE,
    HarvestManifest,
)
from automated_security_helper.utils.suppression_matcher import _rule_id_matches

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIGS = (".ash.yaml", ".ash/.ash_alpha_plugins.yaml")
#: Only the default config's scan runs detect-secrets and the harvester together,
#: so only it must carry the entries.
CONFIG_WITH_THE_ENTRIES = ".ash.yaml"

RULE = "SECRET-HEX-HIGH-ENTROPY-STRING"

#: The directory every harvested package's files land in, for a scan whose output
#: directory is the default, inside the scanned tree:
#: ``.ash/ash_output/converted/sdist-lock-harvester/sdist-locks``.
HARVEST_ROOT = (
    f"{DEFAULT_OUTPUT_RELATIVE.as_posix()}/{ASH_WORK_DIR_NAME}/"
    f"{SdistLockHarvesterConverterConfig().name}/{HARVEST_DIR_NAME}"
)
EXAMPLE_PATH = f"{HARVEST_ROOT}/ruff/0.16.10/{HARVEST_MANIFEST_NAME}"


def digest_line(manifest_type: type = HarvestManifest) -> int:
    """The 1-based line of the sdist digest in a manifest as ``to_json`` writes it."""
    manifest = manifest_type(
        package="example",
        version="1.0.0",
        parent_purl="pkg:pypi/example@1.0.0",
        sdist_url="https://files.example.invalid/example-1.0.0.tar.gz",
        # Made at run time: a literal digest in this file would be a finding too.
        sdist_sha256=hashlib.sha256(b"harvest manifest pin").hexdigest(),
        lockfiles=["Cargo.lock"],
    )
    lines = [
        number
        for number, text in enumerate(manifest.to_json().splitlines(), start=1)
        if '"sdist_sha256"' in text
    ]
    assert len(lines) == 1, f"the manifest names sdist_sha256 on {lines} lines"
    return lines[0]


def manifest_secret_entries(config: dict) -> list[dict]:
    """The suppressions that cover the hex rule in a provenance manifest.

    Read by the product's own rule matcher, as the rule is read when a scan applies
    the entry: a spelling that covers the rule (``secret-hex-*``, ``SECRET-*``,
    ``*``, or none at all) counts as the rule itself. The path is selected by the
    manifest's file name, so a wildcard in the directory part or a wildcard name
    that still ends in it is read too.
    """
    suppressions = (config.get("global_settings") or {}).get("suppressions") or []
    return [
        entry
        for entry in suppressions
        if HARVEST_MANIFEST_NAME in str(entry.get("path") or "")
        and _rule_id_matches(RULE, str(entry.get("rule_id") or "*"))
    ]


def misplaced_pins(config: dict, line: int) -> list[str]:
    """One message per manifest entry whose lines are not exactly ``line``."""
    return [
        f"{entry.get('path')} pins lines {entry.get('line_start')}-"
        f"{entry.get('line_end')}"
        for entry in manifest_secret_entries(config)
        if entry.get("line_start") != line or entry.get("line_end") != line
    ]


def names_one_manifest(path: str) -> bool:
    """Whether ``path`` is ``<harvest root>/<package>/<version>/harvest-manifest.json``."""
    head, tail = f"{HARVEST_ROOT}/", f"/{HARVEST_MANIFEST_NAME}"
    if not (path.startswith(head) and path.endswith(tail)):
        return False
    parts = path[len(head) : -len(tail)].split("/")
    return len(parts) == 2 and all(PACKAGE_IDENTIFIER_RE.fullmatch(p) for p in parts)


def _config(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / name).read_text(encoding="utf-8")) or {}


def _entry(path: str = EXAMPLE_PATH, **fields) -> dict:
    return {"rule_id": RULE, "path": path, "reason": "probe", **fields}


def test_the_repository_suppresses_the_manifests_it_scans():
    entries = manifest_secret_entries(_config(CONFIG_WITH_THE_ENTRIES))
    assert entries, (
        f"{CONFIG_WITH_THE_ENTRIES} has no {RULE} entry for a "
        f"{HARVEST_MANIFEST_NAME}; the default self-scan reports each manifest "
        "without one, and the pin checks below would pass over nothing"
    )


@pytest.mark.parametrize("name", CONFIGS)
def test_every_manifest_entry_pins_the_digest_line(name):
    line = digest_line()
    misplaced = misplaced_pins(_config(name), line)
    assert misplaced == [], (
        f"HarvestManifest.to_json writes the sdist digest on line {line} of a "
        f"manifest, so each entry in {name} needs line_start: {line} and "
        f"line_end: {line}. These pin another range, so the digest is reported "
        f"again: {misplaced}"
    )


@pytest.mark.parametrize("name", CONFIGS)
def test_every_manifest_entry_names_one_manifest_file(name):
    elsewhere = [
        entry["path"]
        for entry in manifest_secret_entries(_config(name))
        if not names_one_manifest(entry["path"])
    ]
    assert elsewhere == [], (
        f"{name}: a manifest entry must be {HARVEST_ROOT}/<package>/<version>/"
        f"{HARVEST_MANIFEST_NAME}, one file, no wildcard: {elsewhere}"
    )


# Negative controls: the checks above, fed entries whose verdict is known.


class _ManifestWithAKeyAbove(HarvestManifest):
    """A serializer that puts one more key above the digest, as a change might."""

    def to_json(self) -> str:
        document = json.loads(super().to_json())
        return json.dumps({"schema": 2, **document}, indent=2)


def test_the_digest_line_follows_the_serializer():
    assert digest_line(_ManifestWithAKeyAbove) == digest_line() + 1


def test_a_serializer_that_moves_the_digest_fails_the_repository_pins():
    # What the guard is for: with the digest one line down, every entry the
    # repository carries is reported, and the report names the line to use.
    moved = digest_line(_ManifestWithAKeyAbove)
    repository = misplaced_pins(_config(CONFIG_WITH_THE_ENTRIES), moved)
    assert repository, "the repository's pins did not move with the digest"
    assert len(repository) == len(
        manifest_secret_entries(_config(CONFIG_WITH_THE_ENTRIES))
    )


@pytest.mark.parametrize(
    "start, end",
    [
        (None, None),  # no pin at all: the whole file
        (5, 5),  # one line above
        (7, 7),  # one line below
        (1, 99),  # a range around it
        (6, None),  # open ended: from the digest line to the end of the file
        (None, 6),  # no start
        (6, 7),  # a range that holds the digest line and another
        (5, 6),
    ],
)
def test_a_pin_that_is_not_the_digest_line_is_reported(start, end):
    fields = {}
    if start is not None:
        fields["line_start"] = start
    if end is not None:
        fields["line_end"] = end
    config = {"global_settings": {"suppressions": [_entry(**fields)]}}
    reported = misplaced_pins(config, digest_line())
    assert len(reported) == 1
    assert EXAMPLE_PATH in reported[0]


def test_the_digest_line_pin_is_not_reported():
    line = digest_line()
    config = {
        "global_settings": {
            "suppressions": [_entry(line_start=line, line_end=line)],
        }
    }
    assert misplaced_pins(config, line) == []


@pytest.mark.parametrize(
    "rule_id",
    [RULE, RULE.lower(), "SECRET-HEX-*", "SECRET-*", "*", None],
)
def test_the_selector_sees_every_rule_spelling_that_covers_the_hex_rule(rule_id):
    entry = {"path": EXAMPLE_PATH, "reason": "probe"}
    if rule_id is not None:
        entry["rule_id"] = rule_id
    config = {"global_settings": {"suppressions": [entry]}}
    assert manifest_secret_entries(config) == [entry]


@pytest.mark.parametrize(
    "rule_id, path",
    [
        # Another rule in a manifest.
        ("B101", EXAMPLE_PATH),
        ("SECRET-AWS-ACCESS-KEY", EXAMPLE_PATH),
        # The hex rule in another file.
        (RULE, f"{HARVEST_ROOT}/ruff/0.16.10/Cargo.lock"),
        (RULE, "scripts/setup-nerdctl-linux.sh"),
    ],
)
def test_the_selector_leaves_other_entries_alone(rule_id, path):
    config = {
        "global_settings": {
            "suppressions": [{"rule_id": rule_id, "path": path, "reason": "probe"}]
        }
    }
    assert manifest_secret_entries(config) == []


@pytest.mark.parametrize(
    "path, expected",
    [
        (EXAMPLE_PATH, True),
        (f"{HARVEST_ROOT}/polars-runtime-32/1.44.2/{HARVEST_MANIFEST_NAME}", True),
        # A wildcard anywhere is not one file.
        (f"{HARVEST_ROOT}/*/0.16.10/{HARVEST_MANIFEST_NAME}", False),
        (f"{HARVEST_ROOT}/ruff/*/{HARVEST_MANIFEST_NAME}", False),
        (f"{HARVEST_ROOT}/**/{HARVEST_MANIFEST_NAME}", False),
        (f"**/{HARVEST_DIR_NAME}/ruff/0.16.10/{HARVEST_MANIFEST_NAME}", False),
        # A package or version that is not one path component.
        (f"{HARVEST_ROOT}/ruff/{HARVEST_MANIFEST_NAME}", False),
        (f"{HARVEST_ROOT}/a/b/c/{HARVEST_MANIFEST_NAME}", False),
        # Another output directory is not the default's.
        (
            f"out/converted/x/{HARVEST_DIR_NAME}/ruff/0.16.10/{HARVEST_MANIFEST_NAME}",
            False,
        ),
        # Another file in the same directory.
        (f"{HARVEST_ROOT}/ruff/0.16.10/Cargo.lock", False),
    ],
)
def test_names_one_manifest_reads_the_path_shape(path, expected):
    assert names_one_manifest(path) is expected
