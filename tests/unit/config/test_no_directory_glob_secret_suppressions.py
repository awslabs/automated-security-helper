# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No committed config suppresses secret or GitHub Actions findings by directory glob.

Why this file exists
--------------------
.ash/.ash.yaml used to carry ``SECRET-*`` over ``tests/**`` and ``scripts/**``,
and ``yaml.github-actions.security.*`` over ``.github/**/*.yml``. Removing them
surfaced 61 findings the globs had been hiding, among them seven shell-injection
sinks in a composite action, a ``curl | sh`` install step, and seven actions
referenced by mutable tag. None of those had been read by anyone, because a glob
over a directory suppresses findings in files that do not exist yet as readily
as the ones its author looked at.

The decisions now sit on the lines they cover: ``# pragma: allowlist secret`` for
detect-secrets, a code fix for each Actions finding. This test keeps it that way.
A suppression for either rule family must name a file, so a secret or an
injection added to a new file is reported instead of inheriting someone else's
justification.

What counts as a directory glob
-------------------------------
``**`` anywhere, a wildcard in any directory component, or a final component
that is nothing but wildcards. The last two are here because ASH matches
non-``**`` patterns with ``fnmatch``, whose ``*`` also matches ``/``: ``tests/*``
covers ``tests/a/b/c.py`` exactly as ``tests/**`` does, so a guard that only
looked for ``**`` could be walked around by deleting one character. A wildcard
inside a file name (``test_secret_masking*.py``) is still allowed; it names files
in one directory.

A rule pattern belongs to a guarded family if it matches any probe rule id below
under ASH's own rule matcher. That includes a missing rule id and ``*``, which
match every rule and so hide secrets as well as anything else.

One kind of entry is admitted, in ``WRITTEN_BY_THE_SCAN``: a pattern for files a
scan writes into its own output while it runs. No committed file stands for
them and no file-scoped entry can name them. Each admitted row is one rule on
one path, and a test below fails if the entry it admits is gone.
"""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.utils.sdist_harvest import (
    HARVEST_DIR_NAME,
    HARVEST_MANIFEST_NAME,
)
from automated_security_helper.utils.suppression_matcher import _rule_id_matches

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
ASH_CONFIG_DIR = REPO_ROOT / ".ash"

# One real rule id per detector, taken from scans of this repository. A probe
# only has to be matched by a pattern for that pattern to be guarded, so this
# list does not need to be exhaustive within a family.
PROBE_RULE_IDS = (
    "SECRET-SECRET-KEYWORD",
    "SECRET-BASE64-HIGH-ENTROPY-STRING",
    "SECRET-HEX-HIGH-ENTROPY-STRING",
    "SECRET-AWS-ACCESS-KEY",
    "SECRET-JSON-WEB-TOKEN",
    "yaml.github-actions.security.run-shell-injection.run-shell-injection",
    "yaml.github-actions.security.gha-curl-pipe-shell.gha-curl-pipe-shell",
    "yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag",
)

WILDCARD_CHARS = ("*", "?", "[")


def _config_files() -> list[Path]:
    in_ash_dir = [
        p for p in ASH_CONFIG_DIR.iterdir() if p.is_file() and p.suffix == ".yaml"
    ]
    return sorted([REPO_ROOT / ".ash.yaml", *in_ash_dir])


def is_directory_glob(path: str) -> bool:
    if "**" in path:
        return True
    *directories, name = path.split("/")
    if any(c in d for d in directories for c in WILDCARD_CHARS):
        return True
    return name != "" and all(c in "*?" for c in name)


def is_guarded_rule(rule_id: str | None) -> bool:
    pattern = rule_id or "*"
    return any(_rule_id_matches(probe, pattern) for probe in PROBE_RULE_IDS)


def broad_guarded_suppressions(config: dict) -> list[dict]:
    suppressions = (config.get("global_settings") or {}).get("suppressions") or []
    return [
        s
        for s in suppressions
        if is_guarded_rule(s.get("rule_id")) and is_directory_glob(s.get("path", ""))
    ]


#: The directory-pattern entries the guard admits, by (rule_id, path), with the
#: reason no file-scoped entry can name their files. Each row is a place where a
#: new finding of its rule goes unreported, so a row names only files a scan
#: writes into its own output, which no commit holds.
WRITTEN_BY_THE_SCAN: dict[tuple[str, str], str] = {
    (
        "SECRET-HEX-HIGH-ENTROPY-STRING",
        f"**/sdist-lock-harvester/{HARVEST_DIR_NAME}/*/*/{HARVEST_MANIFEST_NAME}",
    ): (
        "the provenance manifest the sdist-lock harvester writes beside each "
        "harvested lockfile, one directory per package and version; it records "
        "the sdist's sha256 digest and lives only in a scan's output"
    ),
}


def unallowed_guarded_suppressions(config: dict) -> list[dict]:
    return [
        s
        for s in broad_guarded_suppressions(config)
        if (s.get("rule_id"), s.get("path")) not in WRITTEN_BY_THE_SCAN
    ]


def test_the_repository_ships_config_files_to_check():
    # Without this the parametrized test below collects zero cases and passes.
    names = {p.name for p in _config_files()}
    assert {".ash.yaml", ".ash_alpha_plugins.yaml"} <= names


@pytest.mark.parametrize("config_path", _config_files(), ids=lambda p: p.name)
def test_no_directory_glob_suppresses_secret_or_actions_rules(config_path):
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    offenders = [
        f"{s.get('rule_id') or '*'} on {s['path']}"
        for s in unallowed_guarded_suppressions(config)
    ]
    assert offenders == [], (
        f"{config_path.name} suppresses secret or GitHub Actions findings across a "
        "directory. Mark the line instead (`# pragma: allowlist secret`, "
        "`# nosemgrep: <rule>`), fix the finding, or name the one file with "
        f"line_start/line_end and a reason: {offenders}"
    )


# Negative controls: the predicates above, fed configs whose verdict is known.


@pytest.mark.parametrize(
    "rule_id, path",
    [
        ("SECRET-*", "tests/**"),
        ("SECRET-*", "scripts/**"),
        ("SECRET-SECRET-KEYWORD", "tests/**"),
        ("yaml.github-actions.security.*", ".github/**/*.yml"),
        (
            "yaml.github-actions.security.run-shell-injection.run-shell-injection",
            "ash-agent-plugins/**/.github/**/*.yml",
        ),
        # fnmatch's "*" crosses "/", so these are as broad as "**".
        ("SECRET-*", "tests/*"),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", ".ash/ash_output*/reports/*.json"),
        # A universal rule hides secrets too.
        ("*", "tests/test_data/**"),
        (None, "docs/**"),
    ],
)
def test_a_directory_glob_on_a_guarded_rule_is_reported(rule_id, path):
    entry = {"path": path, "reason": "probe"}
    if rule_id is not None:
        entry["rule_id"] = rule_id
    config = {"global_settings": {"suppressions": [entry]}}
    assert broad_guarded_suppressions(config) == [entry]


@pytest.mark.parametrize(
    "rule_id, path",
    [
        # Line-level and single-file entries are what the guard asks for.
        ("SECRET-SECRET-KEYWORD", "tests/unit/utils/test_secret_masking.py"),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", "scripts/setup-nerdctl-linux.sh"),
        (
            "yaml.github-actions.security.run-shell-injection.run-shell-injection",
            ".github/actions/run-scan-test/action.yml",
        ),
        # A wildcard inside a file name stays within one directory.
        ("SECRET-SECRET-KEYWORD", "tests/unit/utils/test_secret_masking*.py"),
        # Other rule families are out of this guard's scope.
        ("B101", "tests/**/*.py"),
        ("*:MIT", "**"),
    ],
)
def test_a_file_scoped_or_unguarded_entry_is_not_reported(rule_id, path):
    config = {
        "global_settings": {
            "suppressions": [{"rule_id": rule_id, "path": path, "reason": "probe"}]
        }
    }
    assert broad_guarded_suppressions(config) == []


def test_the_guard_reads_a_config_on_disk_the_same_way(tmp_path):
    # The parametrized repository test goes through yaml.safe_load on a real
    # file; prove that path reports a planted entry rather than only the dicts
    # built inline above.
    planted = tmp_path / ".ash.yaml"
    planted.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        '    - rule_id: "SECRET-*"\n'
        '      path: "tests/**"\n'
        '      reason: "planted"\n',
        encoding="utf-8",
    )
    config = yaml.safe_load(planted.read_text(encoding="utf-8"))
    assert [s["path"] for s in broad_guarded_suppressions(config)] == ["tests/**"]


# The allowance: each row admits one rule on one path, and nothing beside it.


@pytest.mark.parametrize("rule_id, path", sorted(WRITTEN_BY_THE_SCAN))
def test_an_allowed_entry_is_a_directory_glob_the_allowance_admits(rule_id, path):
    # A row the guard would not report anyway admits nothing and should go.
    entry = {"rule_id": rule_id, "path": path, "reason": "probe"}
    config = {"global_settings": {"suppressions": [entry]}}
    assert broad_guarded_suppressions(config) == [entry]
    assert unallowed_guarded_suppressions(config) == []


def test_every_allowance_names_an_entry_a_config_carries():
    # A row whose entry is gone would admit the next entry written with that rule
    # and path, without anyone reading it.
    carried = set()
    for config_path in _config_files():
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        carried |= {
            (s.get("rule_id"), s.get("path"))
            for s in broad_guarded_suppressions(config)
        }
    assert set(WRITTEN_BY_THE_SCAN) <= carried


@pytest.mark.parametrize(
    "rule_id, path",
    [
        # Another rule on the allowed path.
        (
            "SECRET-SECRET-KEYWORD",
            f"**/sdist-lock-harvester/{HARVEST_DIR_NAME}/*/*/{HARVEST_MANIFEST_NAME}",
        ),
        # The allowed rule on a wider path.
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            f"**/sdist-lock-harvester/{HARVEST_DIR_NAME}/**/{HARVEST_MANIFEST_NAME}",
        ),
        ("SECRET-HEX-HIGH-ENTROPY-STRING", f"**/{HARVEST_MANIFEST_NAME}"),
    ],
)
def test_an_entry_beside_an_allowance_is_still_reported(rule_id, path):
    entry = {"rule_id": rule_id, "path": path, "reason": "probe"}
    config = {"global_settings": {"suppressions": [entry]}}
    assert unallowed_guarded_suppressions(config) == [entry]
