# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: hand-authored dependency declarations must be scanned.

The detect-secrets scanner drops files from its scan set *before* handing anything
to detect-secrets. That pre-filter used to be driven by a single list,
``KNOWN_LOCKFILE_NAMES``, which mixed machine-generated locks together with files a
human types -- ``requirements.txt``, ``Pipfile``, ``environment.yml``. A credential
in one of those was therefore never read at all.

That is worse than a suppressed finding. The pre-filter runs upstream of the
baseline's ``filters_used``, of ``global_ignore_paths``, and of every severity
threshold, and nothing downstream re-adds a file -- so no configuration could
recover it. The scan still succeeded and still exited 0; the only symptom was a
credential nobody ever heard about. These tests pin the split so the lists cannot
be re-merged without a failure.

The canonical case is a private index URL carrying inline basic-auth credentials,
which is a real shape in real requirements files and exactly what the pre-filter
hid.
"""

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import (
    KNOWN_DEPENDENCY_DECLARATION_NAMES,
    KNOWN_GENERATED_LOCKFILE_NAMES,
    KNOWN_LOCKFILE_NAMES,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)

# An obviously-fake credential in a private-index URL. detect-secrets' Basic Auth
# Credentials plugin is what fires on it.
_FAKE_INDEX_URL = "https://fake-user:fake-token-not-real@pypi.example.com/simple"  # pragma: allowlist secret


def _scanner(source_dir: Path, output_dir: Path) -> DetectSecretsScanner:
    return DetectSecretsScanner(
        context=PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=output_dir / "converted",
            config=get_default_config(),
        ),
        config=DetectSecretsScannerConfig(),
    )


def _scan(tmp_path: Path, files: dict, **options) -> int:
    """Write *files* into a fresh source tree, scan it, return the finding count."""
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    source_dir.mkdir()
    output_dir.mkdir()
    for name, body in files.items():
        (source_dir / name).write_text(body)

    scanner = _scanner(source_dir, output_dir)
    for key, value in options.items():
        setattr(scanner.config.options, key, value)

    report = scanner.scan(target=source_dir, target_type="source")
    assert report is not False, "scan did not run"
    return sum(len(v) for v in scanner._secrets_collection.data.values())


@pytest.mark.parametrize(
    "filename, body",
    [
        ("requirements.txt", f"flask==3.0.0\n--extra-index-url {_FAKE_INDEX_URL}\n"),
        (
            "Pipfile",
            (
                f'[[source]]\nurl = "{_FAKE_INDEX_URL}"\nverify_ssl = true\n\n'
                '[packages]\nflask = "*"\n'
            ),
        ),
        ("environment.yml", f"name: demo\nchannel_alias: {_FAKE_INDEX_URL}\n"),
    ],
)
def test_credential_in_a_hand_authored_declaration_is_reported(
    tmp_path, filename, body
):
    """The defect this change fixes. Each of these returned 0 before the split.

    ``environment.yml`` uses a mapping value rather than a ``channels:`` sequence
    item on purpose: detect-secrets' YAML transformer only yields scalars that have
    a key, so a credential written as a bare sequence item is missed upstream of
    ASH entirely. That is a detect-secrets limitation, not this pre-filter, and a
    fixture written in sequence form would fail here for an unrelated reason.
    """
    assert _scan(tmp_path, {filename: body}) == 1


def test_generated_lockfile_is_still_skipped(tmp_path):
    """The other half of the split: generated locks stay out by default.

    ``npm-shrinkwrap.json`` is the load-bearing choice. detect-secrets' own
    ``heuristic.is_lock_file`` does not know this name and its extension is not in
    ``is_non_text_file``, so a zero here measures ASH's exclusion list rather than
    passing vacuously on a detect-secrets default.
    """
    body = '{"name": "demo", "dependencies": {"x": {"resolved": "%s"}}}\n' % (
        _FAKE_INDEX_URL
    )
    assert _scan(tmp_path, {"npm-shrinkwrap.json": body}) == 0


def test_the_lever_re_admits_generated_lockfiles(tmp_path):
    """``skip_generated_lockfiles=False`` makes the residual exclusion recoverable.

    Before this option existed the exclusion could not be turned off by any
    configuration at all, because it ran ahead of everything that reads
    configuration.
    """
    body = '{"name": "demo", "dependencies": {"x": {"resolved": "%s"}}}\n' % (
        _FAKE_INDEX_URL
    )
    found = _scan(
        tmp_path, {"npm-shrinkwrap.json": body}, skip_generated_lockfiles=False
    )
    assert found > 0, "flipping the lever did not re-admit the file"


def test_hash_pinned_requirements_file_does_not_flood(tmp_path):
    """False-positive control for the newly-scanned side.

    A ``--require-hashes`` requirements file is the realistic noise risk created by
    scanning requirements.txt: dozens of 64-character hex digests, which is the
    shape entropy detectors fire on. detect-secrets' own default heuristics already
    discount them, and this pins that -- if a future change starts reporting them,
    the split has become a noise source and needs revisiting rather than silently
    shipping.
    """
    lines = ["requests==2.31.0 \\"]
    lines += [
        "    --hash=sha256:%064x \\" % (0xABCDEF0123456789 + i) for i in range(30)
    ]
    lines += ["    --hash=sha256:%064x" % 0xFEEDFACE]
    assert _scan(tmp_path, {"requirements.txt": "\n".join(lines)}) == 0


def test_the_two_lists_stay_disjoint():
    """A name may be generated or hand-authored, never both.

    A name landing in both lists would read as excluded, because the pre-filter
    only consults the generated list -- so the declaration list would silently stop
    meaning anything for that file.
    """
    overlap = set(KNOWN_GENERATED_LOCKFILE_NAMES) & set(
        KNOWN_DEPENDENCY_DECLARATION_NAMES
    )
    assert overlap == set(), f"names classified as both: {sorted(overlap)}"


def test_hand_authored_names_are_not_in_the_exclusion_list():
    """The defect stated as a property, independent of any one fixture."""
    for name in ("requirements.txt", "Pipfile", "environment.yml", "environment.yaml"):
        assert name in KNOWN_DEPENDENCY_DECLARATION_NAMES
        assert name not in KNOWN_GENERATED_LOCKFILE_NAMES


def test_compatibility_alias_still_holds_the_original_merged_value():
    """``KNOWN_LOCKFILE_NAMES`` is imported by out-of-tree plugins, so it keeps its
    old contents. It is deprecated and ASH itself must not filter on it."""
    assert set(KNOWN_LOCKFILE_NAMES) == set(KNOWN_GENERATED_LOCKFILE_NAMES) | set(
        KNOWN_DEPENDENCY_DECLARATION_NAMES
    )
    assert len(KNOWN_LOCKFILE_NAMES) == 16
