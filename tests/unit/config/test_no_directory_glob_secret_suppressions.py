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

The sdist-lock harvest manifests
--------------------------------
The sdist-lock harvester writes a provenance manifest (``harvest-manifest.json``)
beside each lockfile it extracts, and the default self-scan's hex detector reports
the sdist's sha256 digest in every one of them. ``.ash.yaml`` suppresses that, one
entry per manifest and each pinned to a line, because a secret rule may not be
suppressed by a directory glob (the guard above).

A manifest is reported by the path of the scan that wrote it, and a glob-free
pattern matches only the path it spells, so each manifest has two entries. A scan
that writes the default output directory, ``.ash/ash_output`` inside the scanned
tree, reports ``.ash/ash_output/converted/...``. A container scan runs the scan
inside the image with ``--source-dir /src --output-dir /out``. The output
directory is outside the source directory, so a converted file there keeps its
absolute path, and nothing strips ``/out`` from it: the scan reports
``/out/converted/...``. With only the first entries, every container scan of the
self-scan that reaches the harvest reports each manifest as an actionable secret.

The pin is a line number, and nothing tied it to the code that decides the line.
``HarvestManifest.to_json`` writes the digest on line 6 today. A key added or moved
above ``sdist_sha256`` moves it, and every entry then excuses a line that holds no
finding while the digest is reported again. A pin that excuses nothing reads the
same in the config as one that works.

What the manifest checks do
~~~~~~~~~~~~~~~~~~~~~~~~~~~
* ``.ash.yaml`` carries at least one such entry, so the checks below do not pass
  over nothing.
* Each entry's ``line_start`` and ``line_end`` are both the line of the digest in
  the manifest ``to_json`` writes, found by serializing a real manifest. A failure
  names the line to use.
* Each entry names one manifest file in the harvest layout of one of the two output
  directories, spelled from the product's own names: no wildcard, and a package and
  a version that are single path components the harvest itself would accept.
* Every manifest has an entry for each output directory, with the same rule and the
  same lines.
* The product's own matcher, given the config's suppressions, suppresses a hex
  finding on the digest line of each manifest, at the path a scan that wrote under
  either output directory reports, by the entry that names that path. The same
  finding one line above and one line below the digest, and a finding of another
  rule on the digest line, are not suppressed. A finding is shaped as detect-secrets
  reports one (the rule id, the path, and the one line as both start and end) and is
  also put with no end, which the matcher reads as a one-line finding. Only
  synthetic findings are matched; no scanner runs.
* The container output directory written here is the one the product passes to the
  scan inside the image.

What the manifest checks do not cover
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
That each named package and version is still in a lock file, or that every
manifest a self-scan reports has an entry. The first would fail an entry added
ahead of a version bump, which is the order the comment above the entries asks for
(the required self-scan reads ``.ash.yaml`` from the pull request's base commit).
The second needs the sdists, which only a scan fetches. Nor do they cover another
output directory: the manual pre-commit hook writes to
``.ash/ash_output_precommit_local``.
"""

import ast
import functools
import hashlib
import json
from collections import Counter
from pathlib import Path, PurePosixPath

import pytest
import yaml

from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.converters.sdist_lock_harvester import (
    SdistLockHarvesterConverterConfig,
)
from automated_security_helper.utils.scan_output_dirs import (
    CONTAINER_SOURCE_MOUNT,
    DEFAULT_OUTPUT_RELATIVE,
)
from automated_security_helper.utils.sdist_harvest import (
    HARVEST_DIR_NAME,
    HARVEST_MANIFEST_NAME,
    PACKAGE_IDENTIFIER_RE,
    HarvestManifest,
)
from automated_security_helper.utils.suppression_matcher import (
    _rule_id_matches,
    should_suppress_finding,
)

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


def test_the_repository_ships_config_files_to_check():
    # Without this the parametrized test below collects zero cases and passes.
    names = {p.name for p in _config_files()}
    assert {".ash.yaml", ".ash_alpha_plugins.yaml"} <= names


@pytest.mark.parametrize("config_path", _config_files(), ids=lambda p: p.name)
def test_no_directory_glob_suppresses_secret_or_actions_rules(config_path):
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    offenders = [
        f"{s.get('rule_id') or '*'} on {s['path']}"
        for s in broad_guarded_suppressions(config)
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
        # The glob that once covered every sdist-lock harvest manifest; each
        # manifest is named in its own entry now.
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            "**/sdist-lock-harvester/sdist-locks/**/harvest-manifest.json",
        ),
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
        # One harvest manifest, named in full: a file, not a directory.
        (
            "SECRET-HEX-HIGH-ENTROPY-STRING",
            ".ash/ash_output/converted/sdist-lock-harvester/sdist-locks/ruff/0.16.10/harvest-manifest.json",
        ),
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


# The sdist-lock harvest manifests, the second section of the docstring.

CONTAINER_RUNNER = (
    REPO_ROOT / "automated_security_helper" / "interactions" / "run_ash_container.py"
)
CONFIGS = (".ash.yaml", ".ash/.ash_alpha_plugins.yaml")
#: Only the default config's scan runs detect-secrets and the harvester together,
#: so only it must carry the entries.
CONFIG_WITH_THE_ENTRIES = ".ash.yaml"

RULE = "SECRET-HEX-HIGH-ENTROPY-STRING"

#: What follows the output directory in the path of a harvested file:
#: ``converted/sdist-lock-harvester/sdist-locks``.
HARVEST_TAIL = (
    f"{ASH_WORK_DIR_NAME}/{SdistLockHarvesterConverterConfig().name}/{HARVEST_DIR_NAME}"
)

#: The directory every harvested package's files land in, for a scan whose output
#: directory is the default, inside the scanned tree:
#: ``.ash/ash_output/converted/sdist-lock-harvester/sdist-locks``.
HARVEST_ROOT = f"{DEFAULT_OUTPUT_RELATIVE.as_posix()}/{HARVEST_TAIL}"

#: The output directory of a container scan. The launcher mounts the host's output
#: directory at ``/out`` and runs the scan inside the image with
#: ``--output-dir /out`` (``_assemble_run_command`` in
#: interactions/run_ash_container.py). The product writes it as a literal and gives
#: it no name, so it is written here, and
#: test_the_container_run_still_writes_to_the_directory_the_entries_name reads the
#: product's source for it: a change there turns this red, instead of leaving
#: entries for a directory no scan writes to.
CONTAINER_OUTPUT_DIR = "/out"

#: The same harvest directory for a container scan. The output is outside the
#: source directory, so the scan reports a harvested file by its absolute path.
CONTAINER_HARVEST_ROOT = f"{CONTAINER_OUTPUT_DIR}/{HARVEST_TAIL}"

HARVEST_ROOTS = (HARVEST_ROOT, CONTAINER_HARVEST_ROOT)


def manifest_path(root: str, package: str, version: str) -> str:
    """The path of one package version's manifest under a harvest root."""
    return f"{root}/{package}/{version}/{HARVEST_MANIFEST_NAME}"


EXAMPLE_PATH = manifest_path(HARVEST_ROOT, "ruff", "0.16.10")
CONTAINER_EXAMPLE_PATH = manifest_path(CONTAINER_HARVEST_ROOT, "ruff", "0.16.10")


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


def manifest_identity(path: str) -> tuple[str, str, str] | None:
    """``(harvest root, package, version)`` when ``path`` names one manifest, else None.

    One manifest is ``<harvest root>/<package>/<version>/harvest-manifest.json``
    under the root of the default output directory or of the container's, with a
    package and a version that are each one path component the harvest accepts.
    """
    tail = f"/{HARVEST_MANIFEST_NAME}"
    for root in HARVEST_ROOTS:
        head = f"{root}/"
        if not (path.startswith(head) and path.endswith(tail)):
            continue
        parts = path[len(head) : -len(tail)].split("/")
        if len(parts) == 2 and all(PACKAGE_IDENTIFIER_RE.fullmatch(p) for p in parts):
            return root, parts[0], parts[1]
    return None


def names_one_manifest(path: str) -> bool:
    """Whether ``path`` is one manifest's file under either harvest root."""
    return manifest_identity(path) is not None


def manifest_pins(config: dict) -> dict[str, Counter]:
    """What the entries that name one manifest pin, counted for each harvest root.

    A pin is ``(package, version, rule_id, line_start, line_end)``. An entry that
    names no one manifest (a wildcard, another directory) is left to the check of
    its path.
    """
    pins: dict[str, Counter] = {root: Counter() for root in HARVEST_ROOTS}
    for entry in manifest_secret_entries(config):
        identity = manifest_identity(str(entry.get("path") or ""))
        if identity is None:
            continue
        root, package, version = identity
        pin = (
            package,
            version,
            entry.get("rule_id"),
            entry.get("line_start"),
            entry.get("line_end"),
        )
        pins[root][pin] += 1
    return pins


def named_manifests(config: dict, root: str) -> list[tuple[str, str]]:
    """The ``(package, version)`` of each manifest an entry names under ``root``."""
    return sorted({(pin[0], pin[1]) for pin in manifest_pins(config)[root]})


def unpaired_manifests(config: dict) -> list[str]:
    """One message per pin held under one harvest root and not, alike, under the other.

    A manifest is reported under the output directory of the scan that wrote it, so
    each needs an entry for each root, with the same rule and the same lines.
    """
    pins = manifest_pins(config)
    default, container = HARVEST_ROOT, CONTAINER_HARVEST_ROOT
    messages = []
    for root, other in ((default, container), (container, default)):
        for package, version, rule_id, start, end in sorted(
            pins[root] - pins[other], key=repr
        ):
            messages.append(
                f"{package} {version} ({rule_id or '*'}, lines {start}-{end}) is "
                f"pinned under {root} and not the same way under {other}"
            )
    return messages


def suppressions_of(config: dict) -> list[AshSuppression]:
    """The config's suppressions as the model that applies them reads them."""
    entries = (config.get("global_settings") or {}).get("suppressions") or []
    return [AshSuppression.model_validate(entry) for entry in entries]


def hex_finding(
    path: str, line: int, rule_id: str = RULE, *, with_line_end: bool = True
) -> FlatVulnerability:
    """A synthetic finding of ``rule_id`` at ``line`` of ``path``. No scanner runs.

    Shaped as detect-secrets reports a hex finding and the suppression step hands it
    to the matcher: the rule id the scanner names, the path it reports, and the line
    as both start and end, because the scanner's region sets ``startLine`` and
    ``endLine`` to it (``build_secret_result`` in
    plugin_modules/ash_builtin/scanners/detect_secrets_scanner.py) and
    ``apply_suppressions_to_sarif`` copies both onto the finding
    (utils/sarif_utils.py). ``with_line_end=False`` leaves the end out, as a scanner
    that wrote no ``endLine`` would; the matcher reads such a finding as one on its
    start line (``_line_ok`` in utils/suppression_frame.py).
    """
    return FlatVulnerability(
        id=f"synthetic-{rule_id}-{path}-{line}",
        title="High entropy string",
        description="Synthetic finding for the harvest manifest suppression check.",
        severity="HIGH",
        scanner="detect-secrets",
        scanner_type="SECRET",
        rule_id=rule_id,
        file_path=path,
        line_start=line,
        line_end=line if with_line_end else None,
    )


def reported_manifests(config: dict) -> list[tuple[str, str]]:
    """The ``(package, version)`` of each manifest an entry names under either root."""
    return sorted(
        {pair for root in HARVEST_ROOTS for pair in named_manifests(config, root)}
    )


def matcher_verdicts(
    config: dict,
    line: int,
    *,
    rule_id: str = RULE,
    with_line_end: bool = True,
    roots: tuple[str, ...] = HARVEST_ROOTS,
    suppressions: list[AshSuppression] | None = None,
) -> dict[str, str | None]:
    """What the product's matcher does with a finding at each reported manifest path.

    For each manifest an entry of ``config`` names, under either harvest root, and
    for each of ``roots``, a hex finding on ``line`` at the path a scan reports for
    it is put to ``should_suppress_finding`` with the config's suppressions
    (``suppressions``, when the caller has them built already). The answer maps that
    path to the path of the entry that suppressed it, or to None when none did. Only
    synthetic findings are matched; no scanner runs.
    """
    entries = suppressions_of(config) if suppressions is None else suppressions
    verdicts: dict[str, str | None] = {}
    for package, version in reported_manifests(config):
        for root in roots:
            path = manifest_path(root, package, version)
            suppressed, entry = should_suppress_finding(
                hex_finding(path, line, rule_id, with_line_end=with_line_end), entries
            )
            verdicts[path] = entry.path if suppressed and entry is not None else None
    return verdicts


def left_reported(verdicts: dict[str, str | None]) -> list[str]:
    """The paths no entry that names them suppresses: nothing does, or another entry."""
    return [path for path, entry_path in verdicts.items() if entry_path != path]


def suppressed_paths(verdicts: dict[str, str | None]) -> list[str]:
    """The paths the matcher suppresses, by whichever entry."""
    return [path for path, entry_path in verdicts.items() if entry_path is not None]


def container_manifests_left_reported(config: dict, line: int) -> list[str]:
    """The container spelling of each named manifest its own entry does not suppress.

    For each package version the entries name, a hex finding on ``line`` at the path
    a container scan reports is put to the product's own matcher with the config's
    suppressions. It is left reported when nothing suppresses it, or when something
    other than the entry that names that path does: a directory glob would also cover
    it, and is what the guard at the top of this file refuses.
    """
    return left_reported(
        matcher_verdicts(config, line, roots=(CONTAINER_HARVEST_ROOT,))
    )


@functools.cache
def _config(name: str) -> dict:
    return yaml.safe_load((REPO_ROOT / name).read_text(encoding="utf-8")) or {}


@functools.cache
def repository_suppressions() -> tuple[AshSuppression, ...]:
    return tuple(suppressions_of(_config(CONFIG_WITH_THE_ENTRIES)))


def _a_named_manifest() -> tuple[str, str]:
    named = named_manifests(_config(CONFIG_WITH_THE_ENTRIES), HARVEST_ROOT)
    assert named, f"{CONFIG_WITH_THE_ENTRIES} names no manifest under {HARVEST_ROOT}"
    return named[0]


def _entry(path: str = EXAMPLE_PATH, **fields) -> dict:
    return {"rule_id": RULE, "path": path, "reason": "probe", **fields}


def _config_of(*entries: dict) -> dict:
    return {"global_settings": {"suppressions": list(entries)}}


def _repository_verdicts(line: int, **shape) -> dict[str, str | None]:
    """``matcher_verdicts`` for the repository's own config and suppressions."""
    return matcher_verdicts(
        _config(CONFIG_WITH_THE_ENTRIES),
        line,
        suppressions=list(repository_suppressions()),
        **shape,
    )


#: What a finding carries for the end of its line range: what detect-secrets reports
#: (the line again) and none, which the matcher reads as a one-line finding.
LINE_END_SHAPES = pytest.mark.parametrize(
    "with_line_end", [True, False], ids=["line_end set", "line_end unset"]
)

#: The scan whose output directory each harvest root is.
SCAN_OF_ROOT = {HARVEST_ROOT: "default", CONTAINER_HARVEST_ROOT: "container"}


def _assert_each_manifest_suppressed(root: str, with_line_end: bool) -> None:
    config = _config(CONFIG_WITH_THE_ENTRIES)
    named = reported_manifests(config)
    assert named, (
        f"{CONFIG_WITH_THE_ENTRIES} names no manifest under {HARVEST_ROOT} or "
        f"{CONTAINER_HARVEST_ROOT}; the check below would pass over nothing"
    )
    scan = SCAN_OF_ROOT[root]
    left = left_reported(
        _repository_verdicts(digest_line(), roots=(root,), with_line_end=with_line_end)
    )
    assert left == [], (
        f"{len(named) - len(left)} of {len(named)} manifests are suppressed, by the "
        f"entry that names them, at the path a {scan} scan reports. The {scan} "
        f"scans of the self-scan report the rest as secrets: {left}"
    )


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
        f"{name}: a manifest entry must be <harvest root>/<package>/<version>/"
        f"{HARVEST_MANIFEST_NAME}, one file, no wildcard, with the harvest root "
        f"{HARVEST_ROOT} or {CONTAINER_HARVEST_ROOT}: {elsewhere}"
    )


@pytest.mark.parametrize("name", CONFIGS)
def test_every_manifest_is_pinned_under_both_output_directories(name):
    unpaired = unpaired_manifests(_config(name))
    assert unpaired == [], (
        f"{name}: a manifest is reported under the output directory of the scan "
        f"that wrote it, so each needs an entry under {HARVEST_ROOT} and one under "
        f"{CONTAINER_HARVEST_ROOT}, with the same rule and the same lines: "
        f"{unpaired}"
    )


# The product's own matcher, given the finding a scan reports for each manifest the
# entries name, once for each output directory and each shape of the line range.


@LINE_END_SHAPES
def test_a_default_scan_finds_each_manifest_suppressed(with_line_end):
    _assert_each_manifest_suppressed(HARVEST_ROOT, with_line_end)


@LINE_END_SHAPES
def test_a_container_scan_finds_each_manifest_suppressed(with_line_end):
    _assert_each_manifest_suppressed(CONTAINER_HARVEST_ROOT, with_line_end)


def test_the_container_run_still_writes_to_the_directory_the_entries_name():
    tree = ast.parse(CONTAINER_RUNNER.read_text(encoding="utf-8"))
    passed = {
        value.value if isinstance(value, ast.Constant) else "<not a literal>"
        for node in ast.walk(tree)
        if isinstance(node, ast.List)
        for flag, value in zip(node.elts, node.elts[1:])
        if isinstance(flag, ast.Constant) and flag.value == "--output-dir"
    }
    mounted = any(
        isinstance(piece, ast.Constant)
        and piece.value == f",destination={CONTAINER_OUTPUT_DIR}"
        for node in ast.walk(tree)
        if isinstance(node, ast.JoinedStr)
        for piece in node.values
    )
    assert passed == {CONTAINER_OUTPUT_DIR}, (
        f"{CONTAINER_RUNNER.name} passes --output-dir {sorted(passed, key=str)} to "
        f"the scan inside the image, and these entries and CONTAINER_OUTPUT_DIR "
        f"name {CONTAINER_OUTPUT_DIR}. Change the suppression entries for "
        f"{CONTAINER_HARVEST_ROOT} to the new directory, and this constant"
    )
    assert mounted, (
        f"{CONTAINER_RUNNER.name} no longer mounts the host's output directory at "
        f"{CONTAINER_OUTPUT_DIR}, so the scan inside the image writes its output "
        "somewhere the entries do not name"
    )
    assert not PurePosixPath(CONTAINER_OUTPUT_DIR).is_relative_to(
        CONTAINER_SOURCE_MOUNT
    ), (
        f"{CONTAINER_OUTPUT_DIR} is inside the source mount {CONTAINER_SOURCE_MOUNT}, "
        "so a converted file there is reported relative to the source and not by an "
        "absolute path: the container spelling is the default one"
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
        ("SECRET-AWS-ACCESS-KEY", CONTAINER_EXAMPLE_PATH),
        # The hex rule in another file.
        (RULE, f"{HARVEST_ROOT}/ruff/0.16.10/Cargo.lock"),
        (RULE, f"{CONTAINER_HARVEST_ROOT}/ruff/0.16.10/Cargo.lock"),
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
        # The container scan's spelling of the same manifests.
        (CONTAINER_EXAMPLE_PATH, True),
        (manifest_path(CONTAINER_HARVEST_ROOT, "polars-runtime-32", "1.44.2"), True),
        # A wildcard anywhere is not one file.
        (f"{HARVEST_ROOT}/*/0.16.10/{HARVEST_MANIFEST_NAME}", False),
        (f"{HARVEST_ROOT}/ruff/*/{HARVEST_MANIFEST_NAME}", False),
        (f"{HARVEST_ROOT}/**/{HARVEST_MANIFEST_NAME}", False),
        (f"**/{HARVEST_DIR_NAME}/ruff/0.16.10/{HARVEST_MANIFEST_NAME}", False),
        (f"{CONTAINER_HARVEST_ROOT}/*/0.16.10/{HARVEST_MANIFEST_NAME}", False),
        (f"{CONTAINER_HARVEST_ROOT}/ruff/*/{HARVEST_MANIFEST_NAME}", False),
        (f"{CONTAINER_OUTPUT_DIR}/**/{HARVEST_MANIFEST_NAME}", False),
        # A package or version that is not one path component.
        (f"{HARVEST_ROOT}/ruff/{HARVEST_MANIFEST_NAME}", False),
        (f"{HARVEST_ROOT}/a/b/c/{HARVEST_MANIFEST_NAME}", False),
        (f"{CONTAINER_HARVEST_ROOT}/ruff/{HARVEST_MANIFEST_NAME}", False),
        (f"{CONTAINER_HARVEST_ROOT}/a/b/c/{HARVEST_MANIFEST_NAME}", False),
        # Another output directory is neither the default's nor the container's.
        (
            f"out/converted/x/{HARVEST_DIR_NAME}/ruff/0.16.10/{HARVEST_MANIFEST_NAME}",
            False,
        ),
        (f"out/{HARVEST_TAIL}/ruff/0.16.10/{HARVEST_MANIFEST_NAME}", False),
        (f"/outside/{HARVEST_TAIL}/ruff/0.16.10/{HARVEST_MANIFEST_NAME}", False),
        # Another file in the same directory.
        (f"{HARVEST_ROOT}/ruff/0.16.10/Cargo.lock", False),
        (f"{CONTAINER_HARVEST_ROOT}/ruff/0.16.10/Cargo.lock", False),
    ],
)
def test_names_one_manifest_reads_the_path_shape(path, expected):
    assert names_one_manifest(path) is expected


def test_a_manifest_pinned_under_both_output_directories_is_paired():
    line = digest_line()
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line, line_end=line),
        _entry(CONTAINER_EXAMPLE_PATH, line_start=line, line_end=line),
    )
    assert unpaired_manifests(config) == []


@pytest.mark.parametrize("root", HARVEST_ROOTS)
def test_a_manifest_pinned_under_one_output_directory_only_is_reported(root):
    line = digest_line()
    config = _config_of(
        _entry(
            manifest_path(root, "ruff", "0.16.10"),
            line_start=line,
            line_end=line,
        )
    )
    unpaired = unpaired_manifests(config)
    assert len(unpaired) == 1
    assert "ruff 0.16.10" in unpaired[0]


@pytest.mark.parametrize(
    "start_shift, end_shift, rule_id",
    [
        (-1, -1, RULE),  # another line
        (0, 1, RULE),  # a wider range
        (0, 0, "SECRET-*"),  # another spelling of the rule
    ],
)
def test_a_container_entry_that_pins_differently_is_reported_on_both_sides(
    start_shift, end_shift, rule_id
):
    line = digest_line()
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line, line_end=line),
        _entry(
            CONTAINER_EXAMPLE_PATH,
            rule_id=rule_id,
            line_start=line + start_shift,
            line_end=line + end_shift,
        ),
    )
    assert len(unpaired_manifests(config)) == 2


def test_a_container_entry_for_another_version_is_reported_on_both_sides():
    # What a version bump that changes one spelling and not the other leaves.
    line = digest_line()
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line, line_end=line),
        _entry(
            manifest_path(CONTAINER_HARVEST_ROOT, "ruff", "0.16.11"),
            line_start=line,
            line_end=line,
        ),
    )
    assert len(unpaired_manifests(config)) == 2


def test_the_check_reports_a_manifest_only_the_default_spelling_suppresses():
    line = digest_line()
    config = _config_of(_entry(EXAMPLE_PATH, line_start=line, line_end=line))
    assert container_manifests_left_reported(config, line) == [CONTAINER_EXAMPLE_PATH]


def test_the_check_reports_a_manifest_only_the_container_spelling_suppresses():
    # The other way round: the default scan's spelling has no entry.
    line = digest_line()
    config = _config_of(_entry(CONTAINER_EXAMPLE_PATH, line_start=line, line_end=line))
    verdicts = matcher_verdicts(config, line, roots=(HARVEST_ROOT,))
    assert left_reported(verdicts) == [EXAMPLE_PATH]


def test_the_check_passes_a_manifest_both_spellings_suppress():
    line = digest_line()
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line, line_end=line),
        _entry(CONTAINER_EXAMPLE_PATH, line_start=line, line_end=line),
    )
    assert container_manifests_left_reported(config, line) == []


@LINE_END_SHAPES
def test_the_digest_line_pin_suppresses_the_finding_in_either_end_shape(with_line_end):
    line = digest_line()
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line, line_end=line),
        _entry(CONTAINER_EXAMPLE_PATH, line_start=line, line_end=line),
    )
    verdicts = matcher_verdicts(config, line, with_line_end=with_line_end)
    assert verdicts == {
        EXAMPLE_PATH: EXAMPLE_PATH,
        CONTAINER_EXAMPLE_PATH: CONTAINER_EXAMPLE_PATH,
    }


@LINE_END_SHAPES
@pytest.mark.parametrize("shift", [-1, 1])
def test_the_check_reports_a_manifest_pinned_to_another_line(shift, with_line_end):
    # What a digest that moved by one line leaves: every entry excuses a line that
    # holds no finding, whichever way the finding's own range is written.
    line = digest_line()
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line + shift, line_end=line + shift),
        _entry(CONTAINER_EXAMPLE_PATH, line_start=line + shift, line_end=line + shift),
    )
    verdicts = matcher_verdicts(config, line, with_line_end=with_line_end)
    assert left_reported(verdicts) == [EXAMPLE_PATH, CONTAINER_EXAMPLE_PATH]
    assert suppressed_paths(verdicts) == []


def test_the_check_reports_a_manifest_only_a_directory_glob_suppresses():
    # The glob suppresses the container spelling through the matcher, which is
    # what made the finding read as covered before each manifest had its entries.
    # The check asks for the entry that names the path, so it is still reported.
    line = digest_line()
    glob = (
        f"**/{SdistLockHarvesterConverterConfig().name}/{HARVEST_DIR_NAME}/"
        f"**/{HARVEST_MANIFEST_NAME}"
    )
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line, line_end=line),
        _entry(glob, line_start=line, line_end=line),
    )
    suppressed, _ = should_suppress_finding(
        hex_finding(CONTAINER_EXAMPLE_PATH, line), suppressions_of(config)
    )
    assert suppressed
    assert container_manifests_left_reported(config, line) == [CONTAINER_EXAMPLE_PATH]


@LINE_END_SHAPES
@pytest.mark.parametrize(
    "start, end, shift, covered",
    [
        # The pin is given as lines from the digest line, so the rows hold wherever
        # the serializer puts the digest.
        (-1, 1, -1, True),  # a range around the digest line holds the line above
        (-1, 1, 1, True),  # and the line below
        (None, None, -1, True),  # no pin: the whole file
        (None, None, 1, True),
        (0, None, 1, True),  # open ended: from the digest line to the end of the file
        (0, None, -1, False),
        (0, 0, -1, False),  # the pin the entries carry
        (0, 0, 1, False),
    ],
)
def test_the_neighbor_check_reads_the_pin(start, end, shift, covered, with_line_end):
    # What the check on the lines beside the digest tells a pin that is too wide
    # from the one the entries carry.
    line = digest_line()
    pin = {}
    if start is not None:
        pin["line_start"] = line + start
    if end is not None:
        pin["line_end"] = line + end
    config = _config_of(
        _entry(EXAMPLE_PATH, **pin),
        _entry(CONTAINER_EXAMPLE_PATH, **pin),
    )
    verdicts = matcher_verdicts(config, line + shift, with_line_end=with_line_end)
    expected = [EXAMPLE_PATH, CONTAINER_EXAMPLE_PATH] if covered else []
    assert suppressed_paths(verdicts) == expected


@LINE_END_SHAPES
@pytest.mark.parametrize(
    "rule_id, shift",
    [
        (RULE, -1),  # the line above the digest
        (RULE, 1),  # the line below it
        ("SECRET-AWS-ACCESS-KEY", 0),  # another rule on the digest line
    ],
)
def test_a_finding_beside_a_named_manifests_pin_stays_reported(
    rule_id, shift, with_line_end
):
    line = digest_line() + shift
    verdicts = _repository_verdicts(line, rule_id=rule_id, with_line_end=with_line_end)
    assert verdicts, (
        f"{CONFIG_WITH_THE_ENTRIES} names no manifest under {HARVEST_ROOT} or "
        f"{CONTAINER_HARVEST_ROOT}; the check below would pass over nothing"
    )
    suppressed = {path: by for path, by in verdicts.items() if by is not None}
    assert suppressed == {}, (
        f"{rule_id} on line {line} is suppressed at {len(suppressed)} of "
        f"{len(verdicts)} manifest paths, by the entry given for each: {suppressed}"
    )


def test_a_version_no_entry_names_stays_reported_at_the_container_spelling():
    package, _ = _a_named_manifest()
    version = "0.0.0"
    named = named_manifests(_config(CONFIG_WITH_THE_ENTRIES), HARVEST_ROOT)
    assert (package, version) not in named
    path = manifest_path(CONTAINER_HARVEST_ROOT, package, version)
    suppressed, entry = should_suppress_finding(
        hex_finding(path, digest_line()), list(repository_suppressions())
    )
    assert not suppressed, f"{path} is suppressed by {entry and entry.path}"


def test_a_package_no_entry_names_stays_reported_at_the_container_spelling():
    package, version = "not-a-harvested-package", "1.0.0"
    named = named_manifests(_config(CONFIG_WITH_THE_ENTRIES), HARVEST_ROOT)
    assert (package, version) not in named
    path = manifest_path(CONTAINER_HARVEST_ROOT, package, version)
    suppressed, entry = should_suppress_finding(
        hex_finding(path, digest_line()), list(repository_suppressions())
    )
    assert not suppressed, f"{path} is suppressed by {entry and entry.path}"
