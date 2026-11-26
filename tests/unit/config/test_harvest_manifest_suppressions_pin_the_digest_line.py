"""The secret suppressions for the sdist-lock harvest manifests pin the digest line.

Why this exists
---------------
The sdist-lock harvester writes a provenance manifest (``harvest-manifest.json``)
beside each lockfile it extracts, and the default self-scan's hex detector reports
the sdist's sha256 digest in every one of them. ``.ash.yaml`` suppresses that, one
entry per manifest and each pinned to a line, because a secret rule may not be
suppressed by a directory glob (test_no_directory_glob_secret_suppressions.py).

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

What this checks
----------------
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
  finding on the digest line at the container spelling of each manifest, by the
  entry that names that path. Only synthetic findings are matched; no scanner runs.
* The container output directory written here is the one the product passes to the
  scan inside the image.

What it does not check
----------------------
That each named package and version is still in a lock file, or that every
manifest a self-scan reports has an entry. The first would fail an entry added
ahead of a version bump, which is the order the comment above the entries asks for
(the required self-scan reads ``.ash.yaml`` from the pull request's base commit).
The second needs the sdists, which only a scan fetches. Nor does it cover another
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


def hex_finding(path: str, line: int, rule_id: str = RULE) -> FlatVulnerability:
    """A synthetic finding of ``rule_id`` at ``line`` of ``path``. No scanner runs."""
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
        line_end=line,
    )


def container_manifests_left_reported(config: dict, line: int) -> list[str]:
    """The container spelling of each named manifest its own entry does not suppress.

    For each package version the entries name under the default output directory, a
    hex finding on ``line`` at the path a container scan reports is put to the
    product's own matcher with the config's suppressions. It is left reported when
    nothing suppresses it, or when something other than the entry that names that
    path does: a directory glob would also cover it, and is what
    test_no_directory_glob_secret_suppressions.py refuses.
    """
    suppressions = suppressions_of(config)
    left = []
    for package, version in named_manifests(config, HARVEST_ROOT):
        path = manifest_path(CONTAINER_HARVEST_ROOT, package, version)
        suppressed, entry = should_suppress_finding(
            hex_finding(path, line), suppressions
        )
        if not suppressed or entry.path != path:
            left.append(path)
    return left


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


def test_a_container_scan_finds_each_manifest_suppressed():
    config = _config(CONFIG_WITH_THE_ENTRIES)
    named = named_manifests(config, HARVEST_ROOT)
    assert named, (
        f"{CONFIG_WITH_THE_ENTRIES} names no manifest under {HARVEST_ROOT}; the "
        "check below would pass over nothing"
    )
    left = container_manifests_left_reported(config, digest_line())
    assert left == [], (
        f"{len(named) - len(left)} of {len(named)} manifests are suppressed, by the "
        "entry that names them, at the path a container scan reports. The container "
        f"scans of the self-scan report the rest as secrets: {left}"
    )


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


def test_the_check_passes_a_manifest_both_spellings_suppress():
    line = digest_line()
    config = _config_of(
        _entry(EXAMPLE_PATH, line_start=line, line_end=line),
        _entry(CONTAINER_EXAMPLE_PATH, line_start=line, line_end=line),
    )
    assert container_manifests_left_reported(config, line) == []


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


@pytest.mark.parametrize(
    "rule_id, shift",
    [
        (RULE, -1),  # the line above the digest
        (RULE, 1),  # the line below it
        ("SECRET-AWS-ACCESS-KEY", 0),  # another rule on the digest line
    ],
)
def test_a_finding_beside_a_named_manifests_pin_stays_reported(rule_id, shift):
    package, version = _a_named_manifest()
    path = manifest_path(CONTAINER_HARVEST_ROOT, package, version)
    finding = hex_finding(path, digest_line() + shift, rule_id)
    suppressed, entry = should_suppress_finding(
        finding, list(repository_suppressions())
    )
    assert not suppressed, (
        f"{rule_id} on line {digest_line() + shift} of {path} is suppressed by "
        f"{entry and entry.path}"
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
