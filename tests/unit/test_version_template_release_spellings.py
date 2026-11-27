# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A page that pins a release shows the commands of that release.

Why this file exists
--------------------
The pages ``scripts/version_template_manager.py`` renders pin an install command to
the release they are rendered for, and the committed pages pin the current release
(``docs/hooks/install_refs.py`` serves them as committed on the ``main`` version of the
site). Their templates were moved to the ASH 3.9 command spellings (``ash scan fs``,
``ash results <verb>``, ``ash container build``) before any 3.9 release existed, so the
committed pages paired ``pipx install ...@v3.8.0`` with ``ash scan fs --mode
container``, which ASH 3.8 refuses: its ``scan`` takes no path argument and no
subcommand. The README on GitHub and the ``main`` docs showed that pairing.

A template now holds the newest spellings, and rendering it for a release older than
the one that introduced them writes the spellings that release reads: ``ash scan``
(with ``--source-dir`` for a path argument), the top-level results commands, and
``ash build-image``. A render for that release or a later one changes only the version
placeholders, so the bump that cuts it moves every page at once.

What is asserted
----------------
The rewrite, row by row, on the shapes the templates use; that every template rendered
for 3.8.0 holds none of the newer spellings and renders for 3.9.0 with nothing but its
placeholders replaced; and that each committed page, which pins the current release,
names no spelling that release lacks. The patterns that say what 3.8 lacks, the release
that introduced it and the results verbs are shared with every other test of the
spellings (tests/utils/release_spellings.py); this file holds the threshold and the
verbs to the manager's own.

A page that says what a pre-commit hook runs quotes the hook's ``entry:``. For a
release before 3.9 the render writes the entry that release's manifest holds, whole
(``ashv3 --mode=precommit``), and not the general respelling of the newer entry (``ashv3
scan --mode=precommit --staged``), which neither manifest has; the table behind that is
held to the repository's manifest and to the v3.8.0 entries written out below.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

from tests.utils.release_spellings import (
    NEWER_SCANNER_FLAG,
    NEWER_SPELLING,
    RESULTS_VERBS,
    SUBJECTS_RELEASE,
    release_tuple,
)

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
HOOK_MANIFEST = REPO_ROOT / ".pre-commit-hooks.yaml"
PRE_COMMIT_PAGE = REPO_ROOT / "docs" / "content" / "how-to" / "pre-commit.md"

#: The ``entry:`` of each hook of ``.pre-commit-hooks.yaml`` at the v3.8.0 tag, the
#: release the committed pages pin: lines 38, 48 and 60 of ``git show
#: v3.8.0:.pre-commit-hooks.yaml``. Written out here, so the manager's table of the
#: entries before the subjects is held to what that release shipped and not to itself.
V3_8_0_HOOK_ENTRIES = {
    "ash": "ashv3 --mode=precommit",
    "ash-simple-scan": "ashv3 --mode=precommit",
    "ash-full-scan": "ashv3 --mode=container --simple",
}


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_release_spellings", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()
MANAGER = MODULE.VersionTemplateManager(REPO_ROOT)


def _packaged_release() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]["version"]


def _templated_targets() -> list[str]:
    return [
        target
        for target in MANAGER.target_files
        if (REPO_ROOT / (target + MANAGER.template_suffix)).is_file()
    ]


def _newer_spellings(text: str) -> list[str]:
    lines = text.splitlines()
    found = []
    for pattern in (NEWER_SPELLING, NEWER_SCANNER_FLAG):
        for match in pattern.finditer(text):
            number = text.count("\n", 0, match.start())
            found.append(f"line {number + 1}: {lines[number].strip()}")
    return found


# (template text, what a render for 3.8.0 writes). Each row is a shape the templates
# or the site's snippets use.
ROWS = [
    ("ash scan fs --mode container", "ash scan --mode container"),
    ("`ash scan fs`", "`ash scan`"),
    ("Run `ash scan fs`, with no path", "Run `ash scan`, with no path"),
    ("ash scan fs", "ash scan"),
    (
        "ash scan fs . --output-dir ../out",
        "ash scan --source-dir . --output-dir ../out",
    ),
    (
        "  ash scan fs /src --output-dir /out",
        "  ash scan --source-dir /src --output-dir /out",
    ),
    (
        "ash scan fs src/my-app --mode container",
        "ash scan --source-dir src/my-app --mode container",
    ),
    ('ash scan fs "$PWD" --mode local', 'ash scan --source-dir "$PWD" --mode local'),
    ("`ash scan fs <path>`", "`ash scan --source-dir <path>`"),
    (
        "ash scan fs --mode local --no-progress \\\n  --fail-on-findings",
        "ash scan --mode local --no-progress \\\n  --fail-on-findings",
    ),
    ("ash scan fs \\\n  --mode local", "ash scan \\\n  --mode local"),
    ("`uv run ash scan fs .` puts", "`uv run ash scan --source-dir .` puts"),
    (
        "ASH_CONFIG=/etc/ash.yaml ash scan fs . --output-dir x",
        "ASH_CONFIG=/etc/ash.yaml ash scan --source-dir . --output-dir x",
    ),
    (
        "uvx --from git+https://example.invalid/a.git@v1.2.3 ash scan fs --mode container",
        "uvx --from git+https://example.invalid/a.git@v1.2.3 ash scan --mode container",
    ),
    ("entry: ash scan fs --mode precommit", "entry: ash scan --mode precommit"),
    # The entries of this repository's hooks: the entry the earlier release ships, whole.
    (
        "`ashv3 scan fs --mode=precommit --staged`",
        "`ashv3 --mode=precommit`",
    ),
    (
        "which runs `ashv3 scan fs --mode=container --simple`. It builds",
        "which runs `ashv3 --mode=container --simple`. It builds",
    ),
    (
        "  entry: ashv3 scan fs --mode=precommit --staged\n",
        "  entry: ashv3 --mode=precommit\n",
    ),
    # Not an entry of this repository's manifest: the general rewrite applies.
    ("`ashv3 scan fs --mode=precommit`", "`ashv3 scan --mode=precommit`"),
    ("on `ash scan fs`.", "on `ash scan`."),
    (
        'data-ash-copy="ash scan fs --mode container"',
        'data-ash-copy="ash scan --mode container"',
    ),
    # The flags 3.9 added for the scanners to run, inside an `ash scan` command: 3.8 has
    # `--scanners` for both.
    (
        "ash scan fs . --only-scanners bandit --offline",
        "ash scan --source-dir . --scanners bandit --offline",
    ),
    (
        "ash scan fs --only-scanners bandit,detect-secrets",
        "ash scan --scanners bandit,detect-secrets",
    ),
    (
        "ash scan fs . --only-scanners detect-secrets --only-scanners npm-audit",
        "ash scan --source-dir . --scanners detect-secrets --scanners npm-audit",
    ),
    (
        "ash scan fs . --only-scanners=bandit",
        "ash scan --source-dir . --scanners=bandit",
    ),
    ("ash scan fs --add-scanners bandit", "ash scan --scanners bandit"),
    ("ash scan --only-scanners bandit", "ash scan --scanners bandit"),
    (
        "ash scan fs --mode local \\\n  --only-scanners bandit",
        "ash scan --mode local \\\n  --scanners bandit",
    ),
    (
        "`ash scan fs --only-scanners bandit` runs",
        "`ash scan --scanners bandit` runs",
    ),
    (
        "uv run ash scan fs --only-scanners ferret-scan",
        "uv run ash scan --scanners ferret-scan",
    ),
    ("ash results inspect findings", "ash inspect findings"),
    ("ash results report --format markdown", "ash report --format markdown"),
    ("ash results merge --fail-on-findings", "ash merge --fail-on-findings"),
    ("`ash results diff`, `ash results trend`", "`ash diff`, `ash trend`"),
    ("ash container build --no-run", "ash build-image --no-run"),
    # Not a command of ASH, or already a spelling 3.8 reads: left alone.
    ("ash scan --mode local", "ash scan --mode local"),
    ("ash scan --source-dir . --mode local", "ash scan --source-dir . --mode local"),
    ("ash --mode container", "ash --mode container"),
    ("ash report", "ash report"),
    (
        "ash scan --workspace services.code-workspace",
        "ash scan --workspace services.code-workspace",
    ),
    ("dash scan fs", "dash scan fs"),
    ("flash results report", "flash results report"),
    ("/usr/local/bin/ash scan fs", "/usr/local/bin/ash scan fs"),
    ("ash scan fsck", "ash scan fsck"),
    ("ash scan fs.py", "ash scan fs.py"),
    ("ash results", "ash results"),
    ("ash container builder", "ash container builder"),
    # A sentence that names a flag says the flag, and so does a command outside `ash scan`.
    ("`--only-scanners` replaces the set", "`--only-scanners` replaces the set"),
    (
        "use `ash scan fs`, or `--only-scanners`",
        "use `ash scan`, or `--only-scanners`",
    ),
    (
        "ash scan fs . ; echo --only-scanners",
        "ash scan --source-dir . ; echo --only-scanners",
    ),
    ("ash --only-scanners bandit", "ash --only-scanners bandit"),
    ("dash scan --only-scanners bandit", "dash scan --only-scanners bandit"),
    ("ash scan --exclude-scanners bandit", "ash scan --exclude-scanners bandit"),
]


@pytest.mark.parametrize(("template", "rendered"), ROWS, ids=[row[0] for row in ROWS])
def test_a_render_for_a_release_before_the_subjects_writes_its_spellings(
    template, rendered
):
    assert MANAGER.render(template, "3.8.0") == rendered


@pytest.mark.parametrize(("template", "rendered"), ROWS, ids=[row[0] for row in ROWS])
def test_a_render_for_the_subjects_release_or_later_leaves_the_spellings(
    template, rendered
):
    for version in ("3.9.0", "3.10.2", "4.0.0"):
        assert MANAGER.render(template, version) == template


def test_the_rewrite_is_idempotent():
    for template, rendered in ROWS:
        assert MANAGER.render(rendered, "3.8.0") == rendered


def test_the_placeholders_still_render_beside_the_rewrite():
    template = (
        "pipx install git+https://example.invalid/a.git@v{{VERSION}}\n"
        "ash scan fs --mode container\n"
        "ASH {{RELEASE}}\n"
    )
    assert MANAGER.render(template, "3.8.0") == (
        "pipx install git+https://example.invalid/a.git@v3.8.0\n"
        "ash scan --mode container\n"
        "ASH 3.8.0\n"
    )
    assert MANAGER.render(template, "3.9.0") == (
        "pipx install git+https://example.invalid/a.git@v3.9.0\n"
        "ash scan fs --mode container\n"
        "ASH 3.9.0\n"
    )


def test_the_threshold_is_the_release_that_introduced_the_spellings():
    # SUBJECTS_RELEASE is the one every test of the spellings imports from
    # tests/utils/release_spellings.py, so this is the test that holds it to the
    # manager's own.
    assert MODULE.SUBJECTS_RELEASE == SUBJECTS_RELEASE
    assert MODULE.spellings_for_release("ash scan fs", "3.8.99") == "ash scan"
    assert MODULE.spellings_for_release("ash scan fs", "3.9.0") == "ash scan fs"
    # A version that is not a release number names no release to write for.
    assert MODULE.spellings_for_release("ash scan fs", "main") == "ash scan fs"
    assert MODULE.spellings_for_release("ash scan fs", "{{VERSION}}") == "ash scan fs"


def test_the_results_verbs_are_the_ones_the_manager_moves():
    """The detectors list the commands 3.9 moved under ``ash results``; the manager lists
    the ones it writes back, in its own pattern. A verb in one and not the other is a
    page the detectors flag and the render cannot fix, or the reverse."""
    listed = re.search(r"\(\?P<verb>([^)]*)\)", MODULE._RESULTS_VERB.pattern)
    assert listed is not None, (
        "the manager no longer names its verbs as `(?P<verb>...)`"
    )
    assert set(listed[1].split("|")) == set(RESULTS_VERBS)
    for verb in RESULTS_VERBS:
        assert MODULE.spellings_for_release(f"ash results {verb}", "3.8.0") == (
            f"ash {verb}"
        )


@pytest.mark.parametrize("target", _templated_targets())
def test_every_template_rendered_for_3_8_holds_no_newer_spelling(target):
    template = (REPO_ROOT / (target + MANAGER.template_suffix)).read_text(
        encoding="utf-8"
    )
    found = _newer_spellings(MANAGER.render(template, "3.8.0"))
    assert not found, (
        f"{target}.template, rendered for 3.8.0, still names a command 3.8 does not "
        "read; add its older spelling to scripts/version_template_manager.py "
        "spellings_for_release, or keep the command off a page that pins a release:\n  "
        + "\n  ".join(found)
    )


@pytest.mark.parametrize("target", _templated_targets())
def test_every_template_rendered_for_3_9_changes_only_its_placeholders(target):
    template = (REPO_ROOT / (target + MANAGER.template_suffix)).read_text(
        encoding="utf-8"
    )
    plain = template.replace(MANAGER.version_placeholder, "3.9.0").replace(
        MANAGER.release_placeholder, "3.9.0"
    )
    assert MANAGER.render(template, "3.9.0") == plain


@pytest.mark.parametrize("target", _templated_targets())
def test_a_committed_page_names_only_the_spellings_of_the_release_it_pins(target):
    """The direct regression: the committed page pins the current release (the round
    trip in test_version_template_round_trip.py holds it to its template), and a
    reader who copies its install command and then its other commands runs them on
    that release."""
    release = _packaged_release()
    if release_tuple(release) >= SUBJECTS_RELEASE:
        pytest.skip(f"the current release, {release}, reads every newer spelling")
    found = _newer_spellings((REPO_ROOT / target).read_text(encoding="utf-8"))
    assert not found, (
        f"{target} pins ASH {release}, which does not read these commands; render "
        "it with scripts/version_template_manager.py generate:\n  " + "\n  ".join(found)
    )


def _manifest_entries() -> dict[str, str]:
    hooks = yaml.safe_load(HOOK_MANIFEST.read_text(encoding="utf-8"))
    return {hook["id"]: hook["entry"] for hook in hooks}


def test_the_hook_entries_the_manager_swaps_are_the_manifests_and_the_3_8_0_ones():
    """A page that says what a hook runs quotes its ``entry:``. The render for a release
    before the subjects swaps each entry of this repository's manifest for the entry
    that release shipped, so the table is keyed by the manifest and its values are the
    v3.8.0 manifest's own, not a respelling of the newer entry."""
    entries = _manifest_entries()
    assert set(entries) == set(V3_8_0_HOOK_ENTRIES), (
        "the manifest and the v3.8.0 manifest define different hooks; the table in "
        "scripts/version_template_manager.py has to follow"
    )
    table = MODULE.HOOK_ENTRIES_BEFORE_THE_SUBJECTS
    assert set(table) == set(entries.values()), (
        "HOOK_ENTRIES_BEFORE_THE_SUBJECTS is not keyed by the entries of "
        f"{HOOK_MANIFEST.name}: {sorted(table)} against {sorted(set(entries.values()))}"
    )
    for hook_id, entry in entries.items():
        assert table[entry] == V3_8_0_HOOK_ENTRIES[hook_id], hook_id


@pytest.mark.parametrize("hook_id", sorted(V3_8_0_HOOK_ENTRIES))
def test_a_render_for_3_8_writes_the_entry_the_3_8_0_manifest_holds(hook_id):
    entry = _manifest_entries()[hook_id]
    assert MANAGER.render(f"`{entry}`", "3.8.0") == f"`{V3_8_0_HOOK_ENTRIES[hook_id]}`"
    assert MANAGER.render(f"`{entry}`", "3.9.0") == f"`{entry}`"


def test_the_committed_pre_commit_page_says_the_entries_its_pinned_release_ships():
    """The page described the hooks as running ``ashv3 scan --mode=precommit --staged``,
    which neither manifest holds. The release it pins is the one whose manifest it
    quotes."""
    release = _packaged_release()
    entries = (
        V3_8_0_HOOK_ENTRIES
        if release_tuple(release) < SUBJECTS_RELEASE
        else _manifest_entries()
    )
    text = " ".join(PRE_COMMIT_PAGE.read_text(encoding="utf-8").split())
    full_scan = entries["ash-full-scan"]
    for sentence in (
        f"The `ash` hook runs `{entries['ash']}` with your `args`.",
        (
            "`.pre-commit-hooks.yaml` also defines `ash-full-scan`, which runs "
            f"`{full_scan}`."
        ),
    ):
        assert sentence in text, (
            f"{PRE_COMMIT_PAGE.name} pins ASH {release} and should say: {sentence}"
        )
