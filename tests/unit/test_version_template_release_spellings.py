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
names no spelling that release lacks.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"

#: The first release whose CLI reads the spellings below. Written here as well as in
#: the manager, so a change to the manager's threshold fails
#: test_the_threshold_is_the_release_that_introduced_the_spellings.
SUBJECTS_RELEASE = (3, 9, 0)

#: A spelling that ASH 3.8 does not read. ``ash scan workspace``, ``image`` and
#: ``git`` are listed too: they have no 3.8 form, so a page pinned to 3.8 must not
#: name them at all.
NEWER_SPELLING = re.compile(
    r"(?<![\w./-])ash(?:v3)?[ \t]+(?:"
    r"scan[ \t]+(?:fs|workspace|image|git)(?![\w-])"
    r"|results[ \t]+(?:report|diff|trend|merge|inspect)(?![\w-])"
    r"|container[ \t]+build(?![\w-])"
    r")"
)


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


def _release_tuple(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in version.split(".")[:3])
    return major, minor, patch


def _templated_targets() -> list[str]:
    return [
        target
        for target in MANAGER.target_files
        if (REPO_ROOT / (target + MANAGER.template_suffix)).is_file()
    ]


def _newer_spellings(text: str) -> list[str]:
    lines = text.splitlines()
    found = []
    for match in NEWER_SPELLING.finditer(text):
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
    (
        "`ashv3 scan fs --mode=precommit --staged`",
        "`ashv3 scan --mode=precommit --staged`",
    ),
    ("on `ash scan fs`.", "on `ash scan`."),
    (
        'data-ash-copy="ash scan fs --mode container"',
        'data-ash-copy="ash scan --mode container"',
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
    assert MODULE.SUBJECTS_RELEASE == SUBJECTS_RELEASE
    assert MODULE.spellings_for_release("ash scan fs", "3.8.99") == "ash scan"
    assert MODULE.spellings_for_release("ash scan fs", "3.9.0") == "ash scan fs"
    # A version that is not a release number names no release to write for.
    assert MODULE.spellings_for_release("ash scan fs", "main") == "ash scan fs"
    assert MODULE.spellings_for_release("ash scan fs", "{{VERSION}}") == "ash scan fs"


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
    if _release_tuple(release) >= SUBJECTS_RELEASE:
        pytest.skip(f"the current release, {release}, reads every newer spelling")
    found = _newer_spellings((REPO_ROOT / target).read_text(encoding="utf-8"))
    assert not found, (
        f"{target} pins ASH {release}, which does not read these commands; render "
        "it with scripts/version_template_manager.py generate:\n  " + "\n  ".join(found)
    )
