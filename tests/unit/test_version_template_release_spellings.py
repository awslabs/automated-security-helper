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
the one that introduced them writes the spellings that release reads in its code: ``ash
scan`` (with ``--source-dir`` for a path argument), ``ash scan --workspace FILE`` for a
workspace scan, the top-level results commands (``report``, ``merge`` and ``inspect``;
``diff`` and ``trend`` have none, so a render leaves them and the checks refuse them),
and ``ash build-image``. The prose around the code is rendered as the template writes
it. A
sentence that names a spelling says what it says on every page, and a rewrite of it can
make it say the opposite: a page that tells its reader an older ASH has no ``fs``
subject, rendered for that older ASH, would tell its reader the subject is gone. A
render for that release or a later one changes only the version placeholders, so the
bump that cuts it moves every page at once.

What is asserted
----------------
The rewrite, row by row, on the shapes the templates use, as a command and inside a
fenced block of a page; which parts of a page a render reaches (the lines of a fenced
block and the text of an inline span, never the prose, which the rows and the sentences
below hold to fixed strings and not to a second pass of the rewrite); that every
template rendered for 3.8.0 holds none of the newer spellings and renders for 3.9.0
with nothing but its placeholders replaced; and that each committed page, which pins the
current release, names no spelling that release lacks. The patterns that say what 3.8
lacks, the release that introduced it and the results verbs are shared with every other
test of the spellings (tests/utils/release_spellings.py); this file holds the threshold
and the verbs to the manager's own.

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
    RESULTS_VERBS_ADDED,
    RESULTS_VERBS_MOVED,
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
PRE_COMMIT_TEMPLATE = PRE_COMMIT_PAGE.with_name(PRE_COMMIT_PAGE.name + ".template")
GITHUB_ACTIONS_PAGE = (
    REPO_ROOT / "docs" / "content" / "how-to" / "ci" / "github-actions.md"
)
GITHUB_ACTIONS_TEMPLATE = GITHUB_ACTIONS_PAGE.with_name(
    GITHUB_ACTIONS_PAGE.name + ".template"
)

#: What the GitHub Actions page says the reusable workflow passes to ASH, written out
#: here and not computed. It names ``--source-dir .`` in prose, as the workflow passes
#: it (an ASH before 3.9 reads it, and so does a later one), and no release rewrites a
#: sentence of prose, so the page says it the same way for every release.
GITHUB_ACTIONS_RUN_SENTENCE = (
    "It runs ASH with `uvx --reinstall`, passing `--source-dir .`, the output "
    "directory, `--no-progress`, the fail-on-findings choice, `--build-target ci`, "
    "`--mode`, and `--config` when a config is set; `--verbose` unless `verbose` is "
    "`false`; `--changed-files-only` and `--base-ref` when `changed-files-only` is "
    "`true`; and then `ash-args`."
)

#: The ``entry:`` of each hook of ``.pre-commit-hooks.yaml`` at the v3.8.0 tag, the
#: release the committed pages pin: lines 38, 48 and 60 of ``git show
#: v3.8.0:.pre-commit-hooks.yaml``. Written out here, so the manager's table of the
#: entries before the subjects is held to what that release shipped and not to itself.
V3_8_0_HOOK_ENTRIES = {
    "ash": "ashv3 --mode=precommit",
    "ash-simple-scan": "ashv3 --mode=precommit",
    "ash-full-scan": "ashv3 --mode=container --simple",
}

#: The commands the root group of ASH 3.8.0 registers, from lines 424 to 774 of ``git show
#: v3.8.0:automated_security_helper/cli/main.py``. Written out here, so the verbs the
#: manager writes back are held to what that release shipped and not to the manager.
#: There is no ``diff`` and no ``trend`` among them.
V3_8_0_COMMANDS = frozenset(
    {
        "scan",
        "build-image",
        "report",
        "merge",
        "mcp",
        "get-genai-guide",
        "config",
        "dependencies",
        "inspect",
        "plugin",
    }
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


def _fenced(text: str) -> str:
    """``text`` as the body of a fenced block, where a page holds a command."""
    return f"```text\n{text}\n```\n"


def _words(text: str) -> str:
    """``text`` with each run of whitespace read as one blank, as a paragraph reads."""
    return " ".join(text.split())


# (text of commands, what 3.8.0 reads it as). Each row is a shape the templates or the
# site's snippets use. The rewrite of commands is spellings_for_release, which the site
# gives its snippets as they are; a page goes through render, which applies it to the
# code of the page (RENDER_ROWS below), so each row is also run inside a fenced block.
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
    # 3.8.0 has neither `diff` nor `trend`, and no release has had either at the top
    # level, so there is no spelling to write them as: both stay as the template has
    # them, and the checks refuse them beside a pin before 3.9.
    (
        "`ash results diff`, `ash results trend`",
        "`ash results diff`, `ash results trend`",
    ),
    (
        "ash results diff before.json after.json",
        "ash results diff before.json after.json",
    ),
    (
        "ash results trend runs/a.json runs/b.json --format json",
        "ash results trend runs/a.json runs/b.json --format json",
    ),
    ("ash \\\n  results trend", "ash \\\n  results trend"),
    ('["ash", "results", "diff"]', '["ash", "results", "diff"]'),
    (
        "ash results diff a.json b.json && ash results report",
        "ash results diff a.json b.json && ash report",
    ),
    ("ash diff a.json b.json", "ash diff a.json b.json"),
    ("ash container build --no-run", "ash build-image --no-run"),
    # A workspace scan: 3.9's subject takes the file as its argument, and 3.8 reads the
    # file as the value of `--workspace`. The subject word becomes the option and the
    # file stays where it is.
    (
        "ash scan workspace services.code-workspace --dry-run",
        "ash scan --workspace services.code-workspace --dry-run",
    ),
    ("ash scan workspace auto", "ash scan --workspace auto"),
    ("`ash scan workspace FILE`", "`ash scan --workspace FILE`"),
    (
        "ash scan workspace <file> --allow-missing-projects",
        "ash scan --workspace <file> --allow-missing-projects",
    ),
    (
        'ash scan workspace "my services.code-workspace"',
        'ash scan --workspace "my services.code-workspace"',
    ),
    (
        "ash scan workspace services.code-workspace --scanners detect-secrets",
        "ash scan --workspace services.code-workspace --scanners detect-secrets",
    ),
    (
        "ash scan workspace services.code-workspace --only-scanners detect-secrets",
        "ash scan --workspace services.code-workspace --scanners detect-secrets",
    ),
    (
        "ASH_CONFIG=/etc/ash.yaml uv run ash scan workspace w.code-workspace",
        "ASH_CONFIG=/etc/ash.yaml uv run ash scan --workspace w.code-workspace",
    ),
    (
        "ashv3 scan workspace w.code-workspace",
        "ashv3 scan --workspace w.code-workspace",
    ),
    # With no file, as when a sentence names the command, the option stands alone.
    ("`ash scan workspace`", "`ash scan --workspace`"),
    ("ash scan workspace 2>&1", "ash scan --workspace 2>&1"),
    (
        "ash \\\n  scan \\\n  workspace \\\n  services.code-workspace",
        "ash \\\n  scan \\\n  --workspace \\\n  services.code-workspace",
    ),
    (
        '["ash", "scan", "workspace", "services.code-workspace"]',
        '["ash", "scan", "--workspace", "services.code-workspace"]',
    ),
    ('["ash", "scan", "workspace"]', '["ash", "scan", "--workspace"]'),
    (
        '[\n    "ash",\n    "scan",\n    "workspace",\n    "services.code-workspace",\n]',
        '[\n    "ash",\n    "scan",\n    "--workspace",\n    "services.code-workspace",\n]',
    ),
    # Not a workspace scan of ASH, or `workspace` is a word of something else: left
    # alone. After `fs`, `workspace` is the path of the scan.
    ("ash scan workspaces", "ash scan workspaces"),
    ("ash scan workspace-file", "ash scan workspace-file"),
    ("ash scan workspace.py", "ash scan workspace.py"),
    ("dash scan workspace w.code-workspace", "dash scan workspace w.code-workspace"),
    ("ash scan fs workspace", "ash scan --source-dir workspace"),
    # An option right after the subject: 3.9 lets the file follow the options, and 3.8's
    # `--workspace` would take the next word as its value. There is no respelling that
    # keeps the words where they are, so the render leaves the command and the checks
    # refuse it.
    (
        "ash scan workspace --dry-run services.code-workspace",
        "ash scan workspace --dry-run services.code-workspace",
    ),
    ("ash scan workspace [OPTIONS] FILE", "ash scan workspace [OPTIONS] FILE"),
    (
        '["ash", "scan", "workspace", "--dry-run", "w.code-workspace"]',
        '["ash", "scan", "workspace", "--dry-run", "w.code-workspace"]',
    ),
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
    # What follows `fs` is its path only when it can be one: a redirection, a usage
    # placeholder and an ellipsis are not, and a number that is no redirection is.
    ("ash scan fs 2>&1", "ash scan 2>&1"),
    ("ash scan fs . 2>&1", "ash scan --source-dir . 2>&1"),
    ("ash scan fs 2>&1 | tee ash.log", "ash scan 2>&1 | tee ash.log"),
    ("ash scan fs 1>/dev/null", "ash scan 1>/dev/null"),
    ("ash scan fs 2", "ash scan --source-dir 2"),
    ("ash scan fs [OPTIONS] [PATH]", "ash scan [OPTIONS] [PATH]"),
    ("ash scan fs [PATH]", "ash scan [PATH]"),
    ("`ash scan fs ...`", "`ash scan ...`"),
    ("ash scan fs ... --mode local", "ash scan ... --mode local"),
    # A command that goes on after a backslash at the end of a line is one command; a
    # backslash with no blank beside it joins two words into one.
    ("ash \\\n  scan fs .", "ash \\\n  scan --source-dir ."),
    ("ash scan \\\n  fs .", "ash scan --source-dir ."),
    (
        "ash scan fs \\\n  . --output-dir x",
        "ash scan \\\n  --source-dir . --output-dir x",
    ),
    (
        "ash \\\n  scan fs . \\\n  --only-scanners bandit",
        "ash \\\n  scan --source-dir . \\\n  --scanners bandit",
    ),
    ("ash \\\n  results report", "ash \\\n  report"),
    ("ash \\\n  container build --no-run", "ash \\\n  build-image --no-run"),
    ("ash\\\nscan fs .", "ash\\\nscan fs ."),
    # A list of arguments, on one line or one item to a line, in either kind of quote:
    # the flag and its path are two items.
    ('["ash", "scan", "fs", "."]', '["ash", "scan", "--source-dir", "."]'),
    ("['ash', 'scan', 'fs', '.']", "['ash', 'scan', '--source-dir', '.']"),
    ('["ash", "scan", "fs"]', '["ash", "scan"]'),
    (
        '["ash", "scan", "fs", "--mode", "local"]',
        '["ash", "scan", "--mode", "local"]',
    ),
    (
        '["ash", "scan", "fs", "--only-scanners", "bandit"]',
        '["ash", "scan", "--scanners", "bandit"]',
    ),
    ('["ash", "results", "report"]', '["ash", "report"]'),
    ('["ash", "container", "build"]', '["ash", "build-image"]'),
    (
        '[\n    "ash",\n    "scan",\n    "fs",\n    ".",\n]',
        '[\n    "ash",\n    "scan",\n    "--source-dir",\n    ".",\n]',
    ),
    ('["dash", "scan", "fs"]', '["dash", "scan", "fs"]'),
    ('["ash", "scan", "fsck"]', '["ash", "scan", "fsck"]'),
    ('["ash", "scan", "--mode", "local"]', '["ash", "scan", "--mode", "local"]'),
]


@pytest.mark.parametrize(("template", "rendered"), ROWS, ids=[row[0] for row in ROWS])
def test_a_render_for_a_release_before_the_subjects_writes_its_spellings(
    template, rendered
):
    assert MODULE.spellings_for_release(template, "3.8.0") == rendered
    # The same text in a fenced block of a page, which is what a render reaches.
    assert MANAGER.render(_fenced(template), "3.8.0") == _fenced(rendered)


@pytest.mark.parametrize(("template", "rendered"), ROWS, ids=[row[0] for row in ROWS])
def test_a_render_for_the_subjects_release_or_later_leaves_the_spellings(
    template, rendered
):
    for version in ("3.9.0", "3.10.2", "4.0.0"):
        assert MODULE.spellings_for_release(template, version) == template
        assert MANAGER.render(template, version) == template
        assert MANAGER.render(_fenced(template), version) == _fenced(template)


def test_the_rewrite_is_idempotent():
    for template, rendered in ROWS:
        assert MODULE.spellings_for_release(rendered, "3.8.0") == rendered
        assert MANAGER.render(_fenced(rendered), "3.8.0") == _fenced(rendered)


def test_the_placeholders_still_render_beside_the_rewrite():
    template = (
        "```bash\n"
        "pipx install git+https://example.invalid/a.git@v{{VERSION}}\n"
        "ash scan fs --mode container\n"
        "```\n"
        "ASH {{RELEASE}}\n"
    )
    assert MANAGER.render(template, "3.8.0") == (
        "```bash\n"
        "pipx install git+https://example.invalid/a.git@v3.8.0\n"
        "ash scan --mode container\n"
        "```\n"
        "ASH 3.8.0\n"
    )
    assert MANAGER.render(template, "3.9.0") == (
        "```bash\n"
        "pipx install git+https://example.invalid/a.git@v3.9.0\n"
        "ash scan fs --mode container\n"
        "```\n"
        "ASH 3.9.0\n"
    )


#: A sentence of prose that names the spellings of an older and a newer ASH, none of them
#: in code: every release leaves it as written.
A_SENTENCE_ABOUT_SPELLINGS = (
    "An ASH older than 3.9 has no ash scan fs; it takes ash scan --source-dir . "
    "and ash report."
)

# (text of a page, what a render of it for 3.8.0 writes). What a render reaches: the
# lines of a fenced block and the text of an inline code span. The prose around them
# stays as the template wrote it, and each such row is a fixed string, never the output
# of the rewrite given its own output. A rewrite of prose turns these red.
RENDER_ROWS = [
    # An inline span: its code, and nothing around it.
    ("Run `ash scan fs .` first.", "Run `ash scan --source-dir .` first."),
    (
        "Run `ash scan fs .` and then `ash results report`.",
        "Run `ash scan --source-dir .` and then `ash report`.",
    ),
    ("``ash scan fs .``", "``ash scan --source-dir .``"),
    (
        "```ash scan fs .``` on a line",
        "```ash scan --source-dir .``` on a line",
    ),
    (
        "Run `ash scan fs .\n--mode local` now.",
        "Run `ash scan --source-dir .\n--mode local` now.",
    ),
    (
        "| `ash scan fs .` | ash scan fs . |",
        "| `ash scan --source-dir .` | ash scan fs . |",
    ),
    # A fenced block: every line of it, whatever the fence is made of.
    ("```bash\nash scan fs .\n```\n", "```bash\nash scan --source-dir .\n```\n"),
    ("~~~\nash scan fs .\n~~~\n", "~~~\nash scan --source-dir .\n~~~\n"),
    (
        "  ```bash\n  ash scan fs .\n  ```\n",
        "  ```bash\n  ash scan --source-dir .\n  ```\n",
    ),
    (
        "````md\n```\nash scan fs .\n```\nash results report\n````\n",
        "````md\n```\nash scan --source-dir .\n```\nash report\n````\n",
    ),
    (
        "~~~\nash scan fs .\n```\nash results report\n~~~\nash scan fs .\n",
        "~~~\nash scan --source-dir .\n```\nash report\n~~~\nash scan fs .\n",
    ),
    # A fence that is never closed holds the rest of the page; the line that opens a
    # fence is not code, whatever its info string says.
    ("```bash\nash scan fs .\n", "```bash\nash scan --source-dir .\n"),
    (
        "```ash scan fs\nash scan fs .\n```\n",
        "```ash scan fs\nash scan --source-dir .\n```\n",
    ),
    # Prose is left as it is: after a fence, around a span, in a sentence about a
    # spelling, and in a paragraph that holds a backtick it never closes.
    (
        "```\nash scan fs .\n```\nash scan fs .\n",
        "```\nash scan --source-dir .\n```\nash scan fs .\n",
    ),
    (
        "```\nash scan fs .\n`````\nash scan fs .\n",
        "```\nash scan --source-dir .\n`````\nash scan fs .\n",
    ),
    ("Run ash scan fs . to scan.", "Run ash scan fs . to scan."),
    (A_SENTENCE_ABOUT_SPELLINGS, A_SENTENCE_ABOUT_SPELLINGS),
    (
        "- ash results report\n- ash container build\n",
        "- ash results report\n- ash container build\n",
    ),
    (
        "A lone ` here.\n\nRun ash scan fs . now, then `x`.\n",
        "A lone ` here.\n\nRun ash scan fs . now, then `x`.\n",
    ),
    # The entry of one of this repository's hooks is a quoted line of its manifest and
    # not a spelling, so it is swapped wherever it stands.
    (
        (
            "The `ash` hook runs `ashv3 scan fs --mode=precommit --staged` with your "
            "`args`."
        ),
        "The `ash` hook runs `ashv3 --mode=precommit` with your `args`.",
    ),
    (
        "It runs ashv3 scan fs --mode=precommit --staged on commit.",
        "It runs ashv3 --mode=precommit on commit.",
    ),
    ("`ashv3 scan fs --mode=precommit`", "`ashv3 scan --mode=precommit`"),
    # A workspace scan is spelled for the release in an inline span, which is code, and in
    # a fenced block, and not in a sentence that names it in prose.
    (
        "Scan it with `ash scan workspace services.code-workspace` first.",
        "Scan it with `ash scan --workspace services.code-workspace` first.",
    ),
    (
        "an option that `ash scan workspace` does not take",
        "an option that `ash scan --workspace` does not take",
    ),
    (
        "```bash\nash scan workspace services.code-workspace --dry-run\n```\n",
        "```bash\nash scan --workspace services.code-workspace --dry-run\n```\n",
    ),
    (
        "Run ash scan workspace services.code-workspace to scan it.",
        "Run ash scan workspace services.code-workspace to scan it.",
    ),
]


@pytest.mark.parametrize(
    ("page", "rendered"),
    RENDER_ROWS,
    ids=[f"row-{index}" for index in range(len(RENDER_ROWS))],
)
def test_a_render_writes_the_spellings_of_the_code_of_a_page_and_nothing_else(
    page, rendered
):
    assert MANAGER.render(page, "3.8.0") == rendered


@pytest.mark.parametrize(
    ("page", "rendered"),
    RENDER_ROWS,
    ids=[f"row-{index}" for index in range(len(RENDER_ROWS))],
)
def test_a_render_for_the_subjects_release_leaves_a_page_as_it_is(page, rendered):
    for version in ("3.9.0", "4.0.0"):
        assert MANAGER.render(page, version) == page


@pytest.mark.parametrize(
    ("page", "rendered"),
    RENDER_ROWS,
    ids=[f"row-{index}" for index in range(len(RENDER_ROWS))],
)
def test_a_rendered_page_renders_as_it_is(page, rendered):
    assert MANAGER.render(rendered, "3.8.0") == rendered


@pytest.mark.parametrize("version", ["3.7.0", "3.8.0"])
def test_the_github_actions_page_names_the_checkout_the_way_the_template_writes_it(
    version,
):
    """A release before the subjects gets the sentence as the template writes it, in the
    words written out above: the checkout is passed as ``--source-dir .``, said once,
    with no second sentence about an older ASH on a page that pins one."""
    page = _words(
        MANAGER.render(GITHUB_ACTIONS_TEMPLATE.read_text(encoding="utf-8"), version)
    )
    assert GITHUB_ACTIONS_RUN_SENTENCE in page
    assert "which has no `fs` subject" not in page


def test_the_committed_github_actions_page_says_the_same_sentence():
    release = _packaged_release()
    if release_tuple(release) >= SUBJECTS_RELEASE:
        pytest.skip(f"the current release, {release}, reads every newer spelling")
    page = _words(GITHUB_ACTIONS_PAGE.read_text(encoding="utf-8"))
    assert GITHUB_ACTIONS_RUN_SENTENCE in page, (
        f"{GITHUB_ACTIONS_PAGE.name} pins ASH {release} and should say: "
        f"{GITHUB_ACTIONS_RUN_SENTENCE}"
    )


@pytest.mark.parametrize("version", ["3.8.0", "3.9.0"])
def test_the_pre_commit_template_names_the_entry_the_release_ships(version):
    """The sentence says what the ``ash`` hook runs, in the entry of the manifest of the
    release the page pins: the v3.8.0 manifest's, written out above, for a release before
    the subjects, and this tree's otherwise."""
    entries = (
        V3_8_0_HOOK_ENTRIES
        if release_tuple(version) < SUBJECTS_RELEASE
        else _manifest_entries()
    )
    page = _words(
        MANAGER.render(PRE_COMMIT_TEMPLATE.read_text(encoding="utf-8"), version)
    )
    assert f"The `ash` hook runs `{entries['ash']}` with your `args`." in page


# (text, how many spellings 3.8 lacks the detector reads in it). The same shapes as the
# rows above, from the other side: whatever the render writes back, the detectors read.
DETECTOR_ROWS = [
    ("ash scan fs .", 1),
    ("ash scan fs . --only-scanners bandit", 2),
    ("ash scan --only-scanners bandit", 1),
    ("ash scan --scanners bandit", 0),
    ("the `--only-scanners` flag replaces the set", 0),
    ("ash \\\n  scan fs .", 1),
    ("ash scan \\\n  --only-scanners bandit", 1),
    ("ash \\\n  results merge", 1),
    ("ash\\\nscan fs .", 0),
    ('["ash", "scan", "fs", "."]', 1),
    ('["ash", "scan", "--only-scanners", "bandit"]', 1),
    ('["ash", "container", "build"]', 1),
    ('[\n    "ash",\n    "scan",\n    "fs",\n]', 1),
    ('["ash", "scan", "--mode", "local"]', 0),
    ('["dash", "scan", "fs"]', 0),
    # `diff` and `trend`: 3.8.0 has neither, in either spelling, and the render leaves
    # both, so the detectors are what refuses them beside a pin before 3.9.
    ("ash results diff a.json b.json", 1),
    ("ash results trend", 1),
    ("ash diff a.json b.json", 1),
    ("ash trend runs/a.json runs/b.json", 1),
    ("ash \\\n  diff a.json b.json", 1),
    ('["ash", "diff"]', 1),
    ('["ash", "results", "trend"]', 1),
    ("`ash diff` and `ash results trend`", 2),
    ("ash diffs", 0),
    ("ash trending", 0),
    ("ash diff-tool", 0),
    ("dash diff a.json b.json", 0),
    ("/usr/local/bin/ash trend", 0),
    # The commands 3.8.0 has as top-level commands are not what the detectors read.
    ("ash report", 0),
    ("ash merge --results a --results b", 0),
    ("ash inspect findings", 0),
    # A workspace scan: 3.8.0 reads `--workspace`, and the subject is a newer spelling,
    # prose included: the detectors read every word of a page, and the render only its code.
    ("ash scan workspace services.code-workspace", 1),
    ("`ash scan workspace`", 1),
    ("Run ash scan workspace services.code-workspace to scan it.", 1),
    ("ash scan workspace --dry-run services.code-workspace", 1),
    ('["ash", "scan", "workspace", "services.code-workspace"]', 1),
    ("ash scan --workspace services.code-workspace", 0),
    ("ash scan workspaces", 0),
]


@pytest.mark.parametrize(
    ("text", "count"),
    DETECTOR_ROWS,
    ids=[f"row-{index}" for index in range(len(DETECTOR_ROWS))],
)
def test_the_detector_on_planted_text(text, count):
    assert len(_newer_spellings(text)) == count, text


@pytest.mark.parametrize(
    "command",
    [
        "ash scan workspace --dry-run services.code-workspace",
        "ash scan workspace [OPTIONS] FILE",
        '["ash", "scan", "workspace", "--dry-run", "w.code-workspace"]',
    ],
)
def test_a_workspace_scan_with_no_respelling_is_left_for_the_checks_to_refuse(command):
    """The file of ``ash scan workspace --dry-run FILE`` follows an option, and 3.8's
    ``--workspace`` takes the next word as its value, so no respelling keeps the words
    where they are. The render leaves the command, and the check of a render for 3.8
    names it, instead of the render writing one that 3.8 refuses."""
    rendered = MANAGER.render(_fenced(command), "3.8.0")
    assert rendered == _fenced(command)
    assert len(_newer_spellings(rendered)) == 1, command


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
    """The detectors list the commands 3.9 moved under ``ash results`` and the ones it
    added there; the manager lists the ones it writes back, in its own pattern. A verb
    the manager writes back that 3.8.0 lacks is a command the render invents, and a verb
    in the detectors' list of moved verbs and not the manager's is a page the detectors
    flag and the render cannot fix."""
    listed = re.search(r"\(\?P<verb>([^)]*)\)", MODULE._RESULTS_VERB.pattern)
    assert listed is not None, (
        "the manager no longer names its verbs as `(?P<verb>...)`"
    )
    assert set(listed[1].split("|")) == set(RESULTS_VERBS_MOVED)
    for verb in RESULTS_VERBS_MOVED:
        assert MODULE.spellings_for_release(f"ash results {verb}", "3.8.0") == (
            f"ash {verb}"
        )


def test_the_verbs_added_in_3_9_are_left_as_they_are_for_3_8():
    """3.8.0 has neither ``diff`` nor ``trend``, as ``ash results <verb>`` or at the top
    level, so the render writes nothing for them: a page that pins 3.8 and names one is
    the detectors' to refuse."""
    assert RESULTS_VERBS_ADDED == ("diff", "trend")
    for verb in RESULTS_VERBS_ADDED:
        for command in (f"ash results {verb}", f"ash {verb}"):
            assert MODULE.spellings_for_release(command, "3.8.0") == command
            assert MANAGER.render(_fenced(command), "3.8.0") == _fenced(command)
            assert len(_newer_spellings(command)) == 1, command


def test_the_verbs_are_split_by_what_3_8_0_has():
    """The moved verbs are commands of the 3.8.0 root group; the added ones are not."""
    assert set(RESULTS_VERBS_MOVED) <= V3_8_0_COMMANDS
    assert not set(RESULTS_VERBS_ADDED) & V3_8_0_COMMANDS
    assert not set(RESULTS_VERBS_MOVED) & set(RESULTS_VERBS_ADDED)
    assert set(RESULTS_VERBS) == set(RESULTS_VERBS_MOVED) | set(RESULTS_VERBS_ADDED)


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
