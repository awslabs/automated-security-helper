#!/usr/bin/env python3
"""
Version Template Manager for Automated Security Helper.

This script manages template-based documentation where version numbers
are replaced with placeholders and then dynamically generated.
"""

import enum
import re
import sys
from pathlib import Path
from typing import List, NamedTuple, Optional, Tuple
import argparse

# Add the project root to the path so we can import our version management
sys.path.insert(0, str(Path(__file__).parent.parent))

# Every form in which a command names the ASH ref it installs: the text in front of the
# `v` of a release tag, and the same form naming a branch instead. `@` covers git URLs
# (`git+https://...@v`, `uvx --from=git+...@v`) and `uses: ...@v`. The repository name is
# interpolated for the reason the flake entry of ASH_PIN_PATTERNS gives.
#
# One list for three readers: scripts/docs_versions.py check reads which release a built
# page pins (release_pins) and requires the main version to name main in every form a
# release page uses (branch_ref_pattern); scripts/docs_checks.py refuses {{RELEASE}} in
# any of these forms in a template (release_in_install_ref). Whether a `v<version>` after
# one of these prefixes is ASH's pin is decided once, by ASH_PIN_PATTERNS below, which
# `convert` and the two readers of a built page's pins (release_pins and
# forms_pinning_a_release) all use: a prefix such as `--branch ` or `rev: ` is written by
# every project, and read alone it called another project's tag an ASH pin.
_REPO_NAME = "automated-security-" + "helper"
INSTALL_REF_FORMS = (
    # (name, the text before `v<version>`, the form naming a branch, with {branch})
    ("@ (git URL, uses:)", r"@", r"@{branch}"),
    ("--branch", r"--branch ", r"--branch {branch}"),
    ("rev:", r"rev: ", r"rev: {branch}"),
    ("refs/tags/ (git ls-remote)", r"refs/tags/", r"refs/heads/{branch}"),
    (
        "flake ref",
        rf"github:[\w.-]+/{_REPO_NAME}/",
        rf"github:[\w.-]+/{_REPO_NAME}/{{branch}}",
    ),
    (
        "--ash-revision-to-install",
        r"--ash-revision-to-install ",
        r"--ash-revision-to-install {branch}",
    ),
    ("ash-version:", r"ash-version: ", r"ash-version: {branch}"),
)
_SEMVER = r"\d+\.\d+\.\d+"
# The rest of one shell command: any text up to a newline that is not escaped, or to a
# separator that starts another command. A backtick, `)` or `]` ends it too: in prose,
# several inline code spans and links share a line, and a command in one span is not
# the command of the repository named in the next. ASH_PIN_PATTERNS uses it to tell a
# `--branch v<version>` that belongs to a clone of this repository from one that
# belongs to another project.
_SAME_COMMAND = r"(?:\\\n|[^\n;&|`)\]])*"
# This repository's name where it is a whole name, with its optional `.git`: not the
# end of another name (`fork-<name>`, `my.<name>`) and not the start of one
# (`<name>-plugins`). Every anchor below is built from it.
_ASH_NAME = rf"(?<![\w.-]){_REPO_NAME}(?:\.git)?(?![\w.-])"
# This repository as a URL or a path names it.
_ASH_REPOSITORY = rf"[/:]{_ASH_NAME}"


def _in_an_ash_command(prefix: str) -> Tuple[str, str]:
    """The two shapes of `<prefix>v<version>` that belong to a command naming ASH.

    The repository can come before the prefix or after it, in the same command (see
    _SAME_COMMAND). Each pattern has one group, the text up to and including the `v`;
    the version number is the rest of the match.
    """
    return (
        rf"({_ASH_REPOSITORY}{_SAME_COMMAND}{prefix}v){_SEMVER}",
        rf"({prefix}v){_SEMVER}(?={_SAME_COMMAND}{_ASH_REPOSITORY})",
    )


_FORM_PREFIX = {name: prefix for name, prefix, _branch in INSTALL_REF_FORMS}

# What unrecognized_pins looks for where the install form has more spellings than the
# anchored patterns read: a YAML value may follow `rev:` or `ash-version:` after any
# run of blanks and be quoted, and a clone takes its tag as `--branch v1`,
# `--branch=v1`, `-b v1` or `-bv1`, with a run of blanks after the flag, as does the
# build flag with `=`. The safety net has to be looser than the anchors, or a pin in a
# spelling nobody anchored is never seen. A quote sits inside the prefix, in front of
# the `v` that unrecognized_pins appends.
_LOOSE_PREFIX = {
    "--branch": r"(?:--branch(?:[ \t]+|=)|(?<![\w-])-b[ \t]*)[\"']?",
    "rev:": r"(?<![\w-])rev:[ \t]+[\"']?",
    "--ash-revision-to-install": r"--ash-revision-to-install(?:[ \t]+|=)[\"']?",
    "ash-version:": r"ash-version:[ \t]+[\"']?",
}

# For every form of INSTALL_REF_FORMS, the patterns that match a release pin of ASH in
# it, and no other project's. Each pattern has one group, the text up to and including
# the `v` that starts the version, and ends with the version number, so `convert`
# replaces the number with a placeholder (`\g<1>{{VERSION}}`) and the readers of a
# built page read it (`_ash_pins`) from the same match.
#
# The forms that name ASH by themselves (a flake ref, the build flag, the action input)
# need no more than their prefix. The others are written by every project and are
# anchored on ASH: `@` bare, or after this repository's name and an optional path (the
# reusable-workflow form); `--branch` and `refs/tags/` in a command that names this
# repository; `rev:` in the pre-commit entry whose `repo:` is this repository. Only
# blank and comment lines may sit between the `repo:` line and its `rev:` line, so the
# match cannot reach into the next entry. The reason for each anchor is with its entry.
ASH_PIN_PATTERNS = {
    # `@v<version>` in inline text (a page's "pinned versions (`@v3.4.0`)"), and the
    # forms naming this repository: `git+<url>[.git]@v<version>`, the action
    # `<owner>/<this repository>@v<version>`, and the reusable workflow
    # `<owner>/<this repository>/.github/workflows/<file>.yml@v<version>`, which is the
    # form the CI pages document. The repository name is interpolated, not written out,
    # for the reason the flake entry gives: the tree walk in
    # tests/unit/test_agent_plugin_ash_version.py reads a literal
    # `<repository>@v<something>` in a comment as an install pin.
    # Bare means not glued to a preceding path or name: unanchored, the pattern also
    # templatized third-party pins such as a `uses: actions/checkout@v4.1.2` line in a
    # CI example, and `generate` then stamped ASH's version into another project's
    # reference. Anchored on the repository name followed directly by `@v`, it missed
    # the reusable-workflow form, whose `@v` follows the workflow's path, so `convert`
    # wrote that pin into the template as a literal and `generate` never moved it
    # again. The optional path after the repository name admits that form; a
    # third-party workflow has another repository name in front of its path and is
    # still left alone.
    "@ (git URL, uses:)": (
        # The ellipsis form is prose for "the workflow of this repository":
        # `uses: ...@v<version>`. It stands alone: after a path or a name it is a
        # shortened reference to another project (`actions/...@v4.1.2`).
        rf"((?<![\w./-])@v|(?<![\w./-])\.\.\.@v|{_ASH_NAME}(?:/[\w./-]+)?@v){_SEMVER}",
    ),
    # `--branch v<version>`, in a command that names this repository. Unanchored, the
    # pattern also templatized the tag of any other project cloned in a page's example
    # (`git clone --branch v1.2.3 <another repository>`), and `generate` then stamped
    # ASH's version into that command. The repository can come before the flag or
    # after it, in the same command. The name must end where the repository's does: a
    # sibling such as `<this repository>-plugins` is another project.
    "--branch": _in_an_ash_command(_FORM_PREFIX["--branch"]),
    # `rev: v<version>` (pre-commit config), in the entry whose `repo:` is this
    # repository. A pre-commit config pins every hook repository with a `rev:`, so
    # unanchored the pattern also templatized the pin of each other repository a
    # page's example lists.
    "rev:": (
        (
            rf"(repo:[ \t]*\S*{_ASH_REPOSITORY}/?[\"']?[ \t]*(?:#[^\n]*)?\n"
            rf"(?:[ \t]*(?:#[^\n]*)?\n)*[ \t]*rev:[ \t]+v){_SEMVER}"
        ),
    ),
    # The tag lookup, `git ls-remote <this repository> refs/tags/v<version>`, in a
    # command that names this repository, as `--branch` does. The reader of a built
    # page counts it as a pin, so `convert` has to move it too.
    "refs/tags/ (git ls-remote)": _in_an_ash_command(
        _FORM_PREFIX["refs/tags/ (git ls-remote)"]
    ),
    # A Nix flake reference, `github:<owner>/<repo>/v<version>`.
    #
    # Every entry above keys on `@v`, `--branch v` or `rev: v`, because every install
    # reference this repository had first carried used one of them. A flake ref
    # separates the ref from the repository with a SLASH, so it was invisible to all of
    # them -- and to `[tool.commitizen] version_files`, and to the three `@v`-anchored
    # patterns in tests/unit/test_agent_plugin_ash_version.py. Five mechanisms with one
    # blind spot, because all five had encoded the same incidental delimiter as though
    # it were part of what a reference is.
    #
    # It was not hypothetical. docs/content/docs/installation-guide.md documented an
    # ASH_NIX_FLAKE_REF override in the flake form, under a heading reading "Override
    # it with:", as a runnable copy-paste. It sat two minor releases behind the
    # shipped version and no mechanism could see it. `nix develop` resolves a git ref
    # like every other consumer here, so it succeeded and supplied an old ASH with an
    # old scanner set.
    #
    # The offending value is described rather than quoted. This file is read by the
    # tree walk in tests/unit/test_agent_plugin_ash_version.py, so pasting the stale
    # literal into this comment would be reported as a real stale pin -- the comment
    # explaining the hazard would BE the hazard. The same applies to the `/v` prefix
    # with nothing after it, which that walk reads as a truncated ref, which is why
    # the repository name is interpolated instead of written inline.
    #
    # The OWNER is deliberately unanchored: `resolve_flake_ref()` builds its ref from
    # `ASH_REPO_URL`, so a fork's docs carry a fork's owner. The repository NAME is
    # anchored, because without it a flake ref to an unrelated project -- nixpkgs,
    # say -- would be rewritten to ASH's version.
    "flake ref": (rf"({_FORM_PREFIX['flake ref']}v){_SEMVER}",),
    # The build flag and the action input name this repository by themselves. The
    # reader of a built page counts a pin in either, so leaving them out meant
    # `convert` wrote the stale literal into a template that the check would then
    # report as a pin it never moved.
    "--ash-revision-to-install": (
        rf"({_FORM_PREFIX['--ash-revision-to-install']}v){_SEMVER}",
    ),
    "ash-version:": (rf"({_FORM_PREFIX['ash-version:']}v){_SEMVER}",),
}


def _ash_pins(text: str) -> List[Tuple[str, str, int]]:
    """(form name, release number, where the number starts) of every ASH pin in text."""
    found = []
    for form, patterns in ASH_PIN_PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(pattern, text):
                found.append(
                    (form, match.string[match.end(1) : match.end()], match.end(1))
                )
    return found


class UnrecognizedPin(NamedTuple):
    """A pin ASH_PIN_PATTERNS rejects: the form, the version, and where it sits."""

    form: str
    version: str
    line: str  # the line that holds the version
    entry: str  # the entry or command around it (see _entry_around)


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


# What ends one shell command and starts another inside a line, or inside a run of
# `\`-continued lines: the separators _SAME_COMMAND stops at, and the backtick that
# opens or closes a code span. _entry_around cuts at the nearest one on each side of
# the pin.
_COMMAND_BREAKS = ";&|`"

# A YAML list item whose first line opens a block scalar: `- run: |`, `- |`, `- run: >-`.
# The lines under it are a script, one command per line, and not keys of the item.
_BLOCK_SCALAR = re.compile(
    r"^(?P<dash>[ \t]*-[ \t]+)(?P<key>[\w.\"'-]+:[ \t]+)?[|>][-+0-9]*[ \t]*(?:#.*)?$"
)


def _block_scalar_floor(line: str) -> Optional[int]:
    """The indent a line must exceed to be inside the block scalar that `line` opens.

    None when line is not a list item that opens one.
    """
    found = _BLOCK_SCALAR.match(line.rstrip())
    if found is None:
        return None
    return len(found.group("dash")) if found.group("key") else _indent(line)


def _entry_around(lines: List[str], index: int, begin: int, finish: int) -> str:
    """The YAML list entry or the shell command that holds the pin on lines[index].

    begin and finish are where the pin starts and ends in that line. A command
    continued with a trailing backslash is whole. A line of a YAML list entry is read
    up to the `- ` line that starts the entry and down through the lines indented
    deeper than it, so a pre-commit `rev:` comes with the `repo:` line above it, and a
    `- rev:` with the `repo:` below it. A list item nested deeper than the `rev:` (the
    `- id:` lines under a `hooks:` key) belongs to a sibling key and is walked past, so
    the `repo:` line above it is still found. Blank lines inside an entry are crossed,
    as the anchored `rev:` pattern crosses them between `repo:` and `rev:`: the entry
    ends at the first line, after any blank ones, that is indented no deeper than its
    `- `. Prose and other text stay one line.

    Whatever the entry is, it is cut at the nearest `;`, `&`, `|` or backtick on each
    side of the pin (see _COMMAND_BREAKS): `git clone <another project> && \\` and the
    clone on the next line are two commands, and a project named in the first must not
    excuse the pin of the second.

    A pin on a line of a script under a list item that opens a block scalar (`- run: |`)
    is read alone, with its own `\\`-continued lines: each line of such a script is a
    command of its own, and the line with the `|` is no part of any of them.
    """
    run_start = index
    while run_start > 0 and lines[run_start - 1].rstrip().endswith("\\"):
        run_start -= 1
    start = run_start
    if not lines[start].lstrip().startswith("- "):
        base = _indent(lines[start])
        above = start - 1
        while above >= 0:
            if not lines[above].strip():
                above -= 1  # a blank line is no end: the line above it decides
                continue
            if lines[above].lstrip().startswith("- "):
                if _indent(lines[above]) < base:
                    start = above
                    break
                if _indent(lines[above]) == base:
                    break
            elif _indent(lines[above]) < base:
                break
            above -= 1
    end = index
    while end + 1 < len(lines) and lines[end].rstrip().endswith("\\"):
        end += 1
    in_script = False
    if start < run_start:
        floor = _block_scalar_floor(lines[start])
        if floor is not None and _indent(lines[run_start]) > floor:
            start = run_start
            in_script = True
    if not in_script and lines[start].lstrip().startswith("- "):
        entry_indent = _indent(lines[start])
        while True:
            following = end + 1
            while following < len(lines) and not lines[following].strip():
                following += 1
            if following >= len(lines) or _indent(lines[following]) <= entry_indent:
                break
            end = following
    entry = "\n".join(lines[start : end + 1])
    where = sum(len(line) + 1 for line in lines[start:index])
    before = max(entry.rfind(mark, 0, where + begin) for mark in _COMMAND_BREAKS)
    after = [entry.find(mark, where + finish) for mark in _COMMAND_BREAKS]
    until = min((found for found in after if found >= 0), default=len(entry))
    return entry[before + 1 : until]


class FileResult(enum.Enum):
    """What convert_file or generate_file did with one file.

    A bare True or False cannot tell a file that was left alone for a reason that is
    not an error (a template kept, no version reference) from one that failed.
    """

    DONE = "done"  # the template or the page was written
    SKIPPED = "skipped"  # left alone, and that is not an error
    FAILED = "failed"  # an error, already printed; the *_all methods list the file


class VersionTemplateManager:
    """Manages version templating for documentation files."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.template_suffix = ".template"
        # The files the last convert_all_to_templates or generate_all_from_templates
        # could not process: a read or write that failed, a version that could not be
        # determined, a listed target with no template (generate) or no page
        # (convert). Both return only a count, so without this a caller cannot tell a
        # skipped file from a failed one. Each run replaces the list; a convert or
        # generate of one file called directly does not touch it.
        self.failures: List[Path] = []
        # The version generate_all_from_templates read for the run in progress, so
        # each template does not read it again; None outside such a run.
        self._run_version: Optional[str] = None
        # The ref an install command uses. A release's docs render it as the release,
        # the docs site's main version as `main` (see render_for_branch).
        self.version_placeholder = "{{VERSION}}"
        # The current release number, on every build: what `ash --version` prints, the
        # release this repository's generated files pin, a release named in a table.
        # Never in an install command, where the main version would then install a
        # release; scripts/docs_checks.py enforces that with release_in_install_ref.
        self.release_placeholder = "{{RELEASE}}"

        # Files to process (relative to project root). Every page with a
        # `.template` sibling is listed, because `generate` renders only what is
        # named here and the round-trip test reads this list: a template with no
        # entry is never rendered, so its page keeps the pin of the release it was
        # written at. The tutorials pages were replaced by the getting-started and
        # how-to pages (docs/redirects.yml), so their entries went with them.
        self.target_files = [
            "README.md",
            "docs/content/docs/advanced-usage.md",
            "docs/content/getting-started/ci.md",
            "docs/content/getting-started/local.md",
            "docs/content/getting-started/platform-teams.md",
            "docs/content/how-to/agent-plugins.md",
            "docs/content/how-to/ci/github-actions.md",
            "docs/content/how-to/ci/gitlab-ci.md",
            "docs/content/how-to/ci/other-ci.md",
            "docs/content/how-to/install.md",
            "docs/content/how-to/pre-commit.md",
            "docs/content/how-to/run-in-a-container.md",
            "docs/content/how-to/scale-large-repos.md",
            "docs/content/how-to/suppress-findings.md",
            "examples/streamlit_ui/README.md",
        ]

    def find_version_references(self, content: str) -> List[Tuple[str, str]]:
        """
        Find all version references in content.

        Matches ANY v3.x.y version string (not just the current version) so that
        templates stay correct even when docs are edited between releases.

        Returns list of (old_pattern, new_pattern) tuples.
        """
        # Every pattern of every form of INSTALL_REF_FORMS, ASH_PIN_PATTERNS' own: the
        # same ones the readers of a built page's pins use, so what `convert` leaves
        # alone is not read as a pin. Each ends in the version number after the `v`
        # and has one group before it, so the replacement keeps what the pattern
        # anchored on and swaps only the number. The reason for each anchor is with
        # its entry in ASH_PIN_PATTERNS.
        replacement = rf"\g<1>{self.version_placeholder}"
        return [
            (pattern, replacement)
            for form_patterns in ASH_PIN_PATTERNS.values()
            for pattern in form_patterns
            if re.search(pattern, content)
        ]

    def render(self, content: str, version: str) -> str:
        """A template rendered for a release: both placeholders become the version."""
        return content.replace(self.version_placeholder, version).replace(
            self.release_placeholder, version
        )

    def render_for_branch(self, content: str, branch: str, release: str) -> str:
        """A template rendered for a branch, such as main, instead of a release.

        The docs site's `main` version is built this way (docs/hooks/install_refs.py),
        so its install commands install main. A placeholder written after a `v`, as in
        `@v{{VERSION}}`, `--branch v{{VERSION}}` or `rev: v{{VERSION}}`, names a release
        tag, and the whole tag becomes the branch: `@main`, not `@vmain`. A tag looked up
        by its full name, `refs/tags/v{{VERSION}}`, becomes the branch's
        `refs/heads/<branch>`, so the command still names a ref that exists. A bare
        placeholder becomes the branch name too. The release placeholder becomes
        release, the current release number: an install of main reports it.
        """
        tag = "v" + self.version_placeholder
        return (
            content.replace("refs/tags/" + tag, "refs/heads/" + branch)
            .replace(tag, branch)
            .replace(self.version_placeholder, branch)
            .replace(self.release_placeholder, release)
        )

    def packaged_release(self) -> str:
        """The current release number: `[tool.commitizen] version` in pyproject.toml.

        That is the field commitizen bumps, and the one the committed pages were
        rendered for. Read from the file rather than with get_version(), which imports
        ASH.
        """
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib

        with (self.project_root / "pyproject.toml").open("rb") as handle:
            return tomllib.load(handle)["tool"]["commitizen"]["version"]

    @staticmethod
    def release_pins(text: str) -> set:
        """The release numbers that ASH install commands in text pin, in any form.

        Another project's `rev:`, `--branch` or `@v` pin is not one: a pin counts when
        ASH_PIN_PATTERNS matches it, the same test `convert` applies.
        """
        return {version for _form, version, _start in _ash_pins(text)}

    @staticmethod
    def forms_pinning_a_release(text: str) -> List[str]:
        """The names of the install-command forms that pin an ASH release in text."""
        pinned = {form for form, _version, _start in _ash_pins(text)}
        return [name for name, _prefix, _branch in INSTALL_REF_FORMS if name in pinned]

    @staticmethod
    def names_this_repository(text: str) -> bool:
        """Whether text names this repository, as a URL or a path (_ASH_REPOSITORY).

        An allowance for another project's pin must never excuse an entry that names
        this repository: the pin in it is ASH's, in a shape no anchor reads.
        """
        return re.search(_ASH_REPOSITORY, text) is not None

    @staticmethod
    def unrecognized_pins(text: str) -> List[UnrecognizedPin]:
        """Every pin ASH_PIN_PATTERNS rejects, with the line and entry that hold it.

        The readers above take only what ASH_PIN_PATTERNS anchors on this repository,
        so another project's tag is not counted as ASH's. The same rule hides a pin of
        ASH written in a shape no anchor knows (a `rev:` before its `repo:`, a
        flow-style `{repo: ..., rev: ...}` entry, a clone of a URL held in a variable),
        which then renders stale on every build and passes the checks that read pins.
        This lists every `<install-ref prefix>v<version>` that no pattern accepted, so
        a check can name it: the pin is either another project's, to be allowed
        explicitly, or ASH's, and needs its shape added to ASH_PIN_PATTERNS. The entry
        is what an allowance is matched against: the project's name sits on the `repo:`
        line above a block-style `rev:` or in the URL of a clone, not always on the line
        of the pin.
        """
        recognized = {start for _form, _version, start in _ash_pins(text)}
        lines = text.split("\n")
        found = []
        for name, install_prefix, _branch in INSTALL_REF_FORMS:
            prefix = _LOOSE_PREFIX.get(name, install_prefix)
            for match in re.finditer(rf"(?:{prefix})v(?P<version>{_SEMVER})", text):
                if match.start("version") in recognized:
                    continue
                index = text.count("\n", 0, match.start())
                line_start = text.rfind("\n", 0, match.start()) + 1
                found.append(
                    UnrecognizedPin(
                        name,
                        match.group("version"),
                        lines[index].strip(),
                        _entry_around(
                            lines,
                            index,
                            match.start() - line_start,
                            match.end() - line_start,
                        ),
                    )
                )
        return found

    @staticmethod
    def branch_ref_pattern(form: str, branch: str) -> "re.Pattern[str]":
        """The named install-command form, naming branch instead of a release."""
        rendering = next(b for name, _p, b in INSTALL_REF_FORMS if name == form)
        return re.compile(rendering.format(branch=re.escape(branch)) + r"(?![\w.-])")

    def release_in_install_ref(self) -> "re.Pattern[str]":
        """The release placeholder written as the ref of an install command."""
        prefixes = "|".join(prefix for _name, prefix, _branch in INSTALL_REF_FORMS)
        return re.compile(f"(?:{prefixes})v?" + re.escape(self.release_placeholder))

    def convert_to_template(self, file_path: Path, overwrite: bool = False) -> bool:
        """
        Convert a file to template format by replacing version numbers with placeholders.

        An existing template is kept unless ``overwrite`` is set. A template is
        hand-maintained once it exists: it carries placeholders (``{{RELEASE}}`` in a
        table, say) that the rendered doc holds only as plain numbers, which the
        patterns here do not recognize, so a convert from the doc wrote a template
        with those placeholders gone and the next generate stamped the stale doc
        over every edit made to the template.

        Args:
            file_path: Path to the file to convert.
            overwrite: Replace an existing template instead of keeping it.

        Returns:
            True if conversion was successful and changes were made. False for a skip
            and for a failure alike; convert_file tells them apart. A call made
            directly does not touch ``failures``, which describes one
            convert_all_to_templates run.
        """
        return self.convert_file(file_path, overwrite) is FileResult.DONE

    def convert_file(self, file_path: Path, overwrite: bool = False) -> FileResult:
        """convert_to_template, telling a failure from a skip.

        DONE when a template was written; SKIPPED for a reason that is not an error (a
        template kept, no version reference, no change); FAILED for an error, which it
        has already printed, a listed page that does not exist included.
        """
        if not file_path.exists():
            # A listed target with no page is the convert-side twin of a target with no
            # template, which generate reports as a failure: the list names a file that
            # was renamed or deleted, and a run that exits 0 over it hides that.
            print(f"Error: File {file_path} does not exist.")
            return FileResult.FAILED

        template_path = file_path.with_suffix(file_path.suffix + self.template_suffix)
        if template_path.exists() and not overwrite:
            print(
                f"Template {template_path} exists; keeping it (convert replaces an "
                "existing template only with --overwrite)"
            )
            return FileResult.SKIPPED

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content
            patterns = self.find_version_references(content)

            if not patterns:
                print(f"No version references found in {file_path}")
                return FileResult.SKIPPED

            # Apply all patterns
            for old_pattern, new_pattern in patterns:
                content = re.sub(old_pattern, new_pattern, content)

            if content == original_content:
                print(f"No changes made to {file_path}")
                return FileResult.SKIPPED

            # Create template file
            with open(template_path, "w", encoding="utf-8") as f:
                f.write(content)

            print(f"Created template: {template_path}")
            return FileResult.DONE

        except Exception as e:
            print(f"Error converting {file_path} to template: {e}")
            return FileResult.FAILED

    def _version_to_render(self) -> str:
        """The version of the checkout the templates belong to, never "unknown"."""
        # Imported here rather than at the top, so loading this module (as the
        # mkdocs hook docs/hooks/install_refs.py does) does not import ASH.
        from automated_security_helper.utils.version_management import get_version

        # Read from the checkout's pyproject.toml: the installed distribution's
        # metadata lags a `version_bump.py set` until the next install, and rendered
        # the old version into every doc.
        version = get_version(self.project_root)
        if version == "unknown":
            # get_version's last resort when neither the checkout's pyproject.toml
            # nor installed metadata names a version. Rendered, it would replace
            # every pin in every doc with the word "unknown".
            raise ValueError(
                f"no version could be determined for {self.project_root}; "
                "not rendering the docs with a placeholder version"
            )
        return version

    def generate_from_template(self, template_path: Path) -> bool:
        """
        Generate final file from template by replacing placeholders with actual version.

        Args:
            template_path: Path to the template file.

        Returns:
            True if generation was successful. False is always a failure here: a
            template is never skipped. A call made directly does not touch
            ``failures``, which describes one generate_all_from_templates run.
        """
        return self.generate_file(template_path) is FileResult.DONE

    def generate_file(self, template_path: Path) -> FileResult:
        """generate_from_template as a FileResult: DONE or FAILED, never SKIPPED."""
        if not template_path.exists():
            # The same words as a convert target with no page: both are failures.
            print(f"Error: Template {template_path} does not exist.")
            return FileResult.FAILED

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()

            # generate_all_from_templates reads the version once for its whole run.
            version = self._run_version or self._version_to_render()
            content = self.render(content, version)

            # Generate output file (remove .template suffix)
            output_path = template_path.with_suffix("")
            if template_path.suffix == self.template_suffix:
                # Remove the .template part, keep the original extension
                name_without_template = template_path.name[: -len(self.template_suffix)]
                output_path = template_path.parent / name_without_template

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)

            print(f"Generated {output_path} from template")
            return FileResult.DONE

        except Exception as e:
            print(f"Error generating from template {template_path}: {e}")
            return FileResult.FAILED

    def convert_all_to_templates(self, overwrite: bool = False) -> int:
        """
        Convert all target files to templates.

        Args:
            overwrite: Replace existing templates instead of keeping them.

        Returns:
            Number of files successfully converted. A file that failed with an
            error, or that is listed in ``target_files`` and does not exist, is
            listed in ``failures``; a file skipped for a reason that is not an
            error (a template kept, no version reference) is not.
        """
        self.failures = []
        converted_count = 0

        for file_path_str in self.target_files:
            file_path = self.project_root / file_path_str
            result = self.convert_file(file_path, overwrite)
            if result is FileResult.FAILED:
                self.failures.append(file_path)
            elif result is FileResult.DONE:
                converted_count += 1

        return converted_count

    def template_path_for(self, target: str) -> Path:
        """The template that ``generate`` renders into the ``target_files`` entry.

        One rule for everything that walks the ``target_files`` list (generate, list,
        and the version checker): the template sits beside its target with the
        template suffix appended to the name. ``convert_file`` is handed the page
        itself, which can be any path, and builds the same name from it.
        """
        return self.project_root / (target + self.template_suffix)

    def generate_all_from_templates(self) -> int:
        """
        Generate all files from their templates.

        The version is read once, before the first template: when it cannot be
        determined that is one error for the run, with every target listed in
        ``failures``, not one error per template.

        Returns:
            Number of files successfully generated. Every target that is not
            generated is listed in ``failures``.
        """
        self.failures = []
        generated_count = 0
        templates = [
            self.template_path_for(file_path_str) for file_path_str in self.target_files
        ]

        try:
            self._run_version = self._version_to_render()
        except Exception as e:
            print(f"Error generating from templates: {e}")
            self.failures.extend(templates)
            return 0

        try:
            for template_path in templates:
                if self.generate_from_template(template_path):
                    generated_count += 1
                else:
                    self.failures.append(template_path)
        finally:
            self._run_version = None

        return generated_count

    def list_templates(self) -> List[Path]:
        """List all existing template files."""
        templates = []
        for file_path_str in self.target_files:
            template_path = self.template_path_for(file_path_str)
            if template_path.exists():
                templates.append(template_path)
        return templates


def _report_failures(manager: VersionTemplateManager, what: str) -> int:
    """Name the files that failed on stderr and return the exit status for them."""
    names = ", ".join(str(path) for path in manager.failures)
    print(
        f"Error: {len(manager.failures)} file(s) were not {what}: {names}",
        file=sys.stderr,
    )
    return 1


def main() -> int:
    """Main entry point. Returns the exit status: 1 when a file failed."""
    parser = argparse.ArgumentParser(
        description="Manage version templates for documentation"
    )
    parser.add_argument(
        "action",
        choices=["convert", "generate", "list"],
        help="Action to perform: convert files to templates, generate from templates, or list templates",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).parent.parent,
        help="Path to project root directory",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="convert: replace an existing .template instead of keeping it",
    )

    args = parser.parse_args()

    manager = VersionTemplateManager(args.project_root)

    if args.action == "convert":
        print("Converting files to templates...")
        count = manager.convert_all_to_templates(overwrite=args.overwrite)
        if manager.failures:
            return _report_failures(manager, "converted to templates")
        print(f"Successfully converted {count} files to templates.")

    elif args.action == "generate":
        print("Generating files from templates...")
        count = manager.generate_all_from_templates()
        if manager.failures:
            return _report_failures(manager, "generated from templates")
        print(f"Successfully generated {count} files from templates.")

    elif args.action == "list":
        templates = manager.list_templates()
        if templates:
            print("Existing template files:")
            for template in templates:
                print(f"  {template}")
        else:
            print("No template files found.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
