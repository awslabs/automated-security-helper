#!/usr/bin/env python3
"""Fails when a change adds a line to the seeds of the docs' unrun blocks.

WHY THIS EXISTS
---------------
The docs are moving to blocks that all run. Two seeds freeze what does not run yet, so
that the count of such blocks can only go down:

* ``docs/illustrative-seed/``, one file per page: a line for each
  ``<!-- doctest: illustrative reason="..." -->`` marker, the page's path, a tab and the
  marker's reason;
* ``scripts/docs_unexecuted_commands_seed.tsv``: a line for each block in a language
  nothing runs (text and the rest) that shows a command, the page's path, a tab and the
  block's first command.

``check_markers`` in scripts/docs_checks.py (the lint job) holds each seed equal to the
pages: a marker or a block the seed does not list is a finding, and so is a seed line
that nothing matches, so a change that converts a block deletes its line in the same
commit. That alone lets a pull request add the line that covers its own new marker, and
every check passes. This script is the other half. The seeds at the head may hold no
line that the seeds at the fork point do not: a conversion deletes lines, and nothing
puts one back.

WHAT IT COMPARES
----------------
A line is its page and its text. The head may hold each (page, text) at most as many
times as the fork point did. A second identical line is therefore a violation, so is a
reworded reason (it is a new line), and so is a line moved from one page to another.
The one allowance is a page that git reports as moved between the two points
(``git diff --find-renames``, which pairs a file with its old path from 50% similarity):
its lines are looked up under its old path. A page moved and rewritten in one change can
fall under that bar, and then its lines are new ones: move it in a pull request of its
own, without edits.

A seed the fork point does not have is not compared. The change that introduces it has
nothing to be held to, and a note says so; every later range is held to what it left.
Files in the seed directory that are not a ``.tsv`` directly in it are not seeds, as
docs_checks reads it.

HOW THE RANGE IS CHOSEN
-----------------------
Like check-snapshot-trailers.py, whose ``resolve_range`` this loads, so both checks read
an event the same way (pull_request, merge_group, push and workflow_dispatch). The seeds
at the head are compared with the seeds at the FORK POINT, the merge base of the head
with the base branch, never with the tip of the base branch: main may have shrunk the
seeds since the pull request was cut, and that is not the pull request's difference. A
new ref and a force-push have no range, so their tip commit is compared with its first
parent. With ``--base``, the fork point is the merge base of BASE and HEAD.

The checkout must have full history (``fetch-depth: 0``), as for the trailer check.

USAGE
-----
    python3 .github/scripts/check-illustrative-ratchet.py --self-test
    python3 .github/scripts/check-illustrative-ratchet.py          # the event's range
    python3 .github/scripts/check-illustrative-ratchet.py --base origin/main --head HEAD

Standard library only, like the other gate scripts, so the job installs nothing.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable
from urllib.parse import quote

#: The two seeds. These are the paths scripts/docs_checks.py reads (its
#: ILLUSTRATIVE_SEED_DIR and UNEXECUTED_SEED_FILE); a unit test holds the two equal.
ILLUSTRATIVE_SEED_DIR = "docs/illustrative-seed"
ILLUSTRATIVE_SEED_SUFFIX = ".tsv"
UNEXECUTED_SEED_FILE = "scripts/docs_unexecuted_commands_seed.tsv"

ILLUSTRATIVE = "illustrative"
UNEXECUTED = "unexecuted"
SEEDS = (ILLUSTRATIVE, UNEXECUTED)

#: The files git pairs by similarity to find a page that moved.
PAGE_PATHSPECS = ("*.md", "*.md.template")

TRAILERS_SCRIPT = Path(__file__).resolve().with_name("check-snapshot-trailers.py")


def _load_trailers():
    """The sibling script, which owns how an event's range is read, loaded by path.

    Registered in sys.modules before it runs, as its dataclasses resolve their
    annotations through the module's entry there.
    """
    name = "_ash_check_snapshot_trailers"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, TRAILERS_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {TRAILERS_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


trailers = _load_trailers()
GitError = trailers.GitError
git = trailers.git
ZERO_SHA = trailers.ZERO_SHA


@dataclass(frozen=True)
class Entry:
    """One line of a seed file."""

    file: str
    number: int
    page: str
    text: str


@dataclass(frozen=True)
class Violation:
    """A line the head's seed holds that the fork point's does not."""

    seed: str  # ILLUSTRATIVE or UNEXECUTED
    file: str  # the seed file at the head that holds the line
    page: str  # the page the line is for
    base_page: str  # the page it was looked up under at the fork point
    text: str  # the marker's reason, or the block's first command
    number: int  # the line's number in ``file``


# ---------------------------------------------------------------------------
# Reading the seeds at a commit
# ---------------------------------------------------------------------------


def seed_paths(repo: Path, rev: str) -> dict[str, list[str]]:
    """The tracked files of each seed at ``rev``.

    The illustrative seed lists everything under its directory: a directory that holds
    a file is a seed that exists (docs_checks arms on the directory), whatever the
    file. read_seed keeps the ``.tsv`` files, which are the seed's.
    """
    listing = git(
        repo,
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        rev,
        "--",
        f"{ILLUSTRATIVE_SEED_DIR}/",
        UNEXECUTED_SEED_FILE,
    )
    paths = [path for path in listing.split("\0") if path]
    return {
        ILLUSTRATIVE: [
            path for path in paths if path.startswith(f"{ILLUSTRATIVE_SEED_DIR}/")
        ],
        UNEXECUTED: [path for path in paths if path == UNEXECUTED_SEED_FILE],
    }


def read_blobs(repo: Path, rev: str, paths: list[str]) -> dict[str, str]:
    """The text of each of ``paths`` at ``rev``, read exactly by one ``git cat-file``.

    Not ``git grep``, which skips a file that holds a NUL byte, and with it the lines
    the file would add.
    """
    if not paths:
        return {}
    for path in paths:
        if any(ord(char) < 32 for char in path):
            raise GitError(f"{path!r} has a control character in its name")
    request = "".join(f"{rev}:{path}\n" for path in paths).encode("utf-8")
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input=request,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        reason = proc.stderr.decode("utf-8", "replace").strip()
        raise GitError(f"git cat-file failed: {reason}")
    out, position = proc.stdout, 0
    blobs: dict[str, str] = {}
    for path in paths:
        end = out.index(b"\n", position)
        header = out[position:end].decode("utf-8", "replace").split()
        position = end + 1
        if len(header) != 3 or header[1] != "blob":
            raise GitError(f"{rev}:{path} is not a file ({' '.join(header)})")
        size = int(header[2])
        blobs[path] = out[position : position + size].decode("utf-8", "replace")
        position += size + 1  # the content, then the newline that ends it
    return blobs


def parse_seed(file: str, text: str) -> list[Entry]:
    """The lines of a seed file's ``text`` that are a page's path, a tab and a text.

    Any other row is not a line here; docs_checks reports it as malformed.
    """
    entries = []
    for number, row in enumerate(text.split("\n"), 1):
        page, tab, rest = row.partition("\t")
        if page and tab and rest:
            entries.append(Entry(file, number, page, rest))
    return entries


def _is_seed_file(path: str) -> bool:
    return (
        PurePosixPath(path).parent.as_posix() == ILLUSTRATIVE_SEED_DIR
        and path.endswith(ILLUSTRATIVE_SEED_SUFFIX)
    )


def read_seed(repo: Path, rev: str, seed: str, paths: list[str]) -> list[Entry]:
    """The lines of ``seed`` at ``rev``, from its files among ``paths``."""
    if seed == ILLUSTRATIVE:
        paths = [path for path in paths if _is_seed_file(path)]
    blobs = read_blobs(repo, rev, paths)
    return [entry for path in paths for entry in parse_seed(path, blobs[path])]


def page_renames(repo: Path, base: str, head: str) -> dict[str, str]:
    """{new path: old path} for each page git reports moved from ``base`` to ``head``.

    Only the pages are paired, so the search for a moved file does not grow with the
    other files a range touches, and ``-l0`` lifts the cap on it.
    """
    listing = git(
        repo,
        "diff",
        "--find-renames",
        "-l0",
        "--name-status",
        "-z",
        base,
        head,
        "--",
        *PAGE_PATHSPECS,
    )
    fields = listing.split("\0")
    renames: dict[str, str] = {}
    index = 0
    while index < len(fields) and fields[index]:
        if fields[index].startswith("R"):
            renames[fields[index + 2]] = fields[index + 1]
            index += 3
        else:
            index += 2
    return renames


# ---------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------


def compare(
    seed: str,
    base_entries: list[Entry],
    head_entries: list[Entry],
    renames: dict[str, str],
) -> list[Violation]:
    """The head's lines that the fork point's do not cover.

    Each (page, text) at the fork point covers one line at the head, so the count of a
    line may fall and may not rise. A line of a moved page is looked up under the page's
    old path.
    """
    allowed = Counter((entry.page, entry.text) for entry in base_entries)
    violations = []
    for entry in head_entries:
        base_page = renames.get(entry.page, entry.page)
        key = (base_page, entry.text)
        if allowed[key] > 0:
            allowed[key] -= 1
        else:
            violations.append(
                Violation(
                    seed, entry.file, entry.page, base_page, entry.text, entry.number
                )
            )
    return violations


def find_added_lines(
    repo: Path, base: str, head: str
) -> tuple[list[Violation], list[str]]:
    """The lines the seeds at ``head`` hold that those at ``base`` do not, and notes.

    ``base`` is the fork point. A seed that does not exist at ``base`` has nothing to be
    compared with, and a note says that this range introduces it.
    """
    base_paths = seed_paths(repo, base)
    head_paths = seed_paths(repo, head)
    violations: list[Violation] = []
    notes: list[str] = []
    renames: dict[str, str] | None = None
    for seed in SEEDS:
        head_entries = read_seed(repo, head, seed, head_paths[seed])
        if not base_paths[seed]:
            if head_entries:
                notes.append(
                    f"the {seed} seed is not in the base ({base[:10]}), so this range "
                    f"introduces it and there is nothing to compare its "
                    f"{len(head_entries)} line(s) with"
                )
            continue
        if not head_entries:
            continue  # nothing can have been added
        if renames is None:
            renames = page_renames(repo, base, head)
        base_entries = read_seed(repo, base, seed, base_paths[seed])
        violations += compare(seed, base_entries, head_entries, renames)
    return violations, notes


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _annotation_data(text: str) -> str:
    # A reason or a command is author-controlled and lands in a workflow command, so it
    # gets the runner's own escaping and cannot end the annotation or start a new one.
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _annotation_property(text: str) -> str:
    return _annotation_data(text).replace(":", "%3A").replace(",", "%2C")


def explain(violation: Violation, base: str) -> str:
    where = (
        "the illustrative seed"
        if violation.seed == ILLUSTRATIVE
        else f"the unexecuted-command seed ({UNEXECUTED_SEED_FILE})"
    )
    moved = (
        f" (looked up as {violation.base_page}, where git sees the page at the fork "
        "point)"
        if violation.base_page != violation.page
        else ""
    )
    if violation.seed == ILLUSTRATIVE:
        fix = (
            "A block that cannot run yet is no reason to add a line: make it run, "
            "and delete its line in the same commit."
        )
    else:
        fix = (
            "Fence the command as bash so the docs runner executes it, or, if the "
            "block is what the block above it prints, mark it output."
        )
    return (
        f"{violation.file}:{violation.number} adds a line for {violation.page}"
        f"{moved} that {where} did not hold at the fork point ({base[:10]}): "
        f"{violation.text!r}. The seed only shrinks, so a line is never added to it, "
        f"never reworded and never moved to another page. {fix} If the page was only "
        "moved, move it in a pull request of its own, with no other edit, so git sees "
        "the move and the lines follow it."
    )


def report(violations: list[Violation], base: str) -> None:
    for violation in violations:
        print(
            f"::error file={_annotation_property(violation.file)},"
            f"line={violation.number}::{_annotation_data(explain(violation, base))}"
        )


# ---------------------------------------------------------------------------
# The range
# ---------------------------------------------------------------------------


def range_of_event(
    repo: Path, event_name: str, payload: dict
) -> tuple[str, str, str] | None:
    """(base, head, what) of the commits an event introduces; None when it has no base.

    The base is the fork point resolve_range chose. A range with none (a new ref, a
    force-push) is the tip commit against its first parent, and a root commit, which has
    no parent, has nothing to be compared with.
    """
    rng = trailers.resolve_range(repo, event_name, payload)
    if rng is None:
        return None
    base = rng.base
    if base is None:
        parents = git(repo, "rev-list", "--parents", "-n", "1", rng.head).split()[1:]
        if not parents:
            return None
        base = parents[0]
    return base, rng.head, rng.note


def run_check(repo: Path, base: str, head: str, what: str) -> int:
    violations, notes = find_added_lines(repo, base, head)
    for note in notes:
        print(f"::notice::{_annotation_data(note)}")
    report(violations, base)
    print(
        f"illustrative ratchet ({what}, {base[:10]}..{head[:10]}): "
        f"{len(violations)} line(s) added to the seeds"
    )
    return 1 if violations else 0


# ---------------------------------------------------------------------------
# The self-test
#
# A checker that has degenerated into finding nothing exits 0 and reads as a clean tree,
# and one that flags everything fails every pull request, so the first thing the job
# runs is this: planted ranges the check must flag, each beside the clean range that
# must pass. Every case runs through the same functions the real check uses.
# ---------------------------------------------------------------------------

DOCKER = "needs Docker"
BUCKET = "writes to a real bucket"
SCAN = "ash scan --source-dir ."

#: Long enough that git, comparing a page with its old path, sees the same file.
FILLER = "".join(
    f"Line {number} of a page long enough for git to see a move.\n"
    for number in range(12)
)


def _seed_file(page: str) -> str:
    return f"{ILLUSTRATIVE_SEED_DIR}/{quote(page, safe='')}{ILLUSTRATIVE_SEED_SUFFIX}"


def _page_text(reasons: tuple[str, ...]) -> str:
    blocks = "\n".join(
        f'<!-- doctest: illustrative reason="{reason}" -->\n```bash\ndocker ps\n```\n'
        for reason in reasons
    )
    return f"# Page\n\n{FILLER}\n{blocks}"


class _SelfRepo:
    """A repository the self-test builds. Its base commit holds two pages with markers,
    their seed files and the unexecuted-command seed, or, when ``seeded`` is false, one
    file and no seed at all."""

    def __init__(self, path: Path, seeded: bool = True) -> None:
        self.path = path
        path.mkdir(parents=True)
        self.git("init", "-q", "-b", "main")
        if seeded:
            self.mark("docs/a.md", DOCKER, BUCKET)
            self.mark("docs/b.md", DOCKER)
            self.write(UNEXECUTED_SEED_FILE, f"docs/a.md\t{SCAN}\n")
        else:
            self.write("README.md", "x\n")
        self.base = self.commit("base")

    def git(self, *args: str) -> str:
        # Isolated from the caller's config: no signing prompt, no hooks, a fixed
        # identity.
        return git(
            self.path,
            "-c",
            "user.name=self-test",
            "-c",
            "user.email=self-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        )

    def write(self, rel: str, text: str) -> None:
        target = self.path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")

    def move(self, old: str, new: str) -> None:
        (self.path / new).parent.mkdir(parents=True, exist_ok=True)
        self.git("mv", old, new)

    def mark(self, page: str, *reasons: str) -> None:
        """Make ``page`` carry a marker for each reason, and write the seed file that
        lists them; with no reason the page has no marker and no seed file."""
        self.write(page, _page_text(reasons))
        seed = self.path / _seed_file(page)
        if reasons:
            self.write(
                _seed_file(page), "".join(f"{page}\t{reason}\n" for reason in reasons)
            )
        elif seed.exists():
            seed.unlink()

    def commit(self, message: str = "change") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.head()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").strip()


Case = Callable[[_SelfRepo], list[tuple[str, str]]]


def _case_untouched(r: _SelfRepo) -> list[tuple[str, str]]:
    r.commit("nothing")
    return []


def _case_line_added(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/b.md", DOCKER, BUCKET)
    r.commit("a second marker on b")
    return [("docs/b.md", BUCKET)]


def _case_new_page(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/c.md", DOCKER)
    r.commit("a new page with a marker, and the line that covers it")
    return [("docs/c.md", DOCKER)]


def _case_duplicate(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/b.md", DOCKER, DOCKER)
    r.commit("the same reason twice")
    return [("docs/b.md", DOCKER)]


def _case_one_converted(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/a.md", DOCKER)
    r.commit("a marker of a converted")
    return []


def _case_page_converted(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/b.md")
    r.commit("b converted, and its seed file gone")
    return []


def _case_reworded(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/b.md", "needs the Docker daemon")
    r.commit("the reason of b reworded")
    return [("docs/b.md", "needs the Docker daemon")]


def _case_swap(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/b.md")
    r.mark("docs/c.md", DOCKER)
    r.commit("b converted, c marked in its place")
    return [("docs/c.md", DOCKER)]


def _case_body_edited(r: _SelfRepo) -> list[tuple[str, str]]:
    text = _page_text((DOCKER, BUCKET)).replace("docker ps", "docker ps -a")
    r.write("docs/a.md", text)
    r.commit("the body of a marked block edited, its seed untouched")
    return []


def _case_moved(r: _SelfRepo) -> list[tuple[str, str]]:
    r.move("docs/b.md", "docs/moved/b.md")
    r.move(_seed_file("docs/b.md"), _seed_file("docs/moved/b.md"))
    r.write(_seed_file("docs/moved/b.md"), f"docs/moved/b.md\t{DOCKER}\n")
    r.commit("b moved, with its line")
    return []


def _case_moved_and_added(r: _SelfRepo) -> list[tuple[str, str]]:
    r.move("docs/b.md", "docs/moved/b.md")
    r.move(_seed_file("docs/b.md"), _seed_file("docs/moved/b.md"))
    r.mark("docs/moved/b.md", DOCKER, BUCKET)
    r.commit("b moved, and a line added")
    return [("docs/moved/b.md", BUCKET)]


def _case_pointed_elsewhere(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/b.md")
    r.write("docs/c.md", _page_text((DOCKER,)))
    r.write(_seed_file("docs/c.md"), f"docs/c.md\t{DOCKER}\n")
    r.commit("the line of b pointed at c, which no move connects to b")
    return [("docs/c.md", DOCKER)]


def _case_template(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/a.md.template", DOCKER)
    r.commit("a template given a marker beside the page it renders to")
    return [("docs/a.md.template", DOCKER)]


def _case_command_added(r: _SelfRepo) -> list[tuple[str, str]]:
    offline = "ash scan --offline"
    r.write(UNEXECUTED_SEED_FILE, f"docs/a.md\t{SCAN}\ndocs/b.md\t{offline}\n")
    r.commit("a command added to the seed")
    return [("docs/b.md", offline)]


def _case_command_removed(r: _SelfRepo) -> list[tuple[str, str]]:
    r.write(UNEXECUTED_SEED_FILE, "")
    r.commit("the command converted")
    return []


def _case_not_seeds(r: _SelfRepo) -> list[tuple[str, str]]:
    r.write(f"{ILLUSTRATIVE_SEED_DIR}/notes.txt", f"docs/z.md\t{DOCKER}\n")
    r.write(f"{ILLUSTRATIVE_SEED_DIR}/nested/z.tsv", f"docs/z.md\t{DOCKER}\n")
    r.commit("lines in files that docs_checks does not read")
    return []


def _case_introduced(r: _SelfRepo) -> list[tuple[str, str]]:
    r.mark("docs/a.md", DOCKER)
    r.write(UNEXECUTED_SEED_FILE, f"docs/a.md\t{SCAN}\n")
    r.commit("the seeds")
    return []


#: (name, the change, whether the base holds the seeds). A case returns the (page, text)
#: of each line the check must report, and nothing when it must pass.
_CASES: tuple[tuple[str, Case, bool], ...] = (
    ("a range that leaves the seeds alone", _case_untouched, True),
    ("a line added to a seeded page", _case_line_added, True),
    ("a new page with a new line", _case_new_page, True),
    ("a second identical line", _case_duplicate, True),
    ("one marker converted", _case_one_converted, True),
    ("a whole page converted", _case_page_converted, True),
    ("a reworded reason", _case_reworded, True),
    ("a converted page swapped for a new one", _case_swap, True),
    ("the body of a marked block edited", _case_body_edited, True),
    ("a page moved with its line", _case_moved, True),
    ("a page moved and a line added", _case_moved_and_added, True),
    ("a line pointed at another page", _case_pointed_elsewhere, True),
    ("a template given a marker", _case_template, True),
    ("a command added to the unexecuted seed", _case_command_added, True),
    ("a command removed from it", _case_command_removed, True),
    ("files that are not seeds", _case_not_seeds, True),
    ("a range that introduces the seeds", _case_introduced, False),
)


def _event_lines(
    repo: Path, event_name: str, payload: dict
) -> list[tuple[str, str]] | None:
    """The lines an event adds to the seeds, as the real check reads them; None when the
    event has no range."""
    chosen = range_of_event(repo, event_name, payload)
    if chosen is None:
        return None
    base, head, _what = chosen
    violations, _notes = find_added_lines(repo, base, head)
    return sorted((v.page, v.text) for v in violations)


def _self_test_events(tmp: Path) -> list[str]:
    """The range of each event is the fork point, not the tip of the base branch."""
    failures: list[str] = []
    r = _SelfRepo(tmp / "events")
    base = r.base
    r.git("checkout", "-q", "-b", "clean")
    clean = r.commit("a pull request that leaves the seeds alone")
    r.git("checkout", "-q", "main")
    r.git("checkout", "-q", "-b", "dirty")
    r.mark("docs/b.md", DOCKER, "an added reason")
    dirty = r.commit("a pull request that adds a line")
    r.git("checkout", "-q", "main")
    r.mark("docs/b.md")
    moved_on = r.commit("main converted b since the pull requests were cut")
    added = [("docs/b.md", "an added reason")]
    cases = (
        (
            "a pull request cut before main shrank the seed, and leaving it alone",
            "pull_request",
            {"pull_request": {"base": {"sha": moved_on}, "head": {"sha": clean}}},
            [],
        ),
        (
            "a pull request that adds a line, against a main that moved on",
            "pull_request",
            {"pull_request": {"base": {"sha": moved_on}, "head": {"sha": dirty}}},
            added,
        ),
        (
            "a merge queue entry cut before main shrank the seed",
            "merge_group",
            {"merge_group": {"base_sha": moved_on, "head_sha": clean}},
            [],
        ),
        (
            "a merge queue entry that adds a line",
            "merge_group",
            {"merge_group": {"base_sha": moved_on, "head_sha": dirty}},
            added,
        ),
        (
            "a push that leaves the seeds alone",
            "push",
            {"before": base, "after": clean},
            [],
        ),
        (
            "a push that adds a line",
            "push",
            {"before": base, "after": dirty},
            added,
        ),
        (
            "a new ref, read as its tip against its parent",
            "push",
            {"before": ZERO_SHA, "after": dirty},
            added,
        ),
        (
            "a new ref whose tip is a root commit",
            "push",
            {"before": ZERO_SHA, "after": base},
            None,
        ),
    )
    for name, event_name, payload, expected in cases:
        got = _event_lines(r.path, event_name, payload)
        if got != expected:
            failures.append(f"{name}: expected {expected}, got {got}")
    return failures


def self_test() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="illustrative-ratchet-") as tmpdir:
        tmp = Path(tmpdir)
        for index, (name, case, seeded) in enumerate(_CASES):
            r = _SelfRepo(tmp / f"case{index}", seeded)
            expected = sorted(case(r))
            violations, notes = find_added_lines(r.path, r.base, r.head())
            got = sorted((v.page, v.text) for v in violations)
            if got != expected:
                failures.append(f"{name}: expected {expected}, got {got}")
            if not seeded and not any("not in the base" in note for note in notes):
                failures.append(f"{name}: no note said the base has no seed: {notes}")
        failures += _self_test_events(tmp)
    for failure in failures:
        print(f"::error::self-test: {failure}")
    print(
        f"self-test: {len(_CASES)} seed cases plus event cases, "
        f"{len(failures)} failure(s)"
    )
    return 1 if failures else 0


# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--base",
        help="compare the seeds at the merge base of BASE and HEAD with HEAD's, "
        "instead of reading the event's range",
    )
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()
    try:
        if opts.base:
            base = trailers.fork_point(opts.repo, [opts.base], opts.head)
            head, what = opts.head, f"{opts.base}..{opts.head}"
        else:
            event_name = os.environ.get("GITHUB_EVENT_NAME")
            event_path = os.environ.get("GITHUB_EVENT_PATH")
            if not event_name or not event_path:
                parser.error("outside Actions, pass --base (e.g. --base origin/main)")
            payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
            chosen = range_of_event(opts.repo, event_name, payload)
            if chosen is None:
                print(f"{event_name}: no commit with a base to compare; nothing to do.")
                return 0
            base, head, what = chosen
        return run_check(opts.repo, base, head, what)
    except GitError as exc:
        print(f"::error::{exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
