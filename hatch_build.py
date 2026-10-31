"""
Custom Hatch build hook to stage build assets.
"""

import os
import re
import shutil
import subprocess  # nosec B404 - This code is run during package build
import sys
from pathlib import Path
from hatchling.builders.hooks.plugin.interface import BuildHookInterface


def _say(message: str) -> None:
    """print(), with any character the console cannot encode written as an escape.

    pip runs a build hook with its output on a pipe, and on Windows a pipe takes
    the ANSI code page (cp1252 and the like), which has no form for most of
    Unicode. A plain print of a path or of git's message then raised
    UnicodeEncodeError, and the handler below recorded "build-error" in place of
    the commit it had already found.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    print(message.encode(encoding, "backslashreplace").decode(encoding))


ASH_REPO_ROOT: Path = Path(__file__).parent
ASH_ASSETS_PATH: Path = ASH_REPO_ROOT.joinpath("automated_security_helper", "assets")
ASH_INSTALLED_REVISION_PATH: Path = ASH_ASSETS_PATH.joinpath("ASH_INSTALLED_REVISION")

# Files the root Dockerfile COPYs from elsewhere in the package, as
# (path under automated_security_helper/, filename inside assets/).
#
# The shipped Dockerfile's build context is the assets directory itself --
# run_ash_container._build_image passes `dockerfile_path.parent` as the context --
# so a COPY naming any path outside assets/ fails there with "file not found"
# while working perfectly from a checkout. These two are staged flat into assets/
# and their COPY lines rewritten to match, the same treatment
# `COPY automated_security_helper/assets/...` already gets below.
#
# They are the pinned tool table and the exception module it imports, needed by
# assets/install-pinned-tool.py before the ASH wheel exists in the image. See that
# script's docstring for why it cannot just call download_utils.install_pinned_tool.
DOCKERFILE_STAGED_PACKAGE_FILES: tuple = (
    ("utils/tool_downloads.py", "tool_downloads.py"),
    ("core/exceptions.py", "exceptions.py"),
)


class StagedSourceMissingError(FileNotFoundError):
    """A file DOCKERFILE_STAGED_PACKAGE_FILES names is not in the tree being built.

    _stage_assets fails the build on this, as it does on every other error of the
    Dockerfile staging. It is a class of its own so that it is told apart from the
    plain FileNotFoundError that _get_commit_sha raises when git is found on PATH
    but cannot be run (its interpreter missing, say). That is an unrunnable git,
    which _record_commit meets by recording "build-error" and letting the build
    continue: it costs the revision and leaves the artifact complete.
    """


# The path every asset the root Dockerfile COPYs is under in a checkout. Inside
# the shipped Dockerfile's build context (assets/ itself) the same file is at the
# bare name, so the prefix comes off every source of every COPY.
_ASSETS_PREFIX = "automated_security_helper/assets/"


def _staged_source(token: str) -> str:
    """A COPY source as the assets build context names it, or the token itself.

    A source in DOCKERFILE_STAGED_PACKAGE_FILES becomes its staged name; a source
    under ``automated_security_helper/assets/`` loses that prefix. Any other
    source, such as ``.``, is already a path the context contains and is kept.
    """
    for source_rel, staged_name in DOCKERFILE_STAGED_PACKAGE_FILES:
        if token == f"automated_security_helper/{source_rel}":
            return staged_name
    if token.startswith(_ASSETS_PREFIX):
        return token[len(_ASSETS_PREFIX) :]
    return token


def _continues(line: str) -> bool:
    """Whether a Dockerfile line ends in a ``\\`` continuation.

    A comment line inside an instruction is dropped by the Dockerfile parser,
    so a ``\\`` ending one continues nothing. The root Dockerfile keeps the
    default escape character; no ``# escape=`` directive is read here.
    """
    stripped = line.rstrip()
    return (
        bool(stripped)
        and not stripped.lstrip().startswith("#")
        and stripped.endswith("\\")
    )


def _staged_instruction(text: str) -> str:
    """One COPY or ADD instruction, its continuation lines joined, sources staged.

    The instruction is read as tokens: the instruction word, its ``--`` flags,
    its sources, and the destination last. Only a source token is rewritten,
    through _staged_source, so a destination that happens to hold the assets
    path keeps it, and a flag is never a source. A ``--from=`` instruction reads
    another image stage, not the build context: its paths are that stage's and
    are left as they are, whatever they hold. The whitespace and the ``\\``
    tokens between the tokens are kept, so the staged text keeps the layout of
    the root Dockerfile's.
    """
    tokens = [(m.start(), m.end(), m.group()) for m in re.finditer(r"\S+", text)]
    arguments = [
        index
        for index, (_start, _end, word) in enumerate(tokens[1:], start=1)
        if word != "\\" and not word.startswith("--")
    ]
    if len(arguments) < 2 or any(
        word.startswith("--from=") for _start, _end, word in tokens
    ):
        return text
    sources = set(arguments[:-1])
    staged = []
    last = 0
    for index, (start, end, word) in enumerate(tokens):
        staged.append(text[last:start])
        staged.append(_staged_source(word) if index in sources else word)
        last = end
    staged.append(text[last:])
    return "".join(staged)


def staged_dockerfile_text(content: str) -> str:
    """The root Dockerfile's text with every COPY source inside the assets context.

    Every source of a COPY or ADD instruction that names a file under
    ``automated_security_helper/assets/`` becomes the bare file name, and every
    source in DOCKERFILE_STAGED_PACKAGE_FILES becomes its staged name. Every
    source, not the first: ``COPY <a> <b> /dest/`` carries two, and rewriting
    only the one right after ``COPY`` left the second pointing outside the
    context, so the packaged image build failed at that line while the same
    Dockerfile built from a checkout. Only sources, not the whole line: a
    text replacement over the line also rewrote a ``--from=`` instruction's
    paths, which name another stage's filesystem and not the context, and a
    destination that held the assets path. The lines of a ``\\``-continued
    instruction are read together, so a source on a continuation line, whose
    first word is not ``COPY``, is rewritten like the first. Comments and every
    other instruction are left as they are; the paths in them are documentation.
    """
    staged = []
    pending = []
    for line in content.splitlines(keepends=True):
        pending.append(line)
        if _continues(line):
            continue
        instruction = "".join(pending)
        pending = []
        first = instruction.split(maxsplit=1)[0].upper() if instruction.strip() else ""
        if first in ("COPY", "ADD"):
            instruction = _staged_instruction(instruction)
        staged.append(instruction)
    staged.extend(pending)
    return "".join(staged)


# The GenAI guide `ash get-genai-guide` writes out. It lives in docs/, which no
# artifact ships, so it is added to both the sdist and the wheel at this path inside
# the package; cli/main.py reads it from there. Without it a wheel install had no
# copy of its own and downloaded the `main` branch's guide from GitHub instead.
GENAI_GUIDE_SOURCE: Path = ASH_REPO_ROOT.joinpath(
    "docs", "content", "docs", "genai-steering-guide.md"
)
GENAI_GUIDE_PACKAGE_PATH = "automated_security_helper/assets/genai-steering-guide.md"

# A commit id as the root Dockerfile's clone step takes it: 40 lowercase hex digits
# and nothing else (its length test is `-eq 40`). ASH's repository is a SHA-1 one. A
# 64-digit id from a SHA-256 repository is left out on purpose: that step would pass
# it to `git clone --branch` and fail the image build, where "unknown-commit" falls
# back to the release tag.
_COMMIT_ID = re.compile(r"[0-9a-f]{40}")

# The most GIT_CONFIG_KEY_<n> entries read: a count from the environment is not
# trusted to bound a loop.
_MAX_GIT_CONFIG_ENTRIES = 1000

# The variables that carry numbered config entries: the count, and the prefix of the
# key and value of entry <n>. These are the only GIT_CONFIG_* names passed to git.
_GIT_CONFIG_COUNT = "GIT_CONFIG_COUNT"
_GIT_CONFIG_KEY = "GIT_CONFIG_KEY_"
_GIT_CONFIG_VALUE = "GIT_CONFIG_VALUE_"

# The oldest git believed to read safe.directory from the command scope, which is
# where the entries above are put. git 2.38 introduced protected configuration, the
# only scope set that git-config(1) says safe.directory is respected in. Not
# measured here, and nothing tests for the version: git gives the same refusal on
# an older release, so the build says this number when git fails with entries passed.
_SAFE_DIRECTORY_MIN_GIT = "2.38"


def _safe_directory_config(environ) -> dict:
    """The safe.directory entries of GIT_CONFIG_COUNT/KEY_<n>/VALUE_<n>, renumbered.

    git refuses a repository owned by another user unless safe.directory names it,
    and a build in a container or CI checkout often passes that through these
    variables. Dropping them with the rest of GIT_* made git fail there and the
    commit record read "unknown-commit". Only entries whose key is safe.directory
    are kept, since any other key set this way (core.worktree, core.fsmonitor, a
    hook path) can point git at another repository or run a program. A count that
    is not a number, and an entry with a key and no value, give nothing.

    GIT_CONFIG_GLOBAL, GIT_CONFIG_SYSTEM and GIT_CONFIG_NOSYSTEM stay dropped
    with the rest. They name whole config files, every key of which git would
    honor, and a file's content cannot be filtered to safe.directory the way
    numbered entries can. A container or CI step that supplies safe.directory
    through one of them gets "unknown-commit" here, and can pass it through
    GIT_CONFIG_COUNT instead.

    Minimum git version. These entries work only where git reads safe.directory
    from the command scope. git-config(1) puts the command scope in "protected
    configuration" (with the system and global scopes), and says safe.directory is
    respected only there; that is how it reads in git 2.50. The first release that
    does is believed to be git 2.38, which introduced protected configuration.
    That bound was not measured here. A git that carries the CVE-2022-24765 fix
    but is older (2.35.2 up to 2.37, and the distribution builds of 2.34 and
    earlier that backport it) is believed to read safe.directory from the
    system and global config only, so the forwarded entries do nothing there and
    the record reads "unknown-commit". Nothing here tests for the version: git
    gives the same refusal either way.
    """
    try:
        count = int(environ.get(_GIT_CONFIG_COUNT, ""))
    except ValueError:
        return {}
    values = []
    for index in range(min(count, _MAX_GIT_CONFIG_ENTRIES)):
        key = environ.get(f"{_GIT_CONFIG_KEY}{index}")
        value = environ.get(f"{_GIT_CONFIG_VALUE}{index}")
        if key is not None and value is not None and key.lower() == "safe.directory":
            values.append(value)
    if not values:
        return {}
    kept = {_GIT_CONFIG_COUNT: str(len(values))}
    for index, value in enumerate(values):
        kept[f"{_GIT_CONFIG_KEY}{index}"] = "safe.directory"
        kept[f"{_GIT_CONFIG_VALUE}{index}"] = value
    return kept


def _commit_from_git(git_path: str) -> str | None:
    """The commit id git names for this tree, or None when it names none.

    None covers git failing (a repository it will not read, no repository at all)
    and git answering with something that is not this tree's own top-level commit.
    """
    # Try to get commit details from current directory (source repo build).
    # With no GIT_* variable from the caller: git exports GIT_DIR (and others) to
    # its hooks, and pre-commit builds hook environments inside `git commit`, so
    # git would read the repository being committed to instead of this tree.
    # GIT_WORK_TREE alone moved the top level, and GIT_COMMON_DIR alone hid the
    # repository. GIT_CEILING_DIRECTORIES is kept: it only stops git looking
    # for a repository above the directories it names, so it can turn a tree
    # unpacked inside another repository into no repository at all, never into
    # a commit of the wrong one.
    git_env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("GIT_") or k == "GIT_CEILING_DIRECTORIES"
    }
    # The one GIT_CONFIG_* setting that is kept: safe.directory, the caller's
    # own statement that git may read this tree despite its owner. It needs a
    # git that reads safe.directory from the command scope (believed to be git
    # 2.38 and later; see _safe_directory_config). GIT_CONFIG_GLOBAL,
    # GIT_CONFIG_SYSTEM and GIT_CONFIG_NOSYSTEM stay dropped by the filter above.
    forwarded = _safe_directory_config(os.environ)
    git_env.update(forwarded)
    try:
        git_result_full = subprocess.run(  # nosec B603 - This code is run during package build
            [git_path, "rev-parse", "--show-prefix", "HEAD"],
            capture_output=True,
            cwd=ASH_REPO_ROOT.as_posix(),
            env=git_env,
            check=True,
        )
        # An empty prefix line, then the commit id: nothing else is the top level.
        at_top_level = re.fullmatch(rb"\n([0-9a-f]{40})\n", git_result_full.stdout)
        if at_top_level:
            return at_top_level.group(1).decode("ascii")
        _say(f"Not a commit of this source tree: {git_result_full.stdout!r}")
    except subprocess.CalledProcessError as e:
        _say(f"Git command failed in current directory: {e}")
        if hasattr(e, "stderr") and e.stderr:
            _say(f"stderr: {e.stderr.decode('utf-8', 'replace').strip()}")
        if forwarded:
            _say(
                "safe.directory entries were passed to git; a git older than "
                f"{_SAFE_DIRECTORY_MIN_GIT} is believed to ignore them"
            )
    return None


def _earlier_commit_record() -> str | None:
    """The commit id an earlier build recorded, when this tree is an unpacked sdist.

    A wheel built from an sdist has no git metadata, and the record the sdist
    build left in assets/ is the commit the sdist was built from. Two things must
    hold for that record to be this tree's. There is no .git, since in a checkout
    git failing (a repository-ownership refusal, say) says nothing about which
    commit the tree is, and the record there is whatever an earlier build, at some
    other commit, left behind. And there is a PKG-INFO at the top, which hatchling
    writes at the root of every sdist: a missing .git alone also describes a source
    tree vendored inside another repository, a copy made with `rsync --exclude
    .git` and the image build context (.dockerignore drops .git and does not name
    the record), and each of those can hold the gitignored record of an earlier
    build at another commit.

    None when the record is not usable: absent, not from an unpacked sdist, or not
    a commit id. A commit id only: the three placeholders, "HEAD" and a branch name
    from an older build, and the "ERROR: ..." text a failed staging script wrote
    all name no commit, and would be installed as a ref.
    """
    if os.path.lexists(ASH_REPO_ROOT.joinpath(".git")):
        _say("This tree is a git checkout, so an earlier commit record is not used")
        return None
    if not ASH_INSTALLED_REVISION_PATH.exists():
        return None
    if not ASH_REPO_ROOT.joinpath("PKG-INFO").is_file():
        _say(
            "This tree is not an unpacked sdist (no PKG-INFO), so its commit record "
            "is not used"
        )
        return None
    existing_sha = ASH_INSTALLED_REVISION_PATH.read_text().strip()
    if not _COMMIT_ID.fullmatch(existing_sha):
        return None
    _say(f"Using existing commit SHA from previous build: {existing_sha}")
    return existing_sha


class CustomBuildHook(BuildHookInterface):
    """Build hook to stage build assets before packaging."""

    PLUGIN_NAME = "stage-build-assets"

    def initialize(self, version, build_data):
        """Run the asset staging script."""
        # Stage assets immediately during initialization
        self._stage_assets()
        self._include_genai_guide(build_data)

    def _include_genai_guide(self, build_data):
        """Stage the GenAI guide at GENAI_GUIDE_PACKAGE_PATH and force-include it.

        Staged into the tree and included from there, like the Dockerfile's staged
        files, rather than included straight from docs/: hatchling reserves a
        force-include's source path and not its target, so a copy already at the
        target (from an earlier build, or by hand) would ship beside it, twice in
        the sdist. Overwriting it and including it as its own source ships one copy,
        the current one. The path is gitignored for the same reason.

        Through build_data rather than a force-include in pyproject.toml, because a
        static force-include of a missing file fails the build. A wheel built from
        the sdist has no docs/, and uses the copy the sdist build staged; a tree
        with neither builds without the guide and says so. The `uv build` inside
        the image has the docs copy, through the exception for it in
        .dockerignore. The artifact gate in .github/scripts/assert-artifact-contents.py
        pins the path, so a released wheel or sdist without it fails CI.
        """
        packaged = ASH_REPO_ROOT.joinpath(*GENAI_GUIDE_PACKAGE_PATH.split("/"))
        if GENAI_GUIDE_SOURCE.is_file():
            packaged.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(GENAI_GUIDE_SOURCE, packaged)
            _say(f"Staged the GenAI guide at {GENAI_GUIDE_PACKAGE_PATH}")
        elif packaged.is_file():
            _say(f"Using the GenAI guide already at {GENAI_GUIDE_PACKAGE_PATH}")
        else:
            # The one message here that holds the checkout's absolute path. Called
            # outside _stage_assets' handler, so a plain print of a path the console
            # cannot encode raised UnicodeEncodeError and failed the whole build
            # instead of printing this warning.
            _say(
                f"Warning: {GENAI_GUIDE_SOURCE} not found; this build carries no "
                "GenAI guide, and `ash get-genai-guide` from it needs --from-github"
            )
            return
        build_data["force_include"][str(packaged)] = GENAI_GUIDE_PACKAGE_PATH

    def _stage_assets(self):
        """Stage the build assets."""
        try:
            # Ensure assets directory exists
            ASH_ASSETS_PATH.mkdir(parents=True, exist_ok=True)

            # Copy the Dockerfile into the assets directory
            dockerfile_path = ASH_REPO_ROOT.joinpath("Dockerfile")
            dockerfile_copy_path = ASH_ASSETS_PATH.joinpath("Dockerfile")

            if dockerfile_path.exists():
                # utf-8 named on both ends: the Dockerfile's first lines hold
                # characters outside every ANSI code page, and read_text() with no
                # encoding takes the console's, so on a Japanese, Chinese or
                # Korean Windows the read raised UnicodeDecodeError, no
                # assets/Dockerfile was generated, and "build-error" was recorded
                # as the commit.
                content = dockerfile_path.read_text(encoding="utf-8")
                # Stage the package files the Dockerfile COPYs from outside assets/;
                # staged_dockerfile_text points every COPY source at the staged
                # copies and the bare asset names. Asserted rather than skipped
                # when a source is missing: a silently-dropped stage produces a
                # Dockerfile that fails at build time in the shipped artifact only,
                # which is the hardest place to notice it.
                for source_rel, staged_name in DOCKERFILE_STAGED_PACKAGE_FILES:
                    source = ASH_REPO_ROOT.joinpath(
                        "automated_security_helper", *source_rel.split("/")
                    )
                    if not source.exists():
                        raise StagedSourceMissingError(
                            f"Dockerfile stages {source_rel}, which does not exist "
                            f"at {source}"
                        )
                    shutil.copyfile(source, ASH_ASSETS_PATH.joinpath(staged_name))
                    _say(f"Staged {source_rel} into assets/{staged_name}")
                # newline="\n": a text-mode write on Windows turns every "\n" into
                # "\r\n", so the same sources staged a different Dockerfile there
                # than on Linux. The image build reads it on Linux either way.
                dockerfile_copy_path.write_text(
                    staged_dockerfile_text(content), encoding="utf-8", newline="\n"
                )
                _say("Successfully generated assets/Dockerfile from root Dockerfile")
            else:
                _say(f"Warning: Dockerfile not found at {dockerfile_path}")
                if dockerfile_copy_path.exists():
                    _say("Using existing Dockerfile in assets directory")
                else:
                    _say(
                        "No Dockerfile available - this may be expected for wheel-only builds"
                    )

        except Exception as e:
            # Every error of the staging fails the build, a missing source
            # (StagedSourceMissingError) and a Dockerfile or staged file that would
            # not read, decode or write alike, as the comment above says a dropped
            # stage must. A handler that printed it and went on shipped a stale or
            # missing assets/Dockerfile beside a healthy-looking commit record, so
            # nothing machine-readable showed the failure and the artifact broke
            # at image build time only. The commit step below is the other kind of
            # error: it costs the revision and leaves the artifact complete, so it
            # records "build-error" and the build goes on.
            _say(f"Error staging the Dockerfile, failing the build: {e}")
            raise

        # After the staging, outside its handler: an error while staging the
        # Dockerfile used to be caught by the same handler that records
        # "build-error", which overwrote the commit record before the commit was
        # looked up, discarding a commit the tree could still name.
        self._record_commit()

    def _record_commit(self):
        """Write the commit the tree is built from to ASH_INSTALLED_REVISION."""
        try:
            commit_sha = self._get_commit_sha()
            ASH_INSTALLED_REVISION_PATH.write_text(commit_sha)
            _say(
                f"Successfully wrote git details '{commit_sha}' to {ASH_INSTALLED_REVISION_PATH}"
            )
        except Exception as e:
            _say(f"Unexpected error recording the commit, continuing the build: {e}")
            # Ensure we have some revision file even if there's an error
            try:
                ASH_INSTALLED_REVISION_PATH.write_text("build-error")
            except Exception:  # nosec B110 — build must continue even if revision file write fails
                pass

    def _get_commit_sha(self) -> str:
        """Get the Git commit SHA, with fallbacks for different build scenarios.

        The full commit id of the checkout being built. A container image built
        from the installed package installs this commit (run_ash_container reads it
        through core/constants.py, and the Dockerfile builds a commit id that a
        branch or tag of ASH reaches). A branch name (`git rev-parse --abbrev-ref
        HEAD`) would not do: a package built on `main` would put main's tip at
        image build time in the image, and one built on a detached checkout would
        record the literal "HEAD", which cannot be cloned.

        Only the repository whose top level is this directory counts: an ASH
        source tree unpacked inside some other repository is not a commit of ASH.
        `--show-prefix` prints the directory's path below the top level, which is
        empty exactly at the top level, so no path has to be read or compared. A
        path printed by `--show-toplevel` could hold a space, a line break or any
        other character, and splitting it on whitespace, then on lines, both cut
        some paths in two.

        git sees none of the caller's GIT_* variables except
        GIT_CEILING_DIRECTORIES and the safe.directory entries of GIT_CONFIG_COUNT,
        GIT_CONFIG_KEY_<n> and GIT_CONFIG_VALUE_<n> (every other config entry there
        can move the worktree or run a program, so it is dropped; the entries
        work on git 2.38 and later, which is believed to be the first to read
        safe.directory from the command scope, and GIT_CONFIG_GLOBAL, _SYSTEM
        and _NOSYSTEM are dropped too: see _safe_directory_config). So a tree that
        has no .git of its own, built with GIT_DIR (and GIT_WORK_TREE) naming its
        repository from outside, is treated as a tree with no git metadata: it keeps
        an earlier record (an unpacked sdist only) or records "unknown-commit".
        That is accepted: the
        alternative would read whichever repository the caller's environment named,
        which inside a `git commit` hook is the one being committed to, not this
        tree's.

        When git cannot name the commit, or is not installed, an unpacked sdist (a
        tree with a PKG-INFO and no .git of its own) keeps the commit id the sdist
        build recorded; any other tree does not, since its earlier record may be of
        another commit (see _earlier_commit_record). With no usable record the
        result is "no-git-available" where git is missing and "unknown-commit"
        where it is not.
        """
        git_path = shutil.which("git")
        if not git_path:
            # Not an early return: a wheel built from an sdist on a host without
            # git still has the commit the sdist recorded, which the fallback
            # below reads.
            _say("Warning: git command not found")
        else:
            commit = _commit_from_git(git_path)
            if commit:
                return commit

        # Fallback: the record an sdist build left, for a wheel built from that
        # sdist. Reached with git missing as well as with git failing.
        recorded = _earlier_commit_record()
        if recorded:
            return recorded

        # Final fallback
        if not git_path:
            return "no-git-available"
        _say("Unable to determine commit SHA, using fallback")
        return "unknown-commit"
