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

# The path every asset the root Dockerfile COPYs is under in a checkout. Inside
# the shipped Dockerfile's build context (assets/ itself) the same file is at the
# bare name, so the prefix comes off every source of every COPY.
_ASSETS_PREFIX = "automated_security_helper/assets/"


def staged_dockerfile_text(content: str) -> str:
    """The root Dockerfile's text with every COPY source inside the assets context.

    Every source of a COPY or ADD instruction that names a file under
    ``automated_security_helper/assets/`` becomes the bare file name, and every
    source in DOCKERFILE_STAGED_PACKAGE_FILES becomes its staged name. Every
    source, not the first: ``COPY <a> <b> /dest/`` carries two, and rewriting
    only the one right after ``COPY`` left the second pointing outside the
    context, so the packaged image build failed at that line while the same
    Dockerfile built from a checkout. Comments and every other instruction are
    left as they are; the paths in them are documentation.
    """
    staged = []
    for line in content.splitlines(keepends=True):
        instruction = line.split(maxsplit=1)[0].upper() if line.strip() else ""
        if instruction in ("COPY", "ADD"):
            for source_rel, staged_name in DOCKERFILE_STAGED_PACKAGE_FILES:
                line = line.replace(
                    f"automated_security_helper/{source_rel}", staged_name
                )
            line = line.replace(_ASSETS_PREFIX, "")
        staged.append(line)
    return "".join(staged)


# The GenAI guide `ash get-genai-guide` writes out. It lives in docs/, which no
# artifact ships, so it is added to both the sdist and the wheel at this path inside
# the package; cli/main.py reads it from there. Without it a wheel install had no
# copy of its own and downloaded the `main` branch's guide from GitHub instead.
GENAI_GUIDE_SOURCE: Path = ASH_REPO_ROOT.joinpath(
    "docs", "content", "docs", "genai-steering-guide.md"
)
GENAI_GUIDE_PACKAGE_PATH = "automated_security_helper/assets/genai-steering-guide.md"


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
            print(f"Staged the GenAI guide at {GENAI_GUIDE_PACKAGE_PATH}")
        elif packaged.is_file():
            print(f"Using the GenAI guide already at {GENAI_GUIDE_PACKAGE_PATH}")
        else:
            print(
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
                # assets/Dockerfile was generated, and the handler below recorded
                # "build-error" as the commit.
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
                        raise FileNotFoundError(
                            f"Dockerfile stages {source_rel}, which does not exist "
                            f"at {source}"
                        )
                    shutil.copyfile(source, ASH_ASSETS_PATH.joinpath(staged_name))
                    _say(f"Staged {source_rel} into assets/{staged_name}")
                dockerfile_copy_path.write_text(
                    staged_dockerfile_text(content), encoding="utf-8"
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

            # Handle Git commit SHA
            commit_sha = self._get_commit_sha()
            ASH_INSTALLED_REVISION_PATH.write_text(commit_sha)
            _say(
                f"Successfully wrote git details '{commit_sha}' to {ASH_INSTALLED_REVISION_PATH}"
            )

        except FileNotFoundError:
            # The staging loop's own assertion: a Dockerfile source that does not
            # exist. Re-raised so the build fails here, as the comment above says
            # it must. The handler below used to catch it with everything else,
            # so the build went on with a stale or missing assets/Dockerfile and
            # recorded "build-error" as the commit: exactly the silently-dropped
            # stage the assertion exists to refuse.
            raise
        except Exception as e:
            _say(f"Unexpected error in build hook: {e}")
            # Ensure we have some revision file even if there's an error
            try:
                ASH_INSTALLED_REVISION_PATH.write_text("build-error")
            except Exception:  # nosec B110 — build must continue even if revision file write fails
                pass
            _say("Continuing build despite asset staging error")

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
        GIT_CEILING_DIRECTORIES. So a tree that has no .git of its own, built with
        GIT_DIR (and GIT_WORK_TREE) naming its repository from outside, is
        treated as a tree with no git metadata: it keeps an earlier record or
        records "unknown-commit". That is accepted: the alternative would read whichever repository the caller's
        environment named, which inside a `git commit` hook is the one being
        committed to, not this tree's.
        """
        git_path = shutil.which("git")
        if not git_path:
            _say("Warning: git command not found")
            return "no-git-available"

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

        # Fallback: Check if we already have a revision file (from sdist build)
        if ASH_INSTALLED_REVISION_PATH.exists():
            existing_sha = ASH_INSTALLED_REVISION_PATH.read_text().strip()
            if (
                existing_sha
                and not existing_sha.startswith("ERROR")
                and existing_sha
                not in ["unknown-commit", "no-git-available", "build-error"]
            ):
                _say(f"Using existing commit SHA from previous build: {existing_sha}")
                return existing_sha

        # Final fallback
        _say("Unable to determine commit SHA, using fallback")
        return "unknown-commit"
