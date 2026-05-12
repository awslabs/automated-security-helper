#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
import subprocess  # nosec B404
import sys
from typing import List, Optional
from igittigitt import IgnoreParser
from pathlib import Path
import argparse
import os

from automated_security_helper.utils.log import ASH_LOGGER

ASH_INCLUSIONS = [
    ".git",
    "**/cdk.out/asset.*",
    "!**/*.template.json",  # CDK output template default path pattern
]


def red(msg) -> str:
    return "\033[91m{}\033[00m".format(msg)


def green(msg) -> str:
    return "\033[92m{}\033[00m".format(msg)


def yellow(msg) -> str:
    return "\033[33m{}\033[00m".format(msg)


def lightPurple(msg) -> str:
    return "\033[94m{}\033[00m".format(msg)


def purple(msg) -> str:
    return "\033[95m{}\033[00m".format(msg)


def cyan(msg) -> str:
    return "\033[96m{}\033[00m".format(msg)


def gray(msg) -> str:
    return "\033[97m{}\033[00m".format(msg)


def black(msg) -> str:
    return "\033[98m{}\033[00m".format(msg)


def debug_echo(*msg, debug: bool = False) -> str | None:
    message = " ".join(str(m) for m in msg)
    if debug:
        ASH_LOGGER.debug(message)
    return message


def _collect_ignorefiles_and_all_files(
    path: str,
    extra_ignorefiles: List[str] | None = None,
    debug: bool = False,
) -> tuple[List[str], List[str]]:
    """Walk the directory tree once to collect ignore files and all file paths.

    Respects .gitignore hierarchy: if a directory is ignored by a parent
    .gitignore, its contents (including nested .gitignore files) are skipped.
    This prevents rules like ``*`` inside ``.venv/.gitignore`` from being
    applied globally and accidentally ignoring all project files.

    Returns a tuple of (ignore_file_paths, all_file_paths).
    """
    if extra_ignorefiles is None:
        extra_ignorefiles = []

    _ignore_names = {".ignore", ".gitignore"}
    ignore_files: List[str] = []
    all_files: List[str] = []

    # Build an initial ignore spec from the root .gitignore (if it exists)
    # so we can skip walking into ignored directories.
    root_ignore_parser = IgnoreParser()
    root_path = Path(path)
    root_gitignore = root_path / ".gitignore"
    if root_gitignore.is_file():
        try:
            root_ignore_parser.parse_rule_file(root_gitignore, base_dir=root_path)
        except Exception:
            # If parsing fails, proceed without pruning
            pass

    for root, dirs, files in os.walk(path):
        # Prune directories that are ignored by the root .gitignore.
        # This prevents descending into .venv/, node_modules/, etc.
        # and picking up their internal .gitignore files.
        dirs_to_remove = []
        for d in dirs:
            dir_path = Path(root) / d
            # igittigitt.match expects a Path; directories need trailing separator
            # to match directory-specific patterns. We check both the dir path
            # and a fake file inside it.
            try:
                if root_ignore_parser.match(dir_path / "placeholder"):
                    dirs_to_remove.append(d)
                    debug_echo(
                        f"Skipping ignored directory: {dir_path}", debug=debug
                    )
            except Exception:
                pass
        for d in dirs_to_remove:
            dirs.remove(d)

        for f in files:
            full_path = os.path.join(root, f)
            if f in _ignore_names:
                ignore_files.append(full_path)
            all_files.append(full_path)

    # Append any user-specified ignore files
    for extra in extra_ignorefiles:
        extra_path = os.path.join(path, extra)
        if extra_path not in ignore_files:
            ignore_files.append(extra_path)

    return ignore_files, all_files


def get_ash_ignorespec_lines(
    path,
    ignorefiles: List[str] | None = None,
    debug: bool = False,
    _discovered_ignore_files: List[str] | None = None,
) -> List[str]:
    if ignorefiles is None:
        ignorefiles = []

    if _discovered_ignore_files is not None:
        all_ignores = list(set(_discovered_ignore_files))
    else:
        # Fallback: collect ignore files via a walk (used when called standalone)
        all_ignores, _ = _collect_ignorefiles_and_all_files(path, ignorefiles, debug)
        all_ignores = list(set(all_ignores))

    lines = []
    for ignorefile in all_ignores:
        if os.path.isfile(ignorefile):
            clean = re.sub(
                rf"^{re.escape(Path(path).as_posix())}", "${SOURCE_DIR}", ignorefile
            )
            debug_echo(f"Found .ignore file: {clean}", debug=debug)
            lines.append(f"######### START CONTENTS: {clean} #########")
            with open(ignorefile) as f:
                lines.extend(f.readlines())
            lines.append(f"######### END CONTENTS: {clean} #########")
            lines.append("")
    lines = [line.strip() for line in lines]
    lines.append("######### START CONTENTS: ASH_INCLUSIONS #########")
    lines.extend(ASH_INCLUSIONS)
    lines.append("######### END CONTENTS: ASH_INCLUSIONS #########")
    return lines


def get_ash_ignorespec(
    lines: List[str],
    debug: bool = False,
) -> IgnoreParser:
    debug_echo("Generating spec from collected ignorespec lines", debug=debug)
    parser = IgnoreParser()

    # Track the current base directory from section markers.
    # Lines like "######### START CONTENTS: ${SOURCE_DIR}/.ruff_cache/.gitignore #########"
    # indicate that subsequent rules should be scoped to that directory.
    current_base_path = "/"

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        # Detect section markers to determine the base path for rules
        if stripped.startswith("#########") and "START CONTENTS:" in stripped:
            # Extract the path from the marker
            # Format: "######### START CONTENTS: ${SOURCE_DIR}/subdir/.gitignore #########"
            # or:     "######### START CONTENTS: ${SOURCE_DIR}/.gitignore #########"
            # or:     "######### START CONTENTS: ASH_INCLUSIONS #########"
            try:
                content_path = stripped.split("START CONTENTS:")[1].strip().rstrip("#").strip()
                if content_path == "ASH_INCLUSIONS":
                    current_base_path = "/"
                elif "${SOURCE_DIR}" in content_path:
                    # Extract the directory containing the .gitignore/.ignore file
                    relative_path = content_path.replace("${SOURCE_DIR}", "").lstrip("/")
                    # Get the parent directory of the ignore file
                    parent_dir = str(Path(relative_path).parent)
                    if parent_dir == ".":
                        current_base_path = "/"
                    else:
                        current_base_path = "/" + parent_dir
                else:
                    current_base_path = "/"
            except (IndexError, ValueError):
                current_base_path = "/"
            continue

        if stripped.startswith("#"):
            continue

        parser.add_rule(stripped, base_path=current_base_path)
    return parser


def get_files_not_matching_spec(
    path,
    spec,
    debug: bool = False,
    _all_files: List[str] | None = None,
):
    if _all_files is None:
        # Fallback: walk again if called standalone without pre-collected files
        _all_files = []
        for root, _dirs, files in os.walk(path):
            for f in files:
                _all_files.append(os.path.join(root, f))

    included = []
    for inc_full in _all_files:
        clean = re.sub(
            rf"^{re.escape(Path(path).as_posix())}", "${SOURCE_DIR}", inc_full
        )
        if not spec.match(Path(inc_full)):
            if "/node_modules/aws-cdk" not in inc_full:
                debug_echo(f"Matched file for scan set: {clean}", debug=debug)
                included.append(inc_full)
    included = sorted(set(included))
    return included


def get_changed_files(base_ref: str = "origin/main", cwd: Optional[Path] = None) -> Optional[List[Path]]:
    """Return files changed between *base_ref* and HEAD using ``git diff``.

    Falls back to ``None`` (meaning "scan everything") when:
    * ``git`` is not available on ``PATH``, or
    * *base_ref* does not exist in the local repository.

    Args:
        base_ref: The git ref to diff against.  Defaults to ``origin/main``.
        cwd: Directory to run git from (must be inside the target repo).
             Defaults to the current working directory.

    Returns:
        A list of :class:`~pathlib.Path` objects relative to the repo root,
        or ``None`` if the diff could not be computed.
    """
    if not re.match(r"^[a-zA-Z0-9._/~^@{}\-]+$", base_ref):
        ASH_LOGGER.warning(
            f"Invalid base_ref '{base_ref}'; falling back to full scan"
        )
        return None

    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base_ref}...HEAD"],  # nosec B603 B607
            capture_output=True,
            text=True,
            timeout=30,
            cwd=cwd,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        ASH_LOGGER.warning(
            "git not available or timed out; falling back to full scan"
        )
        return None

    if result.returncode != 0:
        ASH_LOGGER.warning(
            "git diff against %s failed (rc=%d); falling back to full scan",
            base_ref,
            result.returncode,
        )
        return None

    paths: List[Path] = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if line:
            paths.append(Path(line))
    return paths


def parse_args() -> argparse.Namespace:
    """Parse command line arguments.

    Returns:
        Parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Get list of files not matching .gitignore underneath SourceDir arg path"
    )
    parser.add_argument("--source", help="path to scan", default=os.getcwd(), type=str)
    parser.add_argument(
        "--output",
        help="output path to save the ash-ignore-report.txt and ash-scan-set-files-list.txt files to",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--filter-pattern",
        help="Filter results against a regular expression pattern. Defaults to returning empty which returns the full list of files to be included in the scan.",
        default=None,
        type=str,
    )
    parser.add_argument(
        "--ignorefile",
        help="ignore file to use in addition to the standard gitignore",
        default=[],
        type=str,
        nargs="*",
    )
    parser.add_argument(
        "--debug", help="Enables debug logging", action=argparse.BooleanOptionalAction
    )
    return parser.parse_args()


def scan_set(
    source: Optional[str] = None,
    output: Optional[str] = None,
    ignorefile: Optional[list[str]] = None,
    debug: bool = False,
    print_results: bool = False,
    filter_pattern: Optional[re.Pattern] = None,
) -> list[str]:
    """Get list of files not matching .gitignore underneath source path.

    Args:
        source: Path to scan. Defaults to current working directory.
        output: Output path to save the ash-ignore-report.txt and ash-scan-set-files-list.txt files.
        ignorefile: List of ignore files to use in addition to the standard gitignore.
        debug: Enable debug logging.
        print_results: Print results to stdout. Defaults to False for library usage.
        filter_pattern: Filter results against a re.Pattern. Defaults to returning the full scan set.

    Returns:
        List of files not matching ignore specifications.
    """
    if source is None:
        source = os.getcwd()
    if ignorefile is None:
        ignorefile = []

    ashignore_content = None
    ashscanset_list = None
    ashignore_imported = False
    ashscanset_imported = False

    if output:
        # Ensure output is a Path object
        output_path = Path(output)
        ashignore_path = output_path.joinpath("ash-ignore-report.txt")
        ashscanset_path = output_path.joinpath("ash-scan-set-files-list.txt")
        if ashignore_path.exists():
            with open(ashignore_path) as f:
                ashignore_content = f.readlines()
            ashignore_imported = True
            debug_echo(f"Imported ash-ignore-report.txt from {output}", debug=debug)
        if ashscanset_path.exists():
            with open(ashscanset_path) as f:
                ashscanset_list = f.readlines()
            ashscanset_imported = True
            debug_echo(
                f"Imported ash-scan-set-files-list.txt from {output}", debug=debug
            )

    if not ashignore_content or not ashscanset_list:
        # Single os.walk pass collects both ignore files and the full file list
        discovered_ignores, all_files = _collect_ignorefiles_and_all_files(
            source, ignorefile, debug=debug
        )

    if not ashignore_content:
        ashignore_content = get_ash_ignorespec_lines(
            source, ignorefile, debug=debug,
            _discovered_ignore_files=discovered_ignores,
        )

    if not ashscanset_list:
        spec = get_ash_ignorespec(ashignore_content, debug=debug)
        ashscanset_list = get_files_not_matching_spec(
            source, spec, debug=debug, _all_files=all_files,
        )

    if output:
        # Ensure output is a Path object
        output_path = Path(output)
        ashignore_path = output_path.joinpath("ash-ignore-report.txt")
        ashscanset_path = output_path.joinpath("ash-scan-set-files-list.txt")

        if not ashignore_imported:
            debug_echo(f"Writing ash-ignore-report.txt to {output}", debug=debug)
            if not ashignore_path.parent.exists():
                ashignore_path.parent.mkdir(parents=True)
            with open(ashignore_path, mode="w", encoding="utf-8") as f:
                f.write("\n".join(ashignore_content))

        if not ashscanset_imported:
            debug_echo(
                f"Writing ash-scan-set-files-list.txt to {output}",
                debug=debug,
            )
            if not ashscanset_path.parent.exists():
                ashscanset_path.parent.mkdir(parents=True)
            with open(ashscanset_path, mode="w", encoding="utf-8") as f:
                f.write("\n".join(ashscanset_list))

    if print_results:
        for file in ashscanset_list:
            print(file, file=sys.stdout)

    if filter_pattern:
        ashscanset_list = [
            file
            for file in ashscanset_list
            if re.match(pattern=filter_pattern, string=file)
        ]

    return [item.strip() for item in ashscanset_list]


def main() -> int:
    """Main entry point for CLI usage.

    Returns:
        Exit code (0 for success).
    """
    args = parse_args()

    file_list = scan_set(
        source=args.source,
        output=args.output,
        ignorefile=args.ignorefile,
        debug=args.debug,
        print_results=True,
    )
    print(file_list, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
