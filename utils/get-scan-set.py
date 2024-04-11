#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import re
import sys
from datetime import datetime
from typing import List
from pathspec import PathSpec
from pathlib import Path
import argparse
import os
from glob import glob

ASH_INCLUSIONS=[
    '.git',
    "**/cdk.out/asset.*",
    "!**/*.template.json", # CDK output template default path pattern
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

def debug_echo(*msg, debug: bool = False) -> str:
    if debug:
        print(yellow(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [get-scan-set.py] DEBUG:"), *msg, file=sys.stderr)

def get_ash_ignorespec_lines(
    path,
    ignorefiles: List[str] = [],
    debug: bool = False,
) -> List[str]:
    dotignores = [
        f"{path}/.ignore",
        *[
            item
            for item in glob(f"{path}/**/.ignore")
        ]
    ]
    # ashignores = [
    #     f"{path}/.ashignore",
    #     *[
    #         item
    #         for item in glob(f"{path}/**/.ashignore")
    #     ]
    # ]
    gitignores = [
        f"{path}/.gitignore",
        *[
            item
            for item in glob(f"{path}/**/.gitignore")
        ]
    ]
    all_ignores = list(set([
        *dotignores,
        *gitignores,
        # *ashignores,
        *[
            f"{path}/{file}"
            for file in ignorefiles
        ]
    ]))
    lines = []
    for ignorefile in all_ignores:
        if os.path.isfile(ignorefile):
            clean = re.sub(rf"^{re.escape(path)}", '${SOURCE_DIR}', ignorefile)
            debug_echo(f"Found .ignore file: {clean}", debug=debug)
            lines.append(f"######### START CONTENTS: {clean} #########")
            with open(ignorefile) as f:
                lines.extend(f.readlines())
            lines.append(f"######### END CONTENTS: {clean} #########")
            lines.append("")
    lines = [ line.strip() for line in lines ]
    lines.append(f"######### START CONTENTS: ASH_INCLUSIONS #########")
    lines.extend(ASH_INCLUSIONS)
    lines.append(f"######### END CONTENTS: ASH_INCLUSIONS #########")
    return lines

def get_ash_ignorespec(
    lines: List[str],
    debug: bool = False,
) -> PathSpec:
    debug_echo("Generating spec from collected ignorespec lines", debug=debug)
    spec = PathSpec.from_lines('gitwildmatch', lines)
    return spec

def get_files_not_matching_spec(
    path,
    spec,
    debug: bool = False,
):
    full = []
    included = []
    for item in os.walk(path):
        for file in item[2]:
            full.append(os.path.join(item[0], file))
            inc_full = os.path.join(item[0], file)
            clean = re.sub(rf"^{re.escape(path)}", '${SOURCE_DIR}', inc_full)
            if not spec.match_file(inc_full):
                if '/node_modules/aws-cdk' not in inc_full:
                    debug_echo(f"Matched file for scan set: {clean}", debug=debug)
                    included.append(inc_full)
            # elif '/.git/' not in inc_full:
            #     debug_echo(f"Ignoring file matching spec: {clean}", debug=debug)
    included = sorted(set(included))
    return included

if __name__ == "__main__":
    # set up argparse
    parser = argparse.ArgumentParser(description="Get list of files not matching .gitignore underneath SourceDir arg path")
    parser.add_argument("--source", help="path to scan", default=os.getcwd(), type=str)
    parser.add_argument("--output", help="output path to save the ash-ignore-report.txt and ash-scan-set-files-list.txt files to", default=None, type=str)
    parser.add_argument("--ignorefile", help="ignore file to use in addition to the standard gitignore", default=[], type=str, nargs='*')
    parser.add_argument("--debug", help="Enables debug logging", action=argparse.BooleanOptionalAction)
    args = parser.parse_args()

    ashignore_content = None
    ashscanset_list = None
    ashignore_imported = False
    ashscanset_imported = False

    if args.output:
        ashignore_path = Path(args.output).joinpath('ash-ignore-report.txt')
        ashscanset_path = Path(args.output).joinpath('ash-scan-set-files-list.txt')
        if ashignore_path.exists():
            with open(ashignore_path) as f:
                ashignore_content = f.readlines()
            ashignore_imported = True
            print(cyan(f"Imported ash-ignore-report.txt from {args.output}"), file=sys.stderr)
        if ashscanset_path.exists():
            with open(ashscanset_path) as f:
                ashscanset_list = f.readlines()
            ashscanset_imported = True
            print(cyan(f"Imported ash-scan-set-files-list.txt from {args.output}"), file=sys.stderr)

    if not ashignore_content:
        ashignore_content = get_ash_ignorespec_lines(args.source, args.ignorefile, debug=args.debug)

    if not ashscanset_list:
        spec = get_ash_ignorespec(ashignore_content, debug=args.debug)
        ashscanset_list = get_files_not_matching_spec(args.source, spec, debug=args.debug)

    for file in ashscanset_list:
        print(file, file=sys.stdout)

    if args.output:
        if ashignore_imported == False:
            debug_echo(f"Writing ash-ignore-report.txt to {args.output}", debug=args.debug)
            if not ashignore_path.parent.exists():
                ashignore_path.parent.mkdir(parents=True)
            with open(ashignore_path, "w") as f:
                f.write("\n".join(ashignore_content))

        if ashscanset_imported == False:
            debug_echo(f"Writing ash-scan-set-files-list.txt to {args.output}", debug=args.debug)
            if not ashscanset_path.parent.exists():
                ashscanset_path.parent.mkdir(parents=True)
            with open(ashscanset_path, "w") as f:
                f.write("\n".join(ashscanset_list))
