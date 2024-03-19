#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import List
from pathspec import PathSpec
import argparse
import os
from glob import glob

ASH_INCLUSIONS=[
    "**/cdk.out/asset.*",
    "!**/*.template.json", # CDK output template default path pattern
]

def get_ash_ignorespec_lines(
    path,
    ignorefiles: List[str] = []
) -> List[str]:
    ashignores = [
        f"{path}/.ashignore",
        *[
            item
            for item in glob(f"{path}/**/.ashignore")
        ]
    ]
    semgrepignores = [
        f"{path}/.semgrepignore",
        *[
            item
            for item in glob(f"{path}/**/.semgrepignore")
        ]
    ]
    gitignores = [
        f"{path}/.gitignore",
        *[
            item
            for item in glob(f"{path}/**/.gitignore")
        ]
    ]
    all_ignores = list(set([
        *gitignores,
        *semgrepignores,
        *ashignores,
        *[
            f"{path}/{file}"
            for file in ignorefiles
        ]
    ]))
    lines = ['.git']
    for ignorefile in all_ignores:
        if os.path.isfile(ignorefile):
            # print(f"Reading: {ignorefile}", file=sys.stderr)
            with open(ignorefile) as f:
                lines.extend(f.readlines())
    lines = [ line.strip() for line in lines ]
    lines.extend(ASH_INCLUSIONS)
    return lines

def get_ash_ignorespec(
    lines: List[str],
) -> PathSpec:
    spec = PathSpec.from_lines('gitwildmatch', lines)
    return spec

def get_files_not_matching_spec(
    path,
    spec,
):
    full = []
    included = []
    for item in os.walk(path):
        for file in item[2]:
            full.append(os.path.join(item[0], file))
            if not spec.match_file(os.path.join(item[0], file)):
                inc_full = os.path.join(item[0], file)
                # print(f"Including: {inc_full}", file=sys.stderr)
                included.append(inc_full)
    included = sorted(set(included))
    return included

if __name__ == "__main__":
    # set up argparse
    parser = argparse.ArgumentParser(description="Get list of files not matching .gitignore underneath SourceDir arg path")
    parser.add_argument("path", help="path to scan", default=os.getcwd(), type=str, nargs='?')
    parser.add_argument("--ignorefile", help="ignore file to use in addition to the standard gitignore", default=[], type=str, nargs='*')
    args = parser.parse_args()

    lines = get_ash_ignorespec_lines(args.path, args.ignorefile)
    semgrepignore_path = os.path.join(args.path, ".semgrepignore")
    if not os.path.exists(semgrepignore_path):
        with open(semgrepignore_path, "w") as f:
            f.writelines(lines)

    spec = get_ash_ignorespec(lines)

    files = get_files_not_matching_spec(args.path, spec)
    for file in files:
        # print(f"Returning: {file}", file=sys.stderr)
        print(file, file=sys.stdout)
