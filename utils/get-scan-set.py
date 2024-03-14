#!/usr/bin/env python
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import List
from pathspec import PathSpec
import argparse
import os

ASH_INCLUSIONS=[
    "!**/*.template.json", # CDK output template default path pattern
]

def get_files_not_matching_gitignore(
    path,
    ignorefiles: List[str] = []
):
    # collect all lines from f"{path}/.gitignore" and any extra ignorefiles passed in
    # function call
    all_ignores = list(set([
        f"{path}/.gitignore",
        *[
            f"{path}/{file}"
            for file in ignorefiles
        ]
    ]))
    lines = ['.git']
    full = []
    included = []
    for ignorefile in all_ignores:
        if os.path.isfile(ignorefile):
            with open(ignorefile) as f:
                lines.extend(f.readlines())
    lines = [ line.strip() for line in lines ]
    lines.extend(ASH_INCLUSIONS)
    spec = PathSpec.from_lines('gitwildmatch', lines)
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

    files = get_files_not_matching_gitignore(args.path, args.ignorefile)
    for file in files:
        # print(f"Returning: {file}", file=sys.stderr)
        print(file, file=sys.stdout)
