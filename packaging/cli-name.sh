# shellcheck shell=sh disable=SC2034
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The name of the command the .deb and .rpm put on PATH, and the console script they
# expect the wheel to provide inside the venv. Sourced by packaging/deb/build.sh,
# packaging/rpm/build.sh and both verify-in-container.sh scripts, and parsed by
# packaging/assert-package-payload.py, so renaming the CLI is a one-line edit here.
#
# It must match a [project.scripts] entry in pyproject.toml. The maintainer scripts
# refuse to finish configuring when the venv has no such console script, so a rename
# made here without the matching pyproject change fails the install rather than
# shipping a wrapper that points at nothing.
#
# Keep the assignment on one line with no quoting: the payload checker reads it with
# a regular expression rather than a shell.
ASH_CLI_NAME=ash
