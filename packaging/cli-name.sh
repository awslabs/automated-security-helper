# shellcheck shell=sh disable=SC2034
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The two names the .deb and .rpm are built around. Sourced by packaging/deb/build.sh,
# packaging/rpm/build.sh, packaging/verify-lib.sh and both verify-in-container.sh
# scripts, and parsed by packaging/assert-package-payload.py, so renaming either one
# is a one-line edit here.
#
# ASH_CLI_NAME is the command the packages put on PATH, and the console script they
# expect the wheel to provide inside the venv. It must match a [project.scripts] entry
# in pyproject.toml. The maintainer scripts refuse to finish configuring when the venv
# has no such console script, so a rename made here without the matching pyproject
# change fails the install rather than shipping a wrapper that points at nothing.
#
# ASH_PKG_NAME is the package name dpkg and rpm know it by, and the directory name it
# installs under: /usr/lib/<name>, /usr/share/doc/<name>, /usr/share/licenses/<name>.
# Debian requires lowercase letters, digits, '+', '-' and '.' (at least two
# characters, starting alphanumeric). Renaming it ships a NEW package; an upgrade
# from the old name also needs Replaces/Conflicts (deb) and Obsoletes (rpm) for the
# old name, which these files do not carry yet.
#
# Keep each assignment on one line with no quoting: the payload checker reads them
# with a regular expression rather than a shell.
ASH_CLI_NAME=ash
ASH_PKG_NAME=ash
