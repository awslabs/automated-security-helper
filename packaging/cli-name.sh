# shellcheck shell=bash disable=SC2034
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
# Both names must match ASH_NAME_PATTERN below, which is Debian's rule for a package
# name. Both builds call ash_check_names, and the payload checker applies the same
# pattern, so the deb build, the rpm build and the checker refuse the same names. rpm
# alone would accept uppercase and `_`. Each name is also substituted into the
# maintainer scripts' rm -rf paths, into sed expressions and into file names, so it
# must be a plain path component; the pattern guarantees that.
# packaging/test-build-names.sh holds the three consumers to this.
#
# Keep each name assignment on one line with no quoting: the payload checker reads them
# with a regular expression rather than a shell.
ASH_CLI_NAME=ash
ASH_PKG_NAME=ash

# An extended regular expression, matched against the whole name.
ASH_NAME_PATTERN='[a-z0-9][a-z0-9+.-]+'

# Exits non-zero, naming the offender, unless both names match ASH_NAME_PATTERN.
ash_check_names() {
  ash_check_one_name ASH_PKG_NAME "${ASH_PKG_NAME-}" &&
    ash_check_one_name ASH_CLI_NAME "${ASH_CLI_NAME-}"
}

# A whole-string match, as Python's re.fullmatch is: grep -x matches line by line, so
# it accepted a name with an embedded newline whose first line was valid.
ash_check_one_name() {
  if ! [[ $2 =~ ^($ASH_NAME_PATTERN)$ ]]; then
    echo "error: $1 '$2' (packaging/cli-name.sh) is not a valid package or command name: it must match $ASH_NAME_PATTERN, Debian policy 5.6.1." >&2
    return 1
  fi
}

# Copies file $1 to $2 with @ASH_PKG@ and @ASH_CLI@ replaced by the two names, for the
# docs the packages ship. Fails if a token survives. Call ash_check_names first: the
# names go into a sed expression unescaped, which the pattern makes safe.
#
# A substituted name changes the length of the heading it is in, so every heading
# underline (a line of three or more `=` or `-` under a non-empty line) is redrawn at
# the length of the line above it. The input must not end in blank lines: the command
# substitution drops them.
ash_substitute_names() {
  local text line prev="" mark
  text="$(sed -e "s/@ASH_PKG@/${ASH_PKG_NAME}/g" -e "s/@ASH_CLI@/${ASH_CLI_NAME}/g" "$1")" || return 1
  while IFS= read -r line; do
    if [ -n "$prev" ] && [ "${#line}" -ge 3 ] && [[ $line =~ ^(=+|-+)$ ]]; then
      mark="${line:0:1}"
      printf -v line '%*s' "${#prev}" ''
      line="${line// /$mark}"
    fi
    printf '%s\n' "$line"
    prev="$line"
  done <<<"$text" > "$2" || return 1
  if grep -q '@ASH_PKG@\|@ASH_CLI@' "$2"; then
    echo "error: an @ASH_PKG@ or @ASH_CLI@ token survived substitution in $2" >&2
    return 1
  fi
}
