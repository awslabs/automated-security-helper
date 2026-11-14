#!/bin/sh

#################################################################################
###                 ~~ ASH HELPERS ~~
### Source this file from your shell profile to get an `invoke-ash` command that
### runs the ashx CLI in container mode from any directory:
###
### $ echo ". '/path/to/automated-security-helper/utils/ash_helpers.sh'" >> ~/.bashrc
###
### bash, zsh, and ksh93 report the path of a sourced file, so under them the
### checkout is found from this file's location, following a symlink to it. dash
### and other POSIX shells do not, so there set ASH_ROOT_DIR to the checkout
### first. A preset ASH_ROOT_DIR is also used when this file's location has no
### pyproject.toml above it, as for a copy kept outside the checkout:
###
### ASH_ROOT_DIR='/path/to/automated-security-helper'
### . "${ASH_ROOT_DIR}/utils/ash_helpers.sh"
###
### Defines invoke_ash, and invoke-ash as a function where the shell accepts a
### hyphen in a function name (bash, zsh) or as an alias where it does not (POSIX
### sh, ksh93).
#################################################################################

# $0 is not this file when it is sourced: it is the shell ("bash", "-zsh") or the
# script that sourced it, so ASH_ROOT_DIR taken from it would be the current
# directory. Each shell that knows the sourced file's path spells it differently,
# and the zsh and ksh93 spellings are syntax errors elsewhere, hence eval. The ksh93
# probe runs in a subshell because a bad substitution exits a POSIX shell.
_ash_helpers_file=""
if [ -n "${BASH_VERSION:-}" ]; then
  eval '_ash_helpers_file="${BASH_SOURCE[0]}"'
elif [ -n "${ZSH_VERSION:-}" ]; then
  eval '_ash_helpers_file="${(%):-%x}"'
elif (eval '[ -n "${.sh.version}" ]') 2>/dev/null; then
  eval '_ash_helpers_file="${.sh.file}"'
fi
# The directory above this file is the checkout when it has a pyproject.toml. A
# symlink to this file (from ~/bin, say) is followed until one does, with readlink,
# which is not POSIX but is on every system that has bash, zsh, or ksh93. It is
# followed at most 40 links deep, so a loop of links ends. Only a directory with an
# pyproject.toml replaces a preset ASH_ROOT_DIR, so a copy of this file kept outside the checkout
# still works with one.
_ash_helpers_root=""
_ash_helpers_hops=0
while [ -n "${_ash_helpers_file}" ]; do
  # -P resolves a symlinked directory on the way (a linked utils/, say) before the
  # "..", where a logical cd would go to the link's parent. cd's output goes to
  # /dev/null because $(...) would capture it: CDPATH makes cd print the directory,
  # and a zsh chpwd hook may print anything. The || keeps a dangling link from ending
  # a shell that runs under set -e.
  _ash_helpers_root="$(CDPATH="" cd -P -- "$(dirname -- "${_ash_helpers_file}")/.." >/dev/null 2>&1 && pwd -P)" || _ash_helpers_root=""
  if [ -f "${_ash_helpers_root}/pyproject.toml" ]; then
    ASH_ROOT_DIR="${_ash_helpers_root}"
    break
  fi
  if [ ! -L "${_ash_helpers_file}" ] || [ "${_ash_helpers_hops}" -ge 40 ]; then
    break
  fi
  _ash_helpers_link="$(readlink "${_ash_helpers_file}")" || break
  case "${_ash_helpers_link}" in
    /*) _ash_helpers_file="${_ash_helpers_link}" ;;
    *) _ash_helpers_file="$(dirname -- "${_ash_helpers_file}")/${_ash_helpers_link}" ;;
  esac
  _ash_helpers_hops=$((_ash_helpers_hops + 1))
done
_ash_helpers_found="${_ash_helpers_root}"
unset _ash_helpers_file _ash_helpers_root _ash_helpers_hops _ash_helpers_link

# A refusal returns 3, the code ASH uses for input it refuses, as ./ash and Invoke-ASH
# do. It returns from the sourced file and does not end the shell that sourced it.
if [ -z "${ASH_ROOT_DIR:-}" ]; then
  if [ -n "${_ash_helpers_found}" ]; then
    echo "ash_helpers.sh: '${_ash_helpers_found}', the directory above this file, is not an ASH checkout (it has no pyproject.toml). Set ASH_ROOT_DIR to your automated-security-helper checkout before sourcing this file." >&2
  else
    echo "ash_helpers.sh: this shell does not report the path of a sourced file. Set ASH_ROOT_DIR to your automated-security-helper checkout before sourcing this file." >&2
  fi
  unset _ash_helpers_found
  return 3 2>/dev/null || exit 3
fi
unset _ash_helpers_found
if [ ! -f "${ASH_ROOT_DIR}/pyproject.toml" ]; then
  echo "ash_helpers.sh: ASH_ROOT_DIR is '${ASH_ROOT_DIR}', which is not an ASH checkout (it has no pyproject.toml). Set ASH_ROOT_DIR to your automated-security-helper checkout before sourcing this file." >&2
  return 3 2>/dev/null || exit 3
fi

export ASH_ROOT_DIR
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"
export ASH_HELPERS_SCRIPT="${ASH_UTILS_DIR}/ash_helpers.sh"

# Function to invoke the ASH CLI in single container executable form.
#
# This used to run $ASH_ROOT_DIR/ash, the repository's bash entrypoint. That
# script is gone: the Python CLI parses its whole flag surface and
# run_ash_container.py does the OCI runner resolution and image build it used to
# do by hand. `--mode container` is what preserves the old behavior, because the
# bash script always ran the scan inside a container while the bare Python CLI
# defaults to running locally.
#
# Kept rather than deleted, even though it is now close to an alias, because the
# header above tells people to source this file from their shell profile and
# removing the function would break that on their next login.
invoke_ash() {
  ashx --mode container "$@"
}

# POSIX sh and ksh93 reject a hyphen in a function name, so invoke-ash is a function
# only where the shell accepts one, and otherwise an alias, whose name may contain a
# hyphen in every POSIX shell. The probe runs in a subshell because a syntax error
# inside eval exits a non-interactive POSIX shell. The alias from an earlier sourcing
# goes first: left in place, it would expand inside the probe and the definition and
# turn invoke_ash into a function that calls itself.
unalias invoke-ash 2>/dev/null || :
if (eval 'invoke-ash() { :; }') 2>/dev/null; then
  eval 'invoke-ash() { invoke_ash "$@"; }'
else
  alias invoke-ash=invoke_ash
fi
