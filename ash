#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# ASH_ROOT_DIR, the directory holding this script (the ASH repo root), is resolved
# below, once the helpers it needs are defined (resolve_file): a symlinked ./ash is
# followed to the script file, so the Dockerfile and the build context are the
# checkout's and not the link's directory, and a directory that cannot be entered is
# a refusal rather than the working directory. The cd that resolves it runs with
# CDPATH unset (resolve_dir): with one exported, cd searches its entries for a
# relative directory whose first component is not "." or ".." and prints the
# directory it went to, so a script invoked as `<checkout>/ash` from a directory that
# CDPATH also names (a projects directory, say) found the checkout through that entry
# and printed it, and ASH_ROOT_DIR held its path twice, on two lines. `./ash` and
# `ash` give "." and are never searched.

# Set local variables
SOURCE_DIR=""
# Empty until the source directory is resolved: the default is .ash/ash_output inside
# the scanned directory, as `ash scan` defaults it, not under the working directory.
OUTPUT_DIR=""
CONTAINER_UID_SPECIFIED="NO"
CONTAINER_GID_SPECIFIED="NO"
DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS:-}"
DOCKER_RUN_EXTRA_ARGS=""
ASH_ARGS=""
QUIET_ARG=""
NO_COLOR_ARG=""
COLOR_OUTPUT="true"
NO_BUILD="NO"
NO_RUN="NO"
DEBUG="NO"
OFFLINE="NO"
OFFLINE_SEMGREP_RULESETS="p/ci"
TARGET_STAGE="non-root"
INSTALL_ASH_REVISION="LOCAL"

# A refusal is this script declining its own arguments or environment, before anything
# is built or run. Every wrapper (this one, utils/ash_helpers.sh and Invoke-ASH) exits 3
# for one, except the usage errors `ash` itself refuses with 5, which exit 5 with its
# text: an explicit --sandbox (refuse_sandbox_unless_off below), one of this script's
# own value options given with no value (require_value; the CLI exits 5 for an option
# that requires an argument and got none), a --source-dir that names no directory to
# scan, and an --output-dir that is a file, cannot be made, cannot be entered or
# cannot be written (refuse_usage). A failed build or run is not a refusal: it keeps
# its own status.
WRAPPER_REFUSAL_EXIT=3
USAGE_ERROR_EXIT=5
refuse() {
  echo "ERROR: $*" >&2
  exit "${WRAPPER_REFUSAL_EXIT}"
}

# The text and exit 5 that `ash scan`, Invoke-ASH and the MCP server give for the same
# input (automated_security_helper/utils/directory_refusals.py).
refuse_usage() {
  echo "ERROR: $*" >&2
  exit "${USAGE_ERROR_EXIT}"
}

# A value from the command line or the environment, as this script prints it: as
# typed when a terminal would show every character in it, otherwise quoted as bash
# would read it back, so a control character in it is written out rather than sent
# to the terminal ($'\E]8;;...' instead of an OSC 8 link). A value holding a format
# character is quoted in the C locale, which writes every byte above 0x7f as octal:
# in a UTF-8 locale %q leaves a format character raw, and U+202E shown in place
# reverses the text after it. Any other value is quoted in the caller's locale, so
# its letters stay as typed. A printable value holding a backslash or $' is quoted
# too: printed as typed, the text $'a\E[2Jb' looked like the quoting of a real ESC.
# Every quoted form holds a backslash and no value printed as typed does, so each
# display reads back to one value, and a path with a space still reads as typed.
# In a UTF-8 locale so do characters a terminal shows that a reader may not see for
# what they are: spaces other than ASCII's (Zs, such as U+00A0 and U+3000), combining
# marks (Mn) and fillers such as U+3164. They are outside the set written out here
# and in Invoke-ASH, so a shown value holding one can still look like another. In the
# C locale their bytes are not printable, so the value is quoted with them in octal,
# as in $'img\302\240name'; Invoke-ASH keeps them in every locale.
shown() (
  # Not traced under --debug: set -x would write the value, and the bytes of the
  # format characters has_format_character looks for, to the terminal raw.
  { set +x; } 2>/dev/null
  if has_format_character "$1"; then
    LC_ALL=C
    printf '%q' "$1"
  elif [[ "$1" == *[![:print:]]* || "$1" == *\\* || "$1" == *\$\'* ]]; then
    printf '%q' "$1"
  else
    printf '%s' "$1"
  fi
)

# Whether $1 holds a Unicode format or separator character (categories Cf, Zl and
# Zp, as of Unicode 16), which a UTF-8 locale counts as printable: the bidirectional
# controls, the zero-width characters, the line and paragraph separators, the byte
# order mark, the soft hyphen, the tag characters, and the Arabic, Syriac, Kaithi,
# Egyptian, shorthand and musical format characters. Matched on their UTF-8 bytes
# in the C locale. merge's shown_shard_text writes out the same categories, and
# tests/unit/test_ash_bash_entrypoint_refusals.py checks the two agree. Private-use
# code points (Co: U+E000 to U+F8FF, and planes 15 and 16) are matched as well, as
# Invoke-ASH writes them out: a UTF-8 locale counts them printable too, and what a
# terminal shows for one is its font's.
has_format_character() (
  LC_ALL=C
  local pattern
  for pattern in $'\xc2\xad' $'\xd8[\x80-\x85\x9c]' $'\xdb\x9d' $'\xdc\x8f' \
    $'\xe0\xa2[\x90\x91]' $'\xe0\xa3\xa2' $'\xe1\xa0\x8e' \
    $'\xe2\x80[\x8b-\x8f\xa8-\xae]' $'\xe2\x81[\xa0-\xa4\xa6-\xaf]' \
    $'\xef\xbb\xbf' $'\xef\xbf[\xb9-\xbb]' $'\xf0\x91\x82\xbd' $'\xf0\x91\x83\x8d' \
    $'\xf0\x93\x90[\xb0-\xbf]' $'\xf0\x9b\xb2[\xa0-\xa3]' $'\xf0\x9d\x85[\xb3-\xba]' \
    $'\xf3\xa0[\x80\x81][\x80-\xbf]' \
    $'\xee[\x80-\xbf][\x80-\xbf]' $'\xef[\x80-\xa3][\x80-\xbf]' \
    $'\xf3[\xb0-\xbf][\x80-\xbf][\x80-\xbf]' $'\xf4[\x80-\x8f][\x80-\xbf][\x80-\xbf]'; do
    if [[ "$1" == *${pattern}* ]]; then
      return 0
    fi
  done
  return 1
)

# An option that takes a value, given last with none, an empty one or only whitespace.
# Without this check its variable would be set to the empty string and the script
# would go on: a trailing or empty --oci-runner would fall back to whichever runner
# is on PATH, a blank one would run a command named `build`, and a trailing or empty
# --source-dir would scan the working directory. $1 is the option as typed, $2 the count of arguments left, the
# option included, and $3 the value.
require_value() {
  if [[ "$2" -lt 2 || -z "${3//[[:space:]]/}" ]]; then
    refuse_usage "$1 needs a value."
  fi
}

# The value of one of this script's own value options, in OWN_VALUE, from either
# spelling: `--opt=value`, the value after the first "=", or `--opt value`, the next
# word. OWN_SHIFT is how many words past the option the caller shifts: 0 for the
# first spelling, 1 for the second. $1 is the word as typed, $2 the count of arguments
# left, the option included, and $3 the next word. Before this, only the spaced form
# was this script's: `--source-dir=X`, `--oci-runner=X`, `--build-target=ci` and the
# others fell through to the scan inside the container, which took the directory or
# ignored the option, while this script built and ran with its defaults.
own_value() {
  if [[ "$1" == *=* ]]; then
    OWN_VALUE="${1#*=}"
    OWN_SHIFT=0
    require_value "${1%%=*}" 2 "${OWN_VALUE}"
  else
    require_value "$1" "$2" "$3"
    OWN_VALUE="$3"
    OWN_SHIFT=1
  fi
}

# The scan inside the container runs its scanners unsandboxed (container mode never
# sandboxes inside the image; the container is the boundary), so a --sandbox mode
# asked for here would not be applied. Anything but off is refused as a usage error,
# exit 5, before the image is built, as `ash scan --mode container --sandbox <mode>`
# refuses it; so is a --sandbox with no mode or a value that is not a mode, whose
# message lists the modes. This is the one refusal that exits 5 rather than 3: it is
# the usage error ash itself gives for it.
refuse_sandbox_unless_off() {
  # off, in any case, is read without a tool: below, tr lower-cases the mode, and
  # without tr on PATH off would read as '' and be refused. Any other mode is.
  case "$1" in
    [Oo][Ff][Ff]) return 0 ;;
  esac
  # The mode is shown as the other refusals show a value. It was written with each
  # control byte replaced by '?', byte by byte, which cut a multibyte character such
  # as U+202E into text that is not UTF-8.
  local shown_mode
  shown_mode="$(shown "$1")"
  case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in
    off)
      return 0
      ;;
    auto | bwrap | firejail | landlock | sandbox-exec)
      echo "ERROR: --sandbox ${shown_mode} cannot be used with ASH in a container: the scanners run unsandboxed inside the container. Run 'ash scan --mode local --sandbox ${shown_mode}' to sandbox each scanner, or drop --sandbox." >&2
      ;;
    *)
      echo "ERROR: --sandbox '${shown_mode}' cannot be used with ASH in a container: it is not a sandbox mode, and off is the only one a container takes, since the scanners run unsandboxed inside it. To sandbox each scanner, run 'ash scan --mode local --sandbox <mode>' with one of auto, bwrap, firejail, landlock, sandbox-exec." >&2
      ;;
  esac
  exit 5
}

# The absolute path of directory $1 in RESOLVED_DIR, or a non-zero status when it
# cannot be entered. The value is read as a path and only as one: a relative path is
# taken from the working directory, so CDPATH is not searched and "-" is not $OLDPWD,
# and after "--" a value such as "-L", "-P" or "--" is not one of cd's options. Each
# of those sent cd to another directory, which was then mounted and scanned. pwd's
# output ends in a "." that is stripped afterwards, because $(...) strips trailing
# newlines: a directory named "src" plus a newline resolved to ./src.
resolve_dir() {
  local dir="$1" resolved
  if [[ "${dir}" != /* ]]; then
    dir="./${dir}"
  fi
  # With -P as $2, every symlink is resolved too: the directory's physical
  # path, which is the one a mount's source has to name.
  if [[ "${2:-}" == -P ]]; then
    resolved="$(CDPATH="" cd -P -- "${dir}" >/dev/null 2>&1 && pwd -P && echo .)" || return 1
  else
    resolved="$(CDPATH="" cd -- "${dir}" >/dev/null 2>&1 && pwd && echo .)" || return 1
  fi
  RESOLVED_DIR="${resolved%$'\n.'}"
}

# Where directory $1 will resolve to once mkdir -p makes it, in RESOLVED_DIR, or a
# non-zero status when no ancestor of it can be entered: its deepest ancestor that
# can be, resolved by resolve_dir, then the rest of $1. A relative path holds the
# working directory's path that way, and "../out" leaves it. The rest does not
# exist yet, so its "." and ".." parts are folded by name, as cd folds them in
# the resolved path once mkdir has made it: "x/../../out" with no "x" is the
# working directory's parent's "out", not a path under the working directory.
resolve_new_dir() {
  local existing="$1" rest="" base part folded=""
  if [[ "${existing}" != /* ]]; then
    existing="./${existing}"
  fi
  until resolve_dir "${existing}"; do
    if [[ "${existing}" != */* || "${existing}" == / ]]; then
      return 1
    fi
    rest="${existing##*/}${rest:+/${rest}}"
    existing="${existing%/*}"
    existing="${existing:-/}"
  done
  # An empty base is the root.
  base="${RESOLVED_DIR%/}"
  while [[ -n "${rest}" ]]; do
    part="${rest%%/*}"
    if [[ "${rest}" == */* ]]; then
      rest="${rest#*/}"
    else
      rest=""
    fi
    case "${part}" in
      "" | .) ;;
      ..)
        if [[ "${folded}" == */* ]]; then
          folded="${folded%/*}"
        elif [[ -n "${folded}" ]]; then
          folded=""
        else
          base="${base%/*}"
        fi
        ;;
      *) folded="${folded:+${folded}/}${part}" ;;
    esac
  done
  if [[ -n "${folded}" ]]; then
    RESOLVED_DIR="${base}/${folded}"
  else
    RESOLVED_DIR="${base:-/}"
  fi
}

# One character of UTF-8 at the start of a string, matched byte by byte in the C
# locale: the forms RFC 3629 allows, so no overlong form, no encoded surrogate and
# nothing above U+10FFFF, which is what Python decodes as UTF-8. iconv is not the
# judge: glibc's accepts 4-byte forms above U+10FFFF and 5-byte forms (measured
# with glibc 2.34).
# Whether $1 is UTF-8, one character at a time, whatever the locale. The eight
# forms are matched with bash's own pattern matcher, not =~: that hands the
# pattern to the platform's regex library, and macOS's refuses a bracket
# expression of raw bytes above 0x7f, so every path read as not UTF-8 there.
is_utf8() {
  local LC_ALL=C rest="$1" c
  while [[ -n "${rest}" ]]; do
    case "${rest}" in
      [$'\x01'-$'\x7f']*) c=1 ;;
      [$'\xc2'-$'\xdf'][$'\x80'-$'\xbf']*) c=2 ;;
      $'\xe0'[$'\xa0'-$'\xbf'][$'\x80'-$'\xbf']*) c=3 ;;
      [$'\xe1'-$'\xec'$'\xee'$'\xef'][$'\x80'-$'\xbf'][$'\x80'-$'\xbf']*) c=3 ;;
      $'\xed'[$'\x80'-$'\x9f'][$'\x80'-$'\xbf']*) c=3 ;;
      $'\xf0'[$'\x90'-$'\xbf'][$'\x80'-$'\xbf'][$'\x80'-$'\xbf']*) c=4 ;;
      [$'\xf1'-$'\xf3'][$'\x80'-$'\xbf'][$'\x80'-$'\xbf'][$'\x80'-$'\xbf']*) c=4 ;;
      $'\xf4'[$'\x80'-$'\x8f'][$'\x80'-$'\xbf'][$'\x80'-$'\xbf']*) c=4 ;;
      *) return 1 ;;
    esac
    rest="${rest:${c}}"
  done
}

# Refuse directory $3, given to option $1 as $2, when its path holds a newline, a
# carriage return, a comma or a double quote, or bytes that are not UTF-8. The
# runtimes read --mount as CSV: a newline ends the record, so the mount loses what
# follows it, its destination included, and a carriage return can end it too; a
# comma starts a field of the path's own, and a double quote starts CSV quoting. A
# later field overrides an earlier one and src is source's alias, so an output dir
# named "o,src=/etc" mounted the host's /etc read-write at /out. And they read it as
# UTF-8 text: docker took a byte that is not UTF-8 as U+FFFD, so it refused the
# mount, or mounted a directory of that other name where one existed. UTF-8 is
# judged in bash (is_utf8), so no other tool is needed.
require_mountable() {
  local held
  if [[ "$3" == *$'\n'* ]]; then
    held="a newline"
  elif [[ "$3" == *$'\r'* ]]; then
    held="a carriage return"
  elif [[ "$3" == *,* ]]; then
    held="a comma"
  elif [[ "$3" == *\"* ]]; then
    held="a double quote"
  elif ! is_utf8 "$3"; then
    held="bytes that are not UTF-8"
  else
    return 0
  fi
  if [[ "$2" == "$3" ]]; then
    refuse "$1 $(shown "$2") is a path with ${held} in it, which a container runtime's --mount cannot take. Rename the directory or give another."
  fi
  refuse "$1 $(shown "$2") resolves to $(shown "$3"), a path with ${held} in it, which a container runtime's --mount cannot take. Rename the directory or give another."
}

# The subcommands and root value options of the ash CLI, read by the subcommand
# detector, the argument loop and the config handling.
# tests/unit/test_sandbox_refused_by_every_container_entrypoint.py checks both
# lists against the real commands and options.
ASH_SUBCOMMANDS="scan build-image report merge mcp get-genai-guide config dependencies inspect plugin"
# The subcommands whose own -o is NOT the container runtime: get-genai-guide's -o is
# its --output, config's its --output-dir. After one of these, -o is the
# subcommand's and is forwarded. After scan, whose -o is the CLI's own alias of
# --oci-runner, after build-image, and after every other subcommand, -o is still
# this script's runner, as it is with no subcommand: `./ash scan -o podman` picks
# podman. Forwarding -o after every subcommand sent `scan -o podman` into the
# container while this script picked the first runner on PATH.
ASH_DASH_O_IS_THE_SUBCOMMANDS="get-genai-guide config"
# The root ash options that take a value. A value can be a subcommand's name
# (`--phases report`, `--phases inspect`), so the token after one of these is
# the option's value, not the subcommand.
ASH_ROOT_VALUE_OPTIONS="--ash-config-from-host --ash-plugin-modules --ash-revision-to-install --base-ref --build-target --config --config-file-from-another-checkout --config-file-from-scanned-repository --config-overrides --container-gid --container-uid --custom-build-arg --custom-containerfile --exclude-scanners --format --formats --log-level --min-severity --mode --oci --oci-runner --offline-semgrep-rulesets --output-dir --output-format --output-formats --phases --runner --sandbox --scanners --shard-count --shard-index --source-dir --strategy --workspace --workspace-config -c -f -g -o -u"

# The first word of ASH_ARG_WORDS that names an ash subcommand, in SUBCOMMAND,
# with its index in SUBCOMMAND_AT (-1 and "" when none is named), not counting
# the value of a root option, which can be a command's name (`--phases
# inspect`, `--config config`). Walks the words the refusals checked and the
# scan is given.
detect_subcommand() {
  SUBCOMMAND=""
  SUBCOMMAND_AT=-1
  SKIP_VALUE="NO"
  for ((ASH_WORD_AT = 0; ASH_WORD_AT < ${#ASH_ARG_WORDS[@]}; ASH_WORD_AT++)); do
    ASH_WORD="${ASH_ARG_WORDS[ASH_WORD_AT]}"
    if [[ "${SKIP_VALUE}" = "YES" ]]; then
      SKIP_VALUE="NO"
      continue
    fi
    if [[ " ${ASH_SUBCOMMANDS} " == *" ${ASH_WORD} "* ]]; then
      SUBCOMMAND="${ASH_WORD}"
      SUBCOMMAND_AT=${ASH_WORD_AT}
      break
    fi
    if [[ " ${ASH_ROOT_VALUE_OPTIONS} " == *" ${ASH_WORD} "* ]]; then
      # `--phases report` or `-f sarif`. `--phases=report` and `-fsarif` carry
      # their value in the same word, so nothing is skipped for them.
      SKIP_VALUE="YES"
    elif [[ "${ASH_WORD}" == -[!-]?* ]]; then
      # Clustered short options, as click reads them: the first letter that
      # takes a value takes the rest of the word, or the next word when it is
      # last.
      for ((ASH_AT = 1; ASH_AT < ${#ASH_WORD}; ASH_AT++)); do
        if [[ " ${ASH_ROOT_VALUE_OPTIONS} " == *" -${ASH_WORD:ASH_AT:1} "* ]]; then
          if ((ASH_AT + 1 == ${#ASH_WORD})); then
            SKIP_VALUE="YES"
          fi
          break
        fi
      done
    fi
  done
}

# The output of a command, in OUTPUT_KEPT, with a trailing line feed of its own
# kept: command substitution drops one, and the output here is a path, which
# can end in one. Read with a "." after it, as resolve_dir reads a path.
kept_output() {
  local output
  output="$("$@" && echo .)" || return 1
  OUTPUT_KEPT="${output%$'\n.'}"
}

# The file's path with every symlink followed, in RESOLVED_FILE: the link's
# target is what is read. Each step keeps a trailing line feed (kept_output,
# resolve_dir), so a link whose target ends in one, or a file reached through
# a directory whose name does, is refused by the caller's mount check rather
# than read as its neighbor. Empty, with a non-zero status, when the directory
# holding the file cannot be entered.
resolve_file() {
  local path="$1" target hops=0
  RESOLVED_FILE=""
  while [ -L "${path}" ]; do
    # At most 40 links are followed, the kernel's own limit, so a link loop
    # ends here with a failure and does not run forever.
    hops=$((hops + 1))
    if [ "${hops}" -gt 40 ]; then
      return 1
    fi
    kept_output readlink -- "${path}" || return 1
    target="${OUTPUT_KEPT}"
    case "${target}" in
      /*) path="${target}" ;;
      *)
        kept_output dirname -- "${path}" || return 1
        path="${OUTPUT_KEPT}/${target}"
        ;;
    esac
    # A target ending in '/' names a directory through the link, and [ -L ] on
    # "link/" follows the link and is false, so the loop stopped at a path that is
    # still a link and the walk went on from its name. The trailing slashes are
    # dropped (the root's own stays) so the link itself is tested next time around.
    while [[ "${path}" == */ && "${path}" != / ]]; do
      path="${path%/}"
    done
  done
  kept_output dirname -- "${path}" || return 1
  resolve_dir "${OUTPUT_KEPT}" -P || return 1
  kept_output basename -- "${path}" || return 1
  RESOLVED_FILE="${RESOLVED_DIR}/${OUTPUT_KEPT}"
}

# The ASH repo root: the directory holding this script, every symlink followed
# (resolve_file), with a trailing line feed in its name kept. It was
# `$(cd "$(dirname "$0")"; pwd)`: the directory of the path the script was started
# by, so a symlinked ./ash built from the link's directory with the wrong Dockerfile;
# a cd that failed fell back to the working directory, as the ';' let it; and the
# substitution dropped a trailing line feed. CDPATH never applies: resolve_dir
# clears it for its cd.
if ! resolve_file "$0"; then
  refuse "The directory holding this script, $(shown "$0"), cannot be entered, so the ASH repo root (the Dockerfile and the build context) cannot be found."
fi
export ASH_ROOT_DIR="${RESOLVED_FILE%/*}"
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"

# Whether the absolute name $1 is the scanned tree's (TREES, set where this is
# called). The absolute, uncollapsed spelling is walked one component at a
# time; ".." steps up lexically. The first link whose directory is inside a
# scanned tree decides, as the launcher judges where a link SITS and not where it
# is named (a link that is itself a tree's root sits in the directory above it),
# because the rest of the name is then the tree's to steer. A link
# outside every tree is collapsed with resolve_file, which reads links with
# plain readlink and cd -P as the rest of this script does (readlink
# -f is missing from BSD readlink before macOS 12.3, and a collapse that failed
# there would refuse every name through /tmp or /etc), and the walk continues
# where it lands. A collapse that fails (a link loop, or a link that cannot be
# read) cannot be decided, and the walk does not go on past it;
# nor does a component that cannot be looked up because its directory cannot
# be searched, which may be a link. With no tree link on the way, the name counts exactly when the walked path
# ends inside a tree. Status 0: the name is the tree's. 1: it is not. 2: the
# walk could not be decided, and UNDECIDED_AT says where: "link" for a link that
# cannot be resolved, "directory" for one that cannot be searched. This mirrors
# the launcher's _named_in_a_scanned_tree, which refuses in both cases, each in
# its own words.
named_in_a_scanned_tree() {
  local rest="${1#/}" walked="" part tree parent
  while [ -n "${rest}" ]; do
    part="${rest%%/*}"
    if [ "${part}" = "${rest}" ]; then rest=""; else rest="${rest#*/}"; fi
    case "${part}" in
      "" | .) continue ;;
      ..) walked="${walked%/*}"; continue ;;
    esac
    walked="${walked}/${part}"
    if [ -L "${walked}" ]; then
      for tree in "${TREES[@]}"; do
        case "${walked%/*}/" in "${tree%/}"/*) return 0 ;; esac
      done
      if [ -d "${walked}" ]; then
        # The chain is read without entering its final directory, which may
        # not be searchable: that is found by the lookup of the next
        # component, as "directory". A last name of "." or ".." comes back
        # from resolve_file as "<parent>/." or "<parent>/..", and the tree
        # tests here read the walked spelling as a literal prefix, so it is
        # folded into the physical parent by name.
        if resolve_file "${walked}"; then
          case "${RESOLVED_FILE##*/}" in
            .) walked="${RESOLVED_FILE%/.}" ;;
            ..) walked="${RESOLVED_FILE%/..}"; walked="${walked%/*}" ;;
            *) walked="${RESOLVED_FILE}" ;;
          esac
          # A parent that is the root makes "//name".
          walked="${walked#/}"
          walked="/${walked#/}"
          walked="${walked%/}"
        else
          UNDECIDED_AT="link"
          return 2
        fi
      elif resolve_file "${walked}"; then
        walked="${RESOLVED_FILE}"
      else
        UNDECIDED_AT="link"
        return 2
      fi
    elif [ ! -e "${walked}" ]; then
      # Not a link and not there. Absent is a plain component; but a name that
      # cannot be looked up because its directory cannot be searched may be a
      # link nobody here can see, so the walk cannot decide.
      parent="${walked%/*}"
      parent="${parent:-/}"
      if [ -d "${parent}" ] && [ ! -x "${parent}" ]; then
        UNDECIDED_AT="directory"
        return 2
      fi
    fi
  done
  for tree in "${TREES[@]}"; do
    case "${walked}/" in "${tree%/}"/*) return 0 ;; esac
  done
  return 1
}

# A config file the scanned tree did not write can still sit in another git
# checkout (an ops repository beside the scanned one, say). A local scan reads
# such a file as one that cannot grant, and `ash --mode container` tells the scan
# inside so with --config-file-from-another-checkout, because the mounted copy sits
# in no checkout there (run_ash_container._another_checkout_marks). The functions
# below port the judgment it runs, sandbox_grants.checkout_judgment, so this script
# sends the mark exactly when a local scan would count the file as in a checkout:
# a .git entry at the file's directory or above it, found from the name as given,
# from the real path, or from where a link the name goes through sits. The judgment
# reads .git entries by shape and owner and runs no git.

# Names of the .git entries already warned about, each between line feeds, so a
# warning is printed once per entry.
GIT_ENTRIES_WARNED=""
# The first .git entry git_entry_trusted could not judge without ls, for the refusal
# that names it; in_another_checkout empties it before each judgment.
UNJUDGED_ENTRY=""

# The warning a local scan logs for an entry it counts although it cannot look
# inside it (sandbox_grants._warn_unverifiable_git). $1 is the entry, $2 the reason.
warn_unverifiable_git() {
  case "${GIT_ENTRIES_WARNED}" in
    *$'\n'"$1"$'\n'*) return 0 ;;
  esac
  GIT_ENTRIES_WARNED="${GIT_ENTRIES_WARNED}"$'\n'"$1"$'\n'
  echo "WARNING: Treating $(shown "$1") as a checkout boundary although its contents cannot be read ($2): the conservative answer stands when the lookup cannot be made." >&2
}

# The refusal for a config file whose place cannot be judged: an unmarked file is
# read inside as the operator's, which is the looser reading, so the run does not
# start. $1 is the path as given, $2 why. The words are the launcher's
# (_another_checkout_marks), which words both of its files the same way.
refuse_unjudged() {
  refuse "The config file '$(shown "$1")' was prepared for mounting, but which of its files a git checkout other than the scanned one holds could not be judged: $2. Container mode refuses the scan rather than hand the scan inside a mounted file without the mark a local scan's judgment would give it."
}

# The mode and the owner of $2 as `ls $1` lists it, in LS_MODE and LS_UID; $1 is
# -ldn for an entry itself and -Ldn for what a link leads to. Non-zero when ls is
# missing, fails, or prints no listing. The mode is read by position (the first ten
# characters), so a marker after it, as macOS prints for an attribute or an ACL, is
# no matter.
ls_mode_and_owner() {
  local listing
  listing="$(LC_ALL=C ls "$1" -- "$2" 2>/dev/null)" || return 1
  read -r LS_MODE _ LS_UID _ <<<"${listing}"
  [[ "${LS_MODE}" =~ ^[-a-zA-Z]{10} && "${LS_UID}" =~ ^[0-9]+$ ]]
}

# Whether the .git entry $1 was left by a user who may place a checkout boundary,
# as sandbox_grants._left_by_a_trusted_user reads it: in a directory that group
# members or others can write, anyone can have left an entry, so it counts only
# when root, the directory's owner or the user running this script owns it; in any
# other directory its shape alone decides. Status 0: it counts. 1: it does not.
# 2: the answer needs ls (the shell has no test for the mode bits of a directory
# or the owner of a link) and ls is missing or failed; the first such entry is
# kept in UNJUDGED_ENTRY, for the refusal that names it.
git_entry_trusted() {
  local entry="$1" holder holder_owner
  holder="${entry%/*}"
  holder="${holder:-/}"
  # [[ -O ]] follows a link, so it settles only an entry that is not one.
  if [[ ! -L "${entry}" && -O "${entry}" ]]; then
    return 0
  fi
  if ! ls_mode_and_owner -Ldn "${holder}"; then
    UNJUDGED_ENTRY="${UNJUDGED_ENTRY:-${entry}}"
    return 2
  fi
  if [[ "${LS_MODE:5:1}" != "w" && "${LS_MODE:8:1}" != "w" ]]; then
    return 0
  fi
  holder_owner="${LS_UID}"
  if ! ls_mode_and_owner -ldn "${entry}"; then
    UNJUDGED_ENTRY="${UNJUDGED_ENTRY:-${entry}}"
    return 2
  fi
  if [[ "${LS_UID}" = "0" || "${LS_UID}" = "${holder_owner}" || "${LS_UID}" = "${EUID}" ]]; then
    return 0
  fi
  return 1
}

# Whether the .git entry $1 marks a git checkout, as sandbox_grants._git_shaped
# reads it: a link (one that leads nowhere counts, and a link counts before its
# type is looked at), a regular file whatever it holds, or a directory holding HEAD,
# and left by a trusted user (git_entry_trusted). A directory without HEAD that can
# be searched, an empty one, a FIFO and an entry that is not there do not count. A
# directory that cannot be searched counts, with a warning, because its HEAD could
# not be looked up. Status 0: it counts. 1: it does not. 2: not decidable.
git_shaped() {
  local entry="$1" unverifiable="" trust=0
  if [[ -L "${entry}" || -f "${entry}" ]]; then
    :
  elif [[ ! -d "${entry}" ]]; then
    return 1
  elif [[ ! -e "${entry}/HEAD" && ! -L "${entry}/HEAD" ]]; then
    if [[ -x "${entry}" ]]; then
      return 1
    fi
    unverifiable="Permission denied"
  fi
  git_entry_trusted "${entry}" || trust=$?
  if [[ "${trust}" -ne 0 ]]; then
    return "${trust}"
  fi
  if [[ -n "${unverifiable}" ]]; then
    warn_unverifiable_git "${entry}" "${unverifiable}"
  fi
  return 0
}

# Whether $1, or a directory above it, holds a git-shaped .git entry. $1 is an
# absolute path with nothing left to resolve in it. Every directory up to / is
# looked at, as the Python judgment looks at them, so an entry that cannot be
# judged does not hide a checkout above it. Status 0: one counts. 1: none does.
# 2: none counts and some entry could not be judged.
checkout_at_or_above() {
  local dir="$1" shaped result=1
  while :; do
    shaped=0
    git_shaped "${dir%/}/.git" || shaped=$?
    if [[ "${shaped}" -eq 0 ]]; then
      return 0
    elif [[ "${shaped}" -ne 1 ]]; then
      result=2
    fi
    if [[ -z "${dir}" || "${dir}" = "/" ]]; then
      return "${result}"
    fi
    dir="${dir%/*}"
    dir="${dir:-/}"
  done
}

# The absolute name $1 with every ".." applied the way the kernel applies it, in
# AS_NAMED (sandbox_grants._as_named): the components stay as spelled, and a ".."
# steps up from the physical directory what precedes it leads to, so a link before
# it is followed first. Non-zero when that directory cannot be entered.
as_named_path() {
  local rest="${1#/}" named="" part
  AS_NAMED=""
  while [[ -n "${rest}" ]]; do
    part="${rest%%/*}"
    if [[ "${part}" = "${rest}" ]]; then rest=""; else rest="${rest#*/}"; fi
    case "${part}" in
      "" | .) ;;
      ..)
        if [[ -n "${named}" ]]; then
          resolve_dir "${named}" -P || return 1
          named="${RESOLVED_DIR%/*}"
        fi
        ;;
      *) named="${named}/${part}" ;;
    esac
  done
  AS_NAMED="${named:-/}"
  return 0
}

# The directory each link the absolute name $1 goes through sits in, appended to
# LINK_PARENTS (sandbox_grants._walk_links). The name is walked one component at a
# time, as the kernel walks it: a link's target replaces the link in the rest of the
# name, a relative target is read from the link's directory, and ".." steps up the
# physical position, so a link reached only through another link counts too. Status
# 0: the walk reached the end. 1: it could not, and UNDECIDED_REASON says why: more
# than 40 links (the kernel's own limit), a link that cannot be read, or a name
# that cannot be looked up because its directory cannot be searched.
collect_link_parents() {
  local rest="${1#/}" walked="" part candidate target hops=0
  while [[ -n "${rest}" ]]; do
    part="${rest%%/*}"
    if [[ "${part}" = "${rest}" ]]; then rest=""; else rest="${rest#*/}"; fi
    case "${part}" in
      "" | .) continue ;;
      ..)
        walked="${walked%/*}"
        continue
        ;;
    esac
    candidate="${walked}/${part}"
    if [[ ! -L "${candidate}" ]]; then
      if [[ ! -e "${candidate}" && -d "${walked:-/}" && ! -x "${walked:-/}" ]]; then
        UNDECIDED_REASON="a directory on its path cannot be searched"
        return 1
      fi
      walked="${candidate}"
      continue
    fi
    hops=$((hops + 1))
    if [[ "${hops}" -gt 40 ]]; then
      UNDECIDED_REASON="its path goes through more than 40 links"
      return 1
    fi
    LINK_PARENTS+=("${walked:-/}")
    if ! kept_output readlink -- "${candidate}"; then
      UNDECIDED_REASON="a link on its path cannot be read"
      return 1
    fi
    target="${OUTPUT_KEPT}"
    case "${target}" in
      /*)
        walked=""
        rest="${target#/}${rest:+/${rest}}"
        ;;
      *) rest="${target}${rest:+/${rest}}" ;;
    esac
  done
  return 0
}

# Set CARRIED_ELSEWHERE to YES when a local scan would count the config file as
# inside a git checkout, NO when not (sandbox_grants.checkout_judgment, over the real
# path and each name the file is reached by). $1 is the path as given, $2 the file's
# real path, $3 why the walk of its names could not reach the end (empty when it did),
# the rest its absolute spellings. LINK_PARENTS holds the directory each link the
# spellings go through sits in, from the one walk carry_config_file makes with
# collect_link_parents, which the scanned tree's mark reads too. The file is judged
# from where each spelling sits as written, from where the real path sits, and from
# where each of those links sits. A checkout found settles it, whatever else could not
# be judged. A judgment that cannot be made, with no checkout found, is a refusal,
# exit 3.
in_another_checkout() {
  local given="$1" real="$2" reason="$3" spelling start found
  shift 3
  local starts=("${real}")
  for spelling in "$@"; do
    if as_named_path "${spelling}"; then
      starts+=("${AS_NAMED}")
    else
      reason="a directory on its path cannot be entered"
    fi
  done
  starts+=("${LINK_PARENTS[@]}")
  CARRIED_ELSEWHERE="NO"
  UNJUDGED_ENTRY=""
  for start in "${starts[@]}"; do
    found=0
    checkout_at_or_above "${start}" || found=$?
    if [[ "${found}" -eq 0 ]]; then
      CARRIED_ELSEWHERE="YES"
      return 0
    elif [[ "${found}" -ne 1 ]]; then
      reason="ls could not say who left $(shown "${UNJUDGED_ENTRY:-a .git entry}") or who can write the directory it is in"
    fi
  done
  if [[ -n "${reason}" ]]; then
    refuse_unjudged "${given}" "${reason}"
  fi
}

# Resolve one config input for the scan inside the container, against TREES and
# SOURCE_REAL (set where this is called), and set for its caller:
# CARRIED_INNER, the container path the scan reads; CARRIED_MOUNT, the --mount
# value when the file is mounted on its own, else empty; CARRIED_MARK, YES
# when a local scan of the source dir counts the file as the scanned
# repository's; and CARRIED_ELSEWHERE, YES when the file is mounted on its own, is
# not the scanned repository's, and a local scan counts it as inside a git checkout
# other than the scanned one (in_another_checkout). $1 is the option as the
# operator gave it (--config or ASH_CONFIG), $2 the label the launcher's refusals
# use, $3 the path given, $4 the mount root. Every refusal here is the launcher's,
# with its text. The judgment of the name is the launcher's too:
# named_in_a_scanned_tree over the uncollapsed absolute spelling, and the mark walk
# follows every link hop, as the local membership rule does.
carry_config_file() {
  local option="$1" label="$2" given="$3" mount_root="$4"
  local real abs_given abs_logical physical_cwd spelling spellings named_in_tree named_status real_in_tree tree flat parent walk_reason
  CARRIED_INNER=""
  CARRIED_MOUNT=""
  CARRIED_MARK="NO"
  CARRIED_ELSEWHERE="NO"
  # Given with a character a --mount cannot take, it is refused before it is
  # resolved, as a source directory is. Each refusal is the launcher's text,
  # with the value shown as ./ash shows one: the launcher's sinks one-pass a
  # control character themselves, and here the message goes to the terminal.
  require_mountable "${option}" "${given}" "${given}"
  if [[ -z "${given}" || ! -f "${given}" ]]; then
    refuse "Config file not found: $(shown "${given}"). --config (or ASH_CONFIG) has to name an existing file: container mode mounts it read-only for the scan inside the container."
  fi
  # The runner mounts with its own rights, which can be wider than ASH's.
  if [[ ! -r "${given}" ]]; then
    refuse "Config file cannot be read: $(shown "${given}"). ASH does not hand the container runner a file it cannot read itself."
  fi
  if ! resolve_file "${given}"; then
    refuse "Config file cannot be read: $(shown "${given}"). ASH does not hand the container runner a file it cannot read itself."
  fi
  real="${RESOLVED_FILE}"
  # The name as given, made absolute but not collapsed: the launcher's judgment
  # of it (named_in_a_scanned_tree) walks this spelling. A relative name is
  # taken from the physical working directory, as the launcher's os.getcwd()
  # and the kernel take it: a ".." after a link in $PWD would be read against
  # the link's own directory. When $PWD names that same directory under
  # another spelling, the name is also walked from $PWD, because a link the
  # shell stands below can sit in the scanned tree even when the physical
  # directory does not; either spelling being the tree's makes the name the
  # tree's.
  abs_logical=""
  if [[ "${given}" = /* ]]; then
    abs_given="${given}"
  else
    if ! resolve_dir . -P; then
      refuse "Config file cannot be read: $(shown "${given}"). ASH does not hand the container runner a file it cannot read itself."
    fi
    physical_cwd="${RESOLVED_DIR}"
    abs_given="${physical_cwd}/${given}"
    if [[ "${PWD:-}" = /* && "${PWD}" != "${physical_cwd}" ]] \
      && resolve_dir "${PWD}" -P && [[ "${RESOLVED_DIR}" = "${physical_cwd}" ]]; then
      abs_logical="${PWD%/}/${given}"
    fi
  fi
  require_mountable "${option}" "${given}" "${real}"
  named_in_tree="NO"
  spellings=("${abs_given}")
  if [[ -n "${abs_logical}" ]]; then
    spellings+=("${abs_logical}")
  fi
  for spelling in "${spellings[@]}"; do
    named_status=0
    named_in_a_scanned_tree "${spelling}" || named_status=$?
    if [[ "${named_status}" -eq 2 && "${UNDECIDED_AT}" = "directory" ]]; then
      refuse "The ${label} '$(shown "${given}")' goes through a directory that cannot be searched. ASH does not hand the container runner a name it cannot resolve: a directory on the way cannot be searched. Name the file itself."
    elif [[ "${named_status}" -eq 2 ]]; then
      refuse "The ${label} '$(shown "${given}")' goes through a link that cannot be resolved. ASH does not hand the container runner a name it cannot resolve: a link loop, or a link that cannot be read. Name the file itself."
    elif [[ "${named_status}" -eq 0 ]]; then
      named_in_tree="YES"
    fi
  done
  real_in_tree="NO"
  for tree in "${TREES[@]}"; do
    case "${real}" in "${tree%/}"/*) real_in_tree="YES" ;; esac
  done
  # A file named inside the scanned tree is mounted only when its real path,
  # every link on the way resolved, is inside the tree too; otherwise the
  # repository being scanned would choose which host file is read. A link that
  # stays inside the tree is followed.
  if [[ "${named_in_tree}" = "YES" && "${real_in_tree}" = "NO" ]]; then
    refuse "The ${label} '$(shown "${given}")' is inside the scanned tree but is a link, or is reached through one, to '$(shown "${real}")', which is outside it. ASH does not mount a file the repository being scanned points it at. Name the file itself, outside the repository, or one inside it."
  fi
  case "${real}" in
    "${SOURCE_REAL%/}"/*)
      # Read through /src, the scan's own tree inside the container, which
      # holds the extends bases it can name; no mount and no mark, as the scan
      # inside judges its own tree itself. An absolute extends base in it is
      # the scan's own refusal there: this script never mounts a chain.
      CARRIED_INNER="/src/${real#"${SOURCE_REAL%/}"/}"
      ;;
    *)
      # Mounted on its own, without the files it extends, so a config with an
      # extends entry would not resolve inside the container. Refused, as is
      # every chain this script cannot mount whole. It cannot parse YAML, JSON
      # or TOML, so it errs toward refusing: the key followed by ':' or '='
      # anywhere in the text with line breaks read as spaces (a JSON key and
      # its ':' on two lines, TOML's '=', YAML's '? extends' key), and any
      # quoted key holding a backslash, which may spell the name with an
      # escape.
      flat="$(tr '\r\n' '  ' < "${real}")"
      # A byte order mark at the start is dropped, so a key right after it is seen
      # at the start of the text; a dotted TOML key (ash.extends) has a '.' before
      # the key, so '.' is in the class; and the escaped-key test runs over the
      # flattened text too, with '=' as well as ':', so a TOML key spelled with an
      # escape and an escaped JSON key whose ':' is on the next line are refused as
      # the plain spellings are.
      flat="${flat#$'\xef\xbb\xbf'}"
      if printf '%s' "${flat}" | grep -Eq '(^|[[:space:].{,])["'"'"']?extends["'"'"']?[[:space:]]*[:=]' \
        || printf '%s' "${flat}" | grep -Eq '"[^"]*\\[^"]*"[[:space:]]*[:=]'; then
        refuse "The ${label} '$(shown "${given}")' is outside the source directory and has an extends entry. ./ash mounts such a config on its own, without the files it extends. Run ash --mode container, which mounts the chain, or put the config inside the source directory."
      fi
      kept_output basename -- "${real}"
      CARRIED_INNER="${mount_root}/${OUTPUT_KEPT}"
      CARRIED_MOUNT="type=bind,source=${real},destination=${CARRIED_INNER},readonly"
      # The directory each link the names go through sits in, walked once for both
      # marks below (collect_link_parents): whoever writes the directory a link sits
      # in chooses where it leads. A walk that cannot reach the end leaves the
      # reason in walk_reason and the links it did reach in LINK_PARENTS.
      LINK_PARENTS=()
      walk_reason=""
      for spelling in "${spellings[@]}"; do
        if ! collect_link_parents "${spelling}"; then
          walk_reason="${UNDECIDED_REASON}"
        fi
      done
      # A file the scanned repository wrote: its resolved path inside the
      # scanned tree, or its name reached through a link that sits in it. The
      # scan inside sees the file only under ${mount_root}, outside its own
      # tree, so the host decides and tells it, as the launcher's
      # _repository_written does. A link in some other checkout does not make
      # the file the scanned tree's, so only TREES decides here.
      if [[ "${real_in_tree}" = "YES" ]]; then
        CARRIED_MARK="YES"
      else
        for parent in "${LINK_PARENTS[@]}"; do
          for tree in "${TREES[@]}"; do
            case "${parent%/}/" in "${tree%/}"/*) CARRIED_MARK="YES" ;; esac
          done
        done
      fi
      # A file the scanned repository did not write can sit in another git checkout,
      # an ops repository beside the scanned one, say. It cannot grant either, and
      # the scan inside cannot see the checkout from the mount, so it is told, as the
      # launcher's _another_checkout_marks tells it (--config-file-from-another-checkout,
      # by the container path alone). A file marked as the scanned tree's keeps that
      # mark alone. A walk that could not reach the end and found no checkout refuses
      # the run, whichever mark it would have decided (in_another_checkout).
      if [[ "${CARRIED_MARK}" = "NO" ]]; then
        in_another_checkout "${given}" "${real}" "${walk_reason}" "${spellings[@]}"
      fi
      ;;
  esac
}

# Parse arguments. --config is recorded here, where its value is still one
# argument (ASH_ARGS splits into words below), and forwarded as before; for a
# scan, the config handling after the directory resolution replaces the value's
# words with the file's container path. The word after a value-taking inner
# option is that option's value, so it is not read as --config there
# (--config-overrides --config forwards both words); one that spells an option
# of this script's own is still read as that option, as before. The config
# handling covers the long forms only (--config PATH, --config=PATH): this
# script's -c is its no-color option, so pass a config with --config (the
# containerized CLI's own -c short form is available only when calling ash
# directly).
CONFIG_GIVEN="NO"
CONFIG_PATH=""
CONFIG_INLINE="NO"
INNER_VALUE_PENDING="NO"
# YES once a word naming an ash subcommand has been read (forward_word, below): -v
# before any subcommand is this script's --version, -v after one is the subcommand's
# --verbose. SUBCOMMAND_WORD is the first such word: -o after get-genai-guide or
# config is that subcommand's own option (ASH_DASH_O_IS_THE_SUBCOMMANDS), -o after
# scan or any other subcommand is this script's runner.
SUBCOMMAND_SEEN="NO"
SUBCOMMAND_WORD=""

# Forward word $1 to the scan, as the argument loop's fall-through does: appended to
# ASH_ARGS, with the loop remembering whether it was a value-taking inner option (the
# next word is then its value, not an option of this script's), a clustered short
# option ending in one, or a subcommand's name.
forward_word() {
  if [[ "${INNER_VALUE_PENDING}" = "YES" ]]; then
    INNER_VALUE_PENDING="NO"
  elif [[ " ${ASH_ROOT_VALUE_OPTIONS} " == *" $1 "* ]]; then
    INNER_VALUE_PENDING="YES"
  elif [[ " ${ASH_SUBCOMMANDS} " == *" $1 "* ]]; then
    if [[ "${SUBCOMMAND_SEEN}" = "NO" ]]; then
      SUBCOMMAND_WORD="$1"
    fi
    SUBCOMMAND_SEEN="YES"
  elif [[ "$1" == -[!-]?* ]]; then
    # Clustered short options, as click reads them: the first letter that
    # takes a value takes the rest of the word, or the next word when it
    # is last.
    for ((INNER_LETTER = 1; INNER_LETTER < ${#1}; INNER_LETTER++)); do
      if [[ " ${ASH_ROOT_VALUE_OPTIONS} " == *" -${1:INNER_LETTER:1} "* ]]; then
        if ((INNER_LETTER + 1 == ${#1})); then
          INNER_VALUE_PENDING="YES"
        fi
        break
      fi
    done
  fi
  ASH_ARGS="${ASH_ARGS} $1"
}

# True when a -o word at this point in the line is the subcommand's, not this
# script's runner: it is the value of a value-taking inner option that is still
# open, or it follows a subcommand whose own -o is not the runner
# (ASH_DASH_O_IS_THE_SUBCOMMANDS). After scan, build-image or any other subcommand,
# and with no subcommand, -o is this script's --oci-runner.
dash_o_is_the_subcommands() {
  if [[ "${INNER_VALUE_PENDING}" = "YES" ]]; then
    return 0
  fi
  [[ "${SUBCOMMAND_SEEN}" = "YES" && " ${ASH_DASH_O_IS_THE_SUBCOMMANDS} " == *" ${SUBCOMMAND_WORD} "* ]]
}

while (("$#")); do
  # Each of this script's own value options takes both spellings, `--opt value` and
  # `--opt=value`, and its short form takes the value spaced or attached (`-o podman`,
  # `-opodman`), as the CLI inside does; --oci and --runner are the CLI's own aliases
  # of --oci-runner, so they name this script's runner too.
  case $1 in
    --source-dir | --source-dir=*)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      SOURCE_DIR="${OWN_VALUE}"
      ;;
    --output-dir | --output-dir=*)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      OUTPUT_DIR="${OWN_VALUE}"
      ;;
    --offline)
      OFFLINE="YES"
      ;;
    --offline-semgrep-rulesets | --offline-semgrep-rulesets=*)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      OFFLINE_SEMGREP_RULESETS="${OWN_VALUE}"
      OFFLINE="YES"
      ;;
    --force)
      DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} --no-cache"
      ;;
    --quiet | -q)
      DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} -q"
      QUIET_ARG="--quiet"
      ;;
    --oci-runner | --oci-runner=* | --oci | --oci=* | --runner | --runner=*)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      OCI_RUNNER="${OWN_VALUE}"
      ;;
    -o)
      # -o is this script's --oci-runner with no subcommand and after scan or
      # build-image (the CLI's scan defines -o as its own alias of --oci-runner, so
      # `./ash scan -o podman` picks podman here). It is the subcommand's own after
      # get-genai-guide (`./ash get-genai-guide -o guide.md` writes the guide there;
      # read as the runner, it ran a command named guide.md) and after config (its
      # --output-dir), and as the value of a value-taking inner option it is that
      # option's value.
      if dash_o_is_the_subcommands; then
        forward_word "$1"
      else
        own_value "$1" "$#" "${2-}"
        shift "${OWN_SHIFT}"
        OCI_RUNNER="${OWN_VALUE}"
      fi
      ;;
    --container-uid | --container-uid=* | -u)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      CONTAINER_UID_SPECIFIED="YES"
      CONTAINER_UID="${OWN_VALUE}"
      ;;
    --container-gid | --container-gid=* | -g)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      CONTAINER_GID_SPECIFIED="YES"
      CONTAINER_GID="${OWN_VALUE}"
      ;;
    # The short forms with the value attached, `-opodman`, `-u1000`, `-g1000`, as click
    # reads them. Before this they fell through to the scan inside the container, so
    # the scan got a runner, UID or GID word it has no use for while this script built
    # and ran with its defaults. A blank attached value is refused as a missing one.
    -o?*)
      # The attached spelling follows the spaced -o above: this script's runner with
      # no subcommand and after scan or build-image, the subcommand's own after
      # get-genai-guide or config (`./ash get-genai-guide -oguide.md` writes the guide
      # to guide.md), and the value of a pending inner option when one is open. -u?*
      # and -g?* below take no such guard because their spaced forms take none: the
      # script owns the container UID and GID in every position.
      if dash_o_is_the_subcommands; then
        forward_word "$1"
      else
        require_value "-o" 2 "${1:2}"
        OCI_RUNNER="${1:2}"
      fi
      ;;
    -u?*)
      require_value "-u" 2 "${1:2}"
      CONTAINER_UID_SPECIFIED="YES"
      CONTAINER_UID="${1:2}"
      ;;
    -g?*)
      require_value "-g" 2 "${1:2}"
      CONTAINER_GID_SPECIFIED="YES"
      CONTAINER_GID="${1:2}"
      ;;
    --no-build)
      NO_BUILD="YES"
      ;;
    --no-run)
      NO_RUN="YES"
      ;;
    --debug|-d)
      DEBUG="YES"
      ;;
    --build-target | --build-target=*)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      TARGET_STAGE="${OWN_VALUE}"
      ;;
    --ash-revision | --ash-revision=* | -rev)
      own_value "$1" "$#" "${2-}"
      shift "${OWN_SHIFT}"
      INSTALL_ASH_REVISION="${OWN_VALUE}"
      ;;
    # --help and --version run the CLI on the host from this script's own directory,
    # not the caller's: `python -m` puts the working directory first on sys.path, so
    # run from a scanned checkout it would import that checkout's package under the
    # CLI's name. From ASH_ROOT_DIR the module is this repository's own.
    #
    # -v before any subcommand is this script's --version, as it always was:
    # `./ash -v` prints the version and exits, so a habit or a health check never
    # builds an image. After a subcommand it is that command's --verbose, which the
    # CLI inside defines on ash, scan and report: `./ash scan -v` scans, verbosely,
    # where it once printed a version and exited.
    #
    # Either exits with the CLI's own status: an `exit 0` after it reported success
    # when the host python could not run the CLI at all.
    --help | -h)
      (CDPATH="" cd -- "${ASH_ROOT_DIR}" && python -m automated_security_helper.cli.main --help)
      exit "$?"
      ;;
    --version)
      (CDPATH="" cd -- "${ASH_ROOT_DIR}" && python -m automated_security_helper.cli.main --version)
      exit "$?"
      ;;
    -v)
      if [[ "${SUBCOMMAND_SEEN}" = "YES" ]]; then
        ASH_ARGS="${ASH_ARGS} $1"
      else
        (CDPATH="" cd -- "${ASH_ROOT_DIR}" && python -m automated_security_helper.cli.main --version)
        exit "$?"
      fi
      ;;
    --no-color | -c)
      COLOR_OUTPUT="false"
      NO_COLOR_ARG="--no-color"
      ;;
    --sandbox | --sandbox=*)
      if [ "$1" = "--sandbox" ]; then
        shift
        SANDBOX_MODE="${1:-}"
      else
        SANDBOX_MODE="${1#--sandbox=}"
      fi
      refuse_sandbox_unless_off "${SANDBOX_MODE}"
      ASH_ARGS="${ASH_ARGS} --sandbox off"
      ;;
    --config | --config=*)
      if [[ "${INNER_VALUE_PENDING}" = "YES" ]]; then
        # The value of the inner option before it, not the option.
        INNER_VALUE_PENDING="NO"
      elif [[ "$1" == --config=* ]]; then
        CONFIG_GIVEN="YES"
        CONFIG_PATH="${1#--config=}"
        CONFIG_INLINE="YES"
      else
        # The value itself is read next time around, as any forwarded word is:
        # the last --config wins, as click reads a repeated option.
        CONFIG_GIVEN="YES"
        CONFIG_PATH="${2-}"
        CONFIG_INLINE="NO"
        INNER_VALUE_PENDING="YES"
      fi
      ASH_ARGS="${ASH_ARGS} $1"
      ;;
    --workspace | --workspace=*)
      WORKSPACE_GIVEN="YES"
      ASH_ARGS="${ASH_ARGS} $1"
      ;;
    *)
      # Everything else is ash's, --format included: scan reads it as its output
      # formats and report as the report format, so `./ash report --format text`
      # prints text.
      forward_word "$1"
      ;;
  esac
  shift
done

# The scan inside is given ASH_ARG_WORDS, $ASH_ARGS split into words, so one quoted
# argument that holds several words ("--quiet --sandbox bwrap") reaches it as
# several. The inner CLI applies a --sandbox after every --config-overrides, so
# sandbox.mode=off, appended below, would not beat one that got in this way: the
# refusal also runs over those words. read splits as an unquoted expansion would
# (-d '' reads past a newline, which it splits on too) but never globs, so a word
# such as `--sandbox*` cannot turn into a file named --sandbox=bwrap after the
# refusal has passed it; the scan is given these exact words.
#
# A workspace scan is refused over the same words, with exit 3, before anything is
# built or mounted. ./ash scans one directory: the scan inside the container is given
# ASH_SOURCE_DIR=/src, which counts as --source-dir and is refused next to
# --workspace (exit 4, after the image was built), and --workspace-config applies
# only to a workspace scan. `ash --mode container --workspace <file>` mounts the
# workspace itself.
#
# The sandbox pass runs over every word before the workspace pass, so an explicit
# --sandbox other than off is refused as the usage error it is, with 5, wherever it
# stands next to a --workspace: in one quoted argument, a --workspace ahead of it gave
# 3 and one after it 5. A separate --sandbox is refused while the options are read,
# before either pass, and Invoke-ASH runs its passes in the same order.
read -r -d '' -a ASH_ARG_WORDS <<< "${ASH_ARGS}"
for ((ASH_WORD_AT = 0; ASH_WORD_AT < ${#ASH_ARG_WORDS[@]}; ASH_WORD_AT++)); do
  case "${ASH_ARG_WORDS[ASH_WORD_AT]}" in
    --sandbox)
      refuse_sandbox_unless_off "${ASH_ARG_WORDS[ASH_WORD_AT + 1]:-}"
      ;;
    --sandbox=*)
      refuse_sandbox_unless_off "${ASH_ARG_WORDS[ASH_WORD_AT]#--sandbox=}"
      ;;
  esac
done
for ASH_WORD in "${ASH_ARG_WORDS[@]}"; do
  case "${ASH_WORD}" in
    --workspace | --workspace=* | --workspace-config | --workspace-config=*)
      refuse "./ash scans one directory and cannot run a workspace scan: the scan inside the container is given --source-dir /src, which it refuses next to --workspace, and it could not be told which workspace config the repository wrote. Run ash --mode container --workspace <file> instead."
      ;;
  esac
done

# An image name that starts with '-' reaches the runner as an option of its own, however
# it is quoted, so it is refused before anything is created or run. Beyond that, an
# image name (and ASH_BASE_IMAGE_OVERRIDE, below) may hold only
# A-Z, a-z, 0-9 and . _ : / @ -, and a build target only A-Z, a-z, 0-9 and . _ -; any
# other character is refused, as Invoke-ASH refuses it, with the same message. A build
# target reaches the runner only as --target's value and in the default image name's
# tag, and it is checked before the default image name is made from it, so it is
# refused as a build target, not as an image name it was never given as.
#
# The classes are spelled out, character by character, so the match is the same in
# every locale: a range such as [a-z] follows the locale's collation, and [[:alnum:]]
# and [[:space:]] are the locale's classes (in a UTF-8 locale [[:space:]] took U+2028
# but never U+00A0). A non-ASCII character, in any locale, is not in the list. The
# value is shown as a path refusal shows one: replacing control bytes with '?', byte
# by byte, would cut a multibyte character into text that is not UTF-8.
case "${TARGET_STAGE}" in
  -* | *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-]*) refuse "--build-target '$(shown "${TARGET_STAGE}")' starts with '-' or holds a character other than A-Z, a-z, 0-9 and . _ -, so it is not a Dockerfile stage. Name one, such as non-root or ci." ;;
esac

# The build reads stage names in any case, so --build-target NON-ROOT is non-root:
# lower-cased once, here, so every check below and the image tag see that name. A
# name with no upper-case letter, the default non-root among them, is its own
# lower-case and needs no tool, as `--sandbox off` needs none (refuse_sandbox_unless_off):
# lower-casing every run through tr made a run with tr off PATH a refusal for a
# stage it never had to change. A name with an upper-case letter goes through tr;
# a tr that fails or is missing leaves nothing, and an empty stage made the default
# image name 'automated-security-helper:', which the name check let through; so an
# empty result is a refusal. The class is spelled out, as the check above spells
# its own, so the match is the same in every locale.
case "${TARGET_STAGE}" in
  *[ABCDEFGHIJKLMNOPQRSTUVWXYZ]*)
    TARGET_STAGE_LOWER="$(printf '%s' "${TARGET_STAGE}" | tr '[:upper:]' '[:lower:]')"
    if [[ -z "${TARGET_STAGE_LOWER}" ]]; then
      refuse "--build-target $(shown "${TARGET_STAGE}") could not be lower-cased: tr failed or is not on PATH, so the image stage to build is unknown. Install coreutils (tr) and run again."
    fi
    TARGET_STAGE="${TARGET_STAGE_LOWER}"
    ;;
esac

export ASH_IMAGE_NAME=${ASH_IMAGE_NAME:-"automated-security-helper:${TARGET_STAGE}"}

case "${ASH_IMAGE_NAME}" in
  -* | *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@-]*) refuse "The image name '$(shown "${ASH_IMAGE_NAME}")' starts with '-', which the container runtime would read as an option, or holds a character other than A-Z, a-z, 0-9 and . _ : / @ -, which no image name does. Name an image with only those characters, not starting with '-'." ;;
esac

# Default to the working directory, resolved below like a --source-dir: "$(pwd)"
# dropped a trailing newline from its name, and a working directory "w" plus a
# newline mounted its sibling "w".
if [ "${SOURCE_DIR}" = "" ]; then
  SOURCE_DIR="."
fi

# Resolve the absolute paths, refusing a directory that cannot be entered. This was
# `$(cd "$DIR"; pwd)`, which prints the working directory when the cd fails, so a
# mistyped --source-dir scanned the working directory and an --output-dir naming a
# file sent the results there. Only a run reads them: --no-run builds the image and
# exits, so it neither checks nor creates them.
if [[ "${NO_RUN}" = "NO" ]]; then
  # Which case it is, in the words and the order `ash scan` uses: whether the path
  # can be reached, whether it is a directory, and whether its entries can be both
  # listed and entered. -e is false for a path under a directory that cannot be
  # searched as well as for one that is not there, so the nearest ancestor that -e
  # sees tells them apart: below one that cannot be searched, the path cannot be
  # reached, whether or not it is there.
  if [[ ! -e "${SOURCE_DIR}" ]]; then
    SOURCE_ANCESTOR="${SOURCE_DIR}"
    if [[ "${SOURCE_ANCESTOR}" != /* ]]; then
      SOURCE_ANCESTOR="./${SOURCE_ANCESTOR}"
    fi
    until [[ -e "${SOURCE_ANCESTOR}" || "${SOURCE_ANCESTOR}" != */* ]]; do
      SOURCE_ANCESTOR="${SOURCE_ANCESTOR%/*}"
      SOURCE_ANCESTOR="${SOURCE_ANCESTOR:-/}"
    done
    if [[ -d "${SOURCE_ANCESTOR}" && ! -x "${SOURCE_ANCESTOR}" ]]; then
      refuse_usage "Source directory cannot be entered: $(shown "${SOURCE_DIR}")"
    fi
    refuse_usage "Source directory does not exist: $(shown "${SOURCE_DIR}")"
  elif [[ ! -d "${SOURCE_DIR}" ]]; then
    refuse_usage "Source directory is not a directory: $(shown "${SOURCE_DIR}")"
  elif [[ ! -r "${SOURCE_DIR}" || ! -x "${SOURCE_DIR}" ]] || ! resolve_dir "${SOURCE_DIR}"; then
    refuse_usage "Source directory cannot be entered: $(shown "${SOURCE_DIR}")"
  fi
  require_mountable --source-dir "${SOURCE_DIR}" "${RESOLVED_DIR}"
  SOURCE_DIR="${RESOLVED_DIR}"
  # The source directory's physical path, every symlink resolved: the output-directory
  # protections below compare against it, so a link to the source counts.
  resolve_dir "${SOURCE_DIR}" -P
  SOURCE_PHYSICAL="${RESOLVED_DIR}"
  # The default output directory is inside the scanned directory, where `ash scan`
  # defaults it (source_dir/.ash/ash_output). Taken from the working directory, as it
  # was, `./ash --source-dir sub` run from a checkout root wrote its reports beside the
  # working directory, and a `.ash` link the repository commits at that root stood
  # outside the linked-output rule below, which covers links below the source: the
  # reports went where the link points.
  # A refusal of the default names --output-dir as the way to write elsewhere; one
  # of a directory the operator chose does not, as the choice is theirs already.
  OUTPUT_HINT=""
  if [ -z "${OUTPUT_DIR}" ]; then
    OUTPUT_DIR="${SOURCE_DIR%/}/.ash/ash_output"
    OUTPUT_HINT="; the default is inside the scanned directory, pass --output-dir to write elsewhere"
  fi
  # The refusal gives mkdir's reason (the text after its last ": ", such as "Not a
  # directory") but not mkdir's line, which quotes the path in its own way: GNU mkdir
  # escapes control characters, and others need not.
  OUTPUT_PATH="${OUTPUT_DIR}"
  if [[ "${OUTPUT_PATH}" != /* ]]; then
    OUTPUT_PATH="./${OUTPUT_PATH}"
  fi
  # Before mkdir, so a path that cannot be mounted is not created: the name as given,
  # then where it will resolve to, which for a relative name holds the working
  # directory's path. Checked again after mkdir, on the path itself.
  require_mountable --output-dir "${OUTPUT_DIR}" "${OUTPUT_DIR}"
  if resolve_new_dir "${OUTPUT_DIR}"; then
    require_mountable --output-dir "${OUTPUT_DIR}" "${RESOLVED_DIR}"
    # Made where it was checked. mkdir -p reads ".." after a link by where the link
    # points, while cd and the check read it by name, so "lnk/../out" was made
    # beside the link's target and the working directory's "out" mounted, or
    # refused, with the made directory left behind.
    OUTPUT_PATH="${RESOLVED_DIR}"
  fi
  # A file where the output directory goes, one that mkdir cannot make, and one
  # that is there but cannot be entered are the usage errors `ash scan` refuses
  # with 5, in its words. The reason for one that cannot be made is mkdir's own
  # (the text after its last ": ", such as "Not a directory"), without mkdir's
  # line, which quotes the path in its own way: GNU mkdir escapes control
  # characters, and others need not.
  if [[ -e "${OUTPUT_PATH}" && ! -d "${OUTPUT_PATH}" ]]; then
    refuse_usage "Output directory is not a directory: $(shown "${OUTPUT_DIR}")${OUTPUT_HINT}"
  fi
  # /out is mounted read-write and /src read-only: an output directory that is the
  # source directory or above it would hold the source tree, writable, at /out.
  # Compared by physical path, so a link to the source counts. One that does not exist
  # yet cannot hold the source, so this runs before the directory is created.
  if [[ -d "${OUTPUT_PATH}" ]] && resolve_dir "${OUTPUT_PATH}" -P; then
    OUTPUT_PHYSICAL="${RESOLVED_DIR}"
    case "${SOURCE_PHYSICAL%/}/" in
      "${OUTPUT_PHYSICAL%/}"/*)
        refuse "The output directory '$(shown "${OUTPUT_PATH}")' is the source directory '$(shown "${SOURCE_DIR}")' or a directory above it. Container mode mounts the output read-write at /out and the source read-only at /src, so the source would be writable through /out. Use an output directory inside the source (the default .ash/ash_output) or outside it, not above it${OUTPUT_HINT}."
        ;;
    esac
  fi
  # The same /out mount is why a linked output directory is refused: the scan inside
  # would write wherever the link leads, and a repository that commits
  # `.ash -> /some/host/dir` would choose that directory. Refused with exit 3: the
  # output directory when it is a symlink, wherever it is, and any symlink from below
  # the source directory down to it, with the source taken under its name and its
  # physical path. Links at or above the source are the operator's own spelling. The
  # path is walked as written, `..` included, and before the directory is created,
  # because creating it through a linked `.ash` already writes where the link points;
  # so --no-run would be refused as well, but it creates nothing and never reaches
  # here. `ash --mode container` and Invoke-ASH apply the same rule.
  # Whether path $1 stands below the source directory: by name, under the source as
  # given or under its physical path, or by place, when the directory that holds it
  # resolves, every link followed, to the source or a directory under it. The name
  # test alone decided by spelling: with the working directory itself a link to the
  # source, an output path spelled through it (`.ash/ash_output` from there) named
  # the source under a third name, and the committed `.ash` link it reached was
  # followed. RESOLVED_DIR is left as it was found.
  below_the_source() {
    local parent="${1%/*}" resolved_before="${RESOLVED_DIR-}" below=1
    case "$1" in
      "${SOURCE_DIR%/}"/* | "${SOURCE_PHYSICAL%/}"/*) return 0 ;;
    esac
    if resolve_dir "${parent:-/}" -P; then
      case "${RESOLVED_DIR%/}/" in
        "${SOURCE_PHYSICAL%/}"/*) below=0 ;;
      esac
    fi
    RESOLVED_DIR="${resolved_before}"
    return "${below}"
  }
  refuse_linked_output_dir() {
    local spelled="$1" rest part current="" link=""
    case "${spelled}" in
      /*) ;;
      *) spelled="$(pwd)/${spelled}" ;;
    esac
    rest="${spelled#/}"
    while [ -n "${rest}" ]; do
      part="${rest%%/*}"
      if [ "${part}" = "${rest}" ]; then rest=""; else rest="${rest#*/}"; fi
      case "${part}" in
        "" | .) continue ;;
        ..) current="${current%/*}"; continue ;;
      esac
      current="${current}/${part}"
      if [ -L "${current}" ] && below_the_source "${current}"; then
        link="${current}"
        break
      fi
    done
    if [ -z "${link}" ] && [ -n "${current}" ] && [ -L "${current}" ]; then
      link="${current}"
    fi
    if [ -n "${link}" ]; then
      refuse "Refusing the output directory '$(shown "$1")': the output directory path '$(shown "${link}")' is a symlink. Container mode mounts the output directory read-write at /out, so the scan inside the container would write through the link. Use a directory that is not a symlink and is not reached through one below the source directory${OUTPUT_HINT}."
    fi
  }
  refuse_linked_output_dir "${OUTPUT_DIR}"
fi

# Make the output directory and check that it takes a file, then set OUTPUT_DIR to
# its resolved path. Called once, here, right after the path checks above and before
# the container runtime is looked for, so that a missing --output-dir is made,
# parents and all, and one that cannot be made, entered or written is refused with 5
# in `ash scan`'s words whether or not a runtime follows
# (tests/unit/cli/test_directory_refusals_agree.py pins both on a PATH with no
# runtime); a --no-run has no output to make. The order matters: made any later,
# after the runtime lookup, those refusals would stand behind "Unable to resolve an
# OCI_RUNNER" and the directory would be left unmade on a host with no runtime.
create_output_dir() {
  if [[ "${NO_RUN}" != "NO" ]]; then
    return 0
  fi
  OUTPUT_EXISTED=NO
  if [[ -d "${OUTPUT_PATH}" ]]; then
    OUTPUT_EXISTED=YES
  fi
  MKDIR_ERROR="$(mkdir -p -- "${OUTPUT_PATH}" 2>&1 >/dev/null)"
  if ! resolve_dir "${OUTPUT_PATH}"; then
    if [[ -d "${OUTPUT_PATH}" ]]; then
      refuse_usage "Output directory cannot be entered: $(shown "${OUTPUT_DIR}")${OUTPUT_HINT}"
    fi
    MKDIR_REASON="${MKDIR_ERROR##*: }"
    MKDIR_REASON="${MKDIR_REASON//[![:print:]]/}"
    refuse_usage "Output directory cannot be created: $(shown "${OUTPUT_DIR}") (${MKDIR_REASON:-mkdir did not make it})${OUTPUT_HINT}"
  fi
  # One that was there already must take a file, as the scan writes them: one is
  # made under a name of its own with O_EXCL (bash's noclobber) and removed. -w is
  # not asked: it reads the permission bits for the effective user, not ACLs or a
  # read-only mount. The reason is bash's own, the text after its last ": ".
  if [[ "${OUTPUT_EXISTED}" = YES ]]; then
    WRITE_CHECK="${RESOLVED_DIR%/}/.ash-write-check.${RANDOM}${RANDOM}${RANDOM}"
    if WRITE_ERROR="$( { set -C; : >"${WRITE_CHECK}"; } 2>&1)"; then
      rm -f -- "${WRITE_CHECK:?}"
    else
      WRITE_REASON="${WRITE_ERROR##*: }"
      WRITE_REASON="${WRITE_REASON//[![:print:]]/}"
      refuse_usage "Output directory cannot be written: $(shown "${OUTPUT_DIR}") (${WRITE_REASON:-a file could not be made there})${OUTPUT_HINT}"
    fi
  fi
  require_mountable --output-dir "${OUTPUT_DIR}" "${RESOLVED_DIR}"
  OUTPUT_DIR="${RESOLVED_DIR}"
}
create_output_dir

# The config the scan reads: --config in the arguments, and the file the host's
# ASH_CONFIG names, which a local scan reads as its base whatever names the
# config. The scan inside the container sees the host only through its mounts,
# so a host path names nothing there. `ash --mode container`
# (interactions/run_ash_container.py) already carries both across that
# boundary, and this block mirrors it: a --config inside the source directory
# is read through the read-only /src mount; one outside it is mounted
# read-only on its own under /ash-config; the ASH_CONFIG file is mounted under
# /ash-env-config and named to the scan with --ash-config-from-host. A file
# the scanned repository wrote -- by its resolved path, or reached through a
# link that sits in the scanned tree -- is marked
# (--config-from-scanned-repository for the --config,
# --config-file-from-scanned-repository for the ASH_CONFIG file), as the
# launcher's _config_marks and _env_config_marks mark it. A file in some other git
# checkout is marked --config-file-from-another-checkout, by its container path,
# when a local scan would count it as in one (in_another_checkout), as the
# launcher's _another_checkout_marks marks it. When no --config was
# given, the ASH_CONFIG file is also named to the scan as its --config (with
# --config-from-scanned-repository when marked), whether or not the source
# directory holds a config of its own: ASH_CONFIG is the environment variable of
# the CLI's --config option, so for ./ash (a command-line entry, as `ash --mode
# container` is) the file is the option's value, and an option wins over
# discovery. The launcher's discovery-first rule is for a caller that leaves its
# config unset and has ASH_CONFIG only in the environment, where no option saw
# the variable. A missing or
# unreadable file, a file linked out of the scanned tree, and an outside file
# with an extends entry (this script cannot mount a chain) are refused with
# exit 3 before any build, in the launcher's words. The provenance options are
# the scan command's, so the handling covers a scan: no subcommand, or scan.
# Another subcommand keeps its words as it forwarded them.
CONFIG_RUN_ARGS=()
CONFIG_PROVENANCE_ARGS=()
detect_subcommand
if [[ "${NO_RUN}" = "NO" && ( -z "${SUBCOMMAND}" || "${SUBCOMMAND}" = "scan" ) ]]; then
  # Where the last --config stands among the words the scan is given, in CONFIG_AT
  # (-1 for none): the position the operator chose is kept when the host path is
  # replaced below, and a later --config still wins as click reads a repeated option.
  # The walk skips the values of value-taking options, as the subcommand detector
  # does, so --config as another option's value is not the option.
  CONFIG_AT=-1
  CFG_SKIP="NO"
  for ((CFG_I = 0; CFG_I < ${#ASH_ARG_WORDS[@]}; CFG_I++)); do
    CFG_WORD="${ASH_ARG_WORDS[CFG_I]}"
    if [[ "${CFG_SKIP}" = "YES" ]]; then
      CFG_SKIP="NO"
      continue
    fi
    case "${CFG_WORD}" in
      --config)
        CONFIG_AT=${CFG_I}
        CFG_SKIP="YES"
        ;;
      --config=*)
        CONFIG_AT=${CFG_I}
        ;;
      -[!-]?*)
        for ((CFG_LETTER = 1; CFG_LETTER < ${#CFG_WORD}; CFG_LETTER++)); do
          if [[ " ${ASH_ROOT_VALUE_OPTIONS} " == *" -${CFG_WORD:CFG_LETTER:1} "* ]]; then
            if ((CFG_LETTER + 1 == ${#CFG_WORD})); then
              CFG_SKIP="YES"
            fi
            break
          fi
        done
        ;;
      *)
        if [[ " ${ASH_ROOT_VALUE_OPTIONS} " == *" ${CFG_WORD} "* ]]; then
          CFG_SKIP="YES"
        fi
        ;;
    esac
  done
  # A --config that reached this script inside one quoted argument ("--config
  # path") was split into those words above and never read by the argument loop,
  # so the host path went to the scan as given, with no mount and no mark. Found
  # among the words, it is this script's --config as a separate one is.
  if [[ "${CONFIG_GIVEN}" = "NO" && "${CONFIG_AT}" -ge 0 ]]; then
    CONFIG_GIVEN="YES"
    if [[ "${ASH_ARG_WORDS[CONFIG_AT]}" == --config=* ]]; then
      CONFIG_INLINE="YES"
      CONFIG_PATH="${ASH_ARG_WORDS[CONFIG_AT]#--config=}"
    else
      CONFIG_INLINE="NO"
      CONFIG_PATH="${ASH_ARG_WORDS[CONFIG_AT + 1]:-}"
    fi
  fi
  if [[ "${CONFIG_GIVEN}" = "YES" || -n "${ASH_CONFIG:-}" ]]; then
    # The scanned tree, as a local scan defines it: the outermost directory at
    # or above the source dir holding a .git entry, under its logical and
    # physical names.
    resolve_dir "${SOURCE_DIR}" -P
    SOURCE_REAL="${RESOLVED_DIR}"
    TREES=()
    for TREE_START in "${SOURCE_DIR}" "${SOURCE_REAL}"; do
      TREE_DIR="${TREE_START}"
      TREE_CHECKOUT="${TREE_START}"
      while :; do
        if [ -e "${TREE_DIR}/.git" ]; then TREE_CHECKOUT="${TREE_DIR}"; fi
        if [ "${TREE_DIR}" = "/" ] || [ -z "${TREE_DIR}" ]; then break; fi
        kept_output dirname -- "${TREE_DIR}" || break
        TREE_DIR="${OUTPUT_KEPT}"
      done
      TREES+=("${TREE_CHECKOUT}")
      if resolve_dir "${TREE_CHECKOUT}" -P; then
        TREES+=("${RESOLVED_DIR}")
      fi
    done
  fi
  if [[ "${CONFIG_GIVEN}" = "YES" ]]; then
    carry_config_file --config "config file" "${CONFIG_PATH}" /ash-config
    if [[ -n "${CARRIED_MOUNT}" ]]; then
      CONFIG_RUN_ARGS+=(--mount "${CARRIED_MOUNT}")
    fi
    if [[ "${CARRIED_MARK}" = "YES" ]]; then
      CONFIG_PROVENANCE_ARGS+=(--config-from-scanned-repository)
    fi
    if [[ "${CARRIED_ELSEWHERE}" = "YES" ]]; then
      CONFIG_PROVENANCE_ARGS+=(--config-file-from-another-checkout "${CARRIED_INNER}")
    fi
    # Replace the host path's words with the container path, in place, at the
    # position CONFIG_AT found above. The argument loop recorded the value
    # whole, while ASH_ARG_WORDS holds it split, so the replaced span is the
    # value's own word count -- and the container path goes in as ONE word, so
    # a mounted file whose name holds spaces reaches the scan inside whole.
    if [[ "${CONFIG_INLINE}" = "YES" ]]; then
      # The inline word was split like any other, so a value with spaces
      # occupies several words; all of them are replaced.
      read -r -d '' -a CONFIG_VALUE_WORDS <<< "--config=${CONFIG_PATH}"
      ASH_ARG_WORDS=(
        "${ASH_ARG_WORDS[@]:0:CONFIG_AT}"
        "--config=${CARRIED_INNER}"
        "${ASH_ARG_WORDS[@]:CONFIG_AT+${#CONFIG_VALUE_WORDS[@]}}"
      )
    else
      read -r -d '' -a CONFIG_VALUE_WORDS <<< "${CONFIG_PATH}"
      ASH_ARG_WORDS=(
        "${ASH_ARG_WORDS[@]:0:CONFIG_AT}"
        --config "${CARRIED_INNER}"
        "${ASH_ARG_WORDS[@]:CONFIG_AT+1+${#CONFIG_VALUE_WORDS[@]}}"
      )
    fi
  fi
  if [[ -n "${ASH_CONFIG:-}" ]]; then
    carry_config_file ASH_CONFIG "ASH_CONFIG file" "${ASH_CONFIG}" /ash-env-config
    if [[ -n "${CARRIED_MOUNT}" ]]; then
      CONFIG_RUN_ARGS+=(--mount "${CARRIED_MOUNT}")
    fi
    CONFIG_PROVENANCE_ARGS+=(--ash-config-from-host "${CARRIED_INNER}")
    if [[ "${CARRIED_MARK}" = "YES" ]]; then
      CONFIG_PROVENANCE_ARGS+=(--config-file-from-scanned-repository "${CARRIED_INNER}")
    fi
    if [[ "${CARRIED_ELSEWHERE}" = "YES" ]]; then
      CONFIG_PROVENANCE_ARGS+=(--config-file-from-another-checkout "${CARRIED_INNER}")
    fi
    # With no --config given, the ASH_CONFIG file is also the scan's --config,
    # as it is for a scan on the host: the CLI reads the variable as the
    # option's value, so the file is named even when the source directory holds
    # a discoverable config. An explicit --config already won above.
    if [[ "${CONFIG_GIVEN}" = "NO" ]]; then
      CONFIG_PROVENANCE_ARGS+=(--config "${CARRIED_INNER}")
      if [[ "${CARRIED_MARK}" = "YES" ]]; then
        CONFIG_PROVENANCE_ARGS+=(--config-from-scanned-repository)
      fi
    fi
  fi
elif [ -n "${ASH_CONFIG:-}" ] && [ "${NO_RUN}" = "NO" ]; then
  # ASH_CONFIG names the operator's config for a local scan. For a subcommand
  # this handling does not cover, ./ash does not pass it into the container;
  # say so rather than drop it silently.
  echo "WARNING: ASH_CONFIG is set ($(shown "${ASH_CONFIG}")), but ./ash passes it into the container only for a scan, so ash ${SUBCOMMAND} there does not read it." >&2
fi

#
# Gather the UID and GID of the caller
#
HOST_UID=$(id -u)
HOST_GID=$(id -g)

# --container-uid and --container-gid become build arguments, read as numbers.
for id_flag in UID GID; do
  id_given="CONTAINER_${id_flag}_SPECIFIED"
  id_value="CONTAINER_${id_flag}"
  if [[ "${!id_given}" = "YES" && ! "${!id_value}" =~ ^[0-9]+$ ]]; then
    # The value is shown as every other refusal shows one, not written raw.
    refuse "Container ${id_flag} must be a numeric value: '$(shown "${!id_value}")'."
  fi
done

# The non-root stage creates its user with `adduser --uid <UID> --gid <GID>`. UID 0 is
# root, which already exists: that build fails at that step, after the whole core stage
# has been built. GID 0 is root's group, which would give the unprivileged user root's
# group rights over the image. Either is refused before building, with exit 3, as
# `ash --mode container`, `ash build-image` and Invoke-ASH refuse it. Any spelling of
# zero counts, since the build reads UID=00 as 0 too.
if [[ "${NO_BUILD}" = "NO" && "${TARGET_STAGE}" = "non-root" ]]; then
  BUILD_UID="${HOST_UID}"
  BUILD_GID="${HOST_GID}"
  if [[ "${CONTAINER_UID_SPECIFIED}" = "YES" ]]; then
    BUILD_UID="${CONTAINER_UID}"
  fi
  if [[ "${CONTAINER_GID_SPECIFIED}" = "YES" ]]; then
    BUILD_GID="${CONTAINER_GID}"
  fi
  if [[ "${BUILD_UID}" =~ ^0+$ ]]; then
    echo "ERROR: The non-root image stage creates a user with UID 0, which is root: ASH is running as root, or --container-uid 0 was given. Pass --build-target ci to build the image that runs as root. Another --container-uid and --container-gid work only when the output directory is writable by that UID: the container runs as that user and writes its reports there." >&2
    exit 3
  fi
  if [[ "${BUILD_GID}" =~ ^0+$ ]]; then
    echo "ERROR: The non-root image stage gives its user GID 0, which is root's group: ASH is running with GID 0, or --container-gid 0 was given. Pass --build-target ci to build the image that runs as root. Another --container-gid works only when the output directory is writable by the container's user, which writes its reports there." >&2
    exit 3
  fi
fi

# Resolve any offline mode flags
if [[ "${OFFLINE}" == "YES" ]]; then
  DOCKER_RUN_EXTRA_ARGS="${DOCKER_RUN_EXTRA_ARGS} --network=none"
fi

# Resolve the OCI_RUNNER
RESOLVED_OCI_RUNNER=${OCI_RUNNER:-$(command -v finch || command -v docker || command -v nerdctl || command -v podman)}
# If we couldn't resolve an OCI_RUNNER, refuse. Checked before OCI_RUNNER_WRAPPER is
# prefixed, which would otherwise turn an empty runner into "sudo " and pass the check.
# A blank OCI_RUNNER from the environment is refused too: unquoted below, " " ran a
# command named `build`.
if [[ -n "${OCI_RUNNER:-}" && -z "${OCI_RUNNER//[[:space:]]/}" ]]; then
    refuse "OCI_RUNNER is set to only whitespace. Set it to a runner, or unset it to use the first of finch, docker, nerdctl or podman on PATH."
elif [[ -z "${RESOLVED_OCI_RUNNER//[[:space:]]/}" ]]; then
    refuse "Unable to resolve an OCI_RUNNER: none of finch, docker, nerdctl or podman is on PATH. Install one, or set OCI_RUNNER or pass --oci-runner."
# else, build and run the image
else
    # The runner's words, one argument each. A runner found on PATH is one word, so a
    # runtime installed under a directory with a space in its name (Program Files
    # under Git Bash) runs: expanded unquoted in a string, it was split there. One the
    # operator gave (OCI_RUNNER, --oci-runner) is split on whitespace, as it was, so
    # it can carry arguments of its own.
    if [[ -n "${OCI_RUNNER:-}" ]]; then
        read -r -d '' -a RUNNER_WORDS <<< "${OCI_RUNNER}"
    else
        RUNNER_WORDS=("${RESOLVED_OCI_RUNNER}")
    fi
    # The runtime's own name, before any wrapper is prefixed and without the runner's
    # own arguments (the basename of the whole string never matched nerdctl or finch
    # for a runner given with arguments), for the few decisions that differ by runtime.
    OCI_RUNNER_NAME="$(basename "${RUNNER_WORDS[0]}")"
    # OCI_RUNNER_WRAPPER prefixes all OCI commands (like RUSTC_WRAPPER for cargo)
    # Example: OCI_RUNNER_WRAPPER=sudo makes all finch/docker calls use sudo
    if [[ -n "${OCI_RUNNER_WRAPPER:-}" ]]; then
        RESOLVED_OCI_RUNNER="${OCI_RUNNER_WRAPPER} ${RESOLVED_OCI_RUNNER}"
        read -r -d '' -a WRAPPER_WORDS <<< "${OCI_RUNNER_WRAPPER}"
        RUNNER_WORDS=("${WRAPPER_WORDS[@]}" "${RUNNER_WORDS[@]}")
    fi
    # Under a runner that reads workflow commands from the job's output (GitHub
    # Actions, Azure Pipelines, TeamCity), ash checks a terminal's lines too, but
    # only when it sees the runner's variable, so each one that is set goes into the
    # container: by name, or through OCI_RUNNER_WRAPPER, which need not pass this
    # script's environment on (sudo does not by default), with its value. These are
    # public markers of the CI system, not secrets, and no other variable's value
    # goes on the command line. An array, so a value with spaces (TeamCity's) stays
    # one word. A value holding a newline is refused here, before anything is built.
    # A wrapper of only spaces, tabs and newlines is none, as on the prefix line
    # above, where IFS splits it into no word, and in container mode. Any other
    # character, a vertical tab included, is a word there, so it is a wrapper here.
    RUNNER_ENV_ARGS=()
    if [ "${NO_RUN}" = "NO" ]; then
      for RUNNER_VARIABLE in GITHUB_ACTIONS TF_BUILD TEAMCITY_VERSION; do
        if [[ -z "${!RUNNER_VARIABLE:-}" ]]; then
          continue
        elif [[ -z "${OCI_RUNNER_WRAPPER//[$' \t\n']/}" ]]; then
          RUNNER_ENV_ARGS+=(-e "${RUNNER_VARIABLE}")
        elif [[ "${!RUNNER_VARIABLE}" == *$'\n'* ]]; then
          refuse "${RUNNER_VARIABLE} holds a newline, so it is not passed to the container: with OCI_RUNNER_WRAPPER set, GITHUB_ACTIONS, TF_BUILD and TEAMCITY_VERSION go on the runner's command line with their values. Remove the newline from ${RUNNER_VARIABLE}, or unset OCI_RUNNER_WRAPPER so the container gets the variable by name."
        else
          RUNNER_ENV_ARGS+=(-e "${RUNNER_VARIABLE}=${!RUNNER_VARIABLE}")
        fi
      done
    fi
    # Under --debug, the build and the run commands are traced shown (trace_command),
    # as set -x would print them but with each caller value shown rather than written
    # to the terminal raw: set -x traced the build line and every $(shown ...) call
    # with the raw values (--ash-revision, the runner, a layout directory), against
    # shown()'s own rule.
    trace_command() {
      local word trace="+"
      if [[ "${DEBUG}" != "YES" ]]; then
        return 0
      fi
      for word in "$@"; do
        trace+=" $(shown "${word}")"
      done
      printf '%s\n' "${trace}" >&2
    }
    # This script's own status lines, here and below, go to stderr, and so does the
    # build's output (the image ID under --quiet included): stdout is the container's
    # alone, so `./ash report --format json > file` writes the report and nothing
    # else into the file. Written to stdout, they stood at the top of it.
    echo "Resolved OCI_RUNNER to: $(shown "${RESOLVED_OCI_RUNNER}")" >&2

    # Build the image if the --no-build flag is not set
    if [ "${NO_BUILD}" = "NO" ]; then
      # The UID and GID build arguments, one word each: the given --container-uid
      # and --container-gid, else the caller's.
      CONTAINER_ID_OPTIONS=()
      if [[ ${CONTAINER_UID_SPECIFIED} = "YES" ]]; then
        CONTAINER_ID_OPTIONS+=(--build-arg "UID=${CONTAINER_UID}")
      elif [[ "${HOST_UID}" != "" ]]; then
        CONTAINER_ID_OPTIONS+=(--build-arg "UID=${HOST_UID}")
      fi
      if [[ ${CONTAINER_GID_SPECIFIED} = "YES" ]]; then
        CONTAINER_ID_OPTIONS+=(--build-arg "GID=${CONTAINER_GID}")
      elif [[ "${HOST_GID}" != "" ]]; then
        CONTAINER_ID_OPTIONS+=(--build-arg "GID=${HOST_GID}")
      fi
      # ASH_BASE_IMAGE_OVERRIDE redirects `FROM ${BASE_IMAGE}` at whichever registry actually
      # served the base image. .github/actions/prepull-base-image sets it when ECR Public
      # refuses and Docker Hub answers, as a digest-pinned reference.
      #
      # A local tag under the ECR name is not sufficient on its own. BuildKit falls back to a
      # local store after a registry refusal only when its worker has one -- the recovery in
      # sourceresolver/imageresolver.go is gated on `is.ImageStore == nil` -- and
      # worker/runc/runc.go sets that to nil explicitly. A buildkitd left on its default OCI
      # worker therefore ignores the tag, as does `docker buildx` on a docker-container driver,
      # both reachable here through OCI_RUNNER. Unquoted for the same reason as the two options
      # above: these expand to nothing when unset. An image reference holds no whitespace,
      # and one that did split here into options of the build's own
      # ("python:3.12 --network=host"), so such a value is refused below, as is one that
      # starts with '-', the same as an image name.
      #
      # ASH_BASE_OCI_LAYOUT=<layout dir>@<arch manifest digest> is the cache-hit hand-off from
      # the same action: a layout it has verified against the Dockerfile's pinned digest. This
      # entrypoint runs `<runner> build`, so on docker that is the docker driver, which turns an
      # oci-layout context into a registry lookup (measured) -- the action loads the layout into
      # the engine instead, and the driver prefers the local image. podman has no oci-layout
      # context and gets the same treatment in its own store. nerdctl and finch take the layout
      # as a build context, spelled without the digest because nerdctl reads the image from
      # index.json and treats the rest of the value as the path, plus --pull=false, which nerdctl
      # maps to image-resolve-mode=local. See .github/actions/prepull-base-image for the rest.
      # An array, one argument per word: the layout directory is a path the action
      # computed, and unquoted in a string it was split on its spaces and globbed,
      # so a directory with a space in its name reached the build as two options.
      BASE_IMAGE_OPTIONS=()
      if [[ -n "${ASH_BASE_OCI_LAYOUT:-}" ]]; then
        if [[ ! "${ASH_BASE_OCI_LAYOUT}" =~ ^(.+)@(sha256:[0-9a-f]{64})$ ]]; then
          refuse "ASH_BASE_OCI_LAYOUT is '$(shown "${ASH_BASE_OCI_LAYOUT}")', which is not <layout dir>@sha256:<64 hex>. Unset it to build from the Dockerfile's own base image reference."
        fi
        case "${OCI_RUNNER_NAME}" in
          nerdctl | finch)
            BASE_IMAGE_OPTIONS=(--build-context "ash-base-image=oci-layout://${BASH_REMATCH[1]}" --build-arg BASE_IMAGE=ash-base-image --pull=false)
            echo "Base image taken from the verified OCI layout named by ASH_BASE_OCI_LAYOUT, with no registry call." >&2
            ;;
          *)
            echo "Base image expected in $(shown "${OCI_RUNNER_NAME}")'s local store, placed there from the verified OCI layout named by ASH_BASE_OCI_LAYOUT." >&2
            ;;
        esac
      elif [[ -n "${ASH_BASE_IMAGE_OVERRIDE:-}" ]]; then
        case "${ASH_BASE_IMAGE_OVERRIDE}" in
          -* | *[!ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/@-]*) refuse "ASH_BASE_IMAGE_OVERRIDE '$(shown "${ASH_BASE_IMAGE_OVERRIDE}")' starts with '-' or holds a character other than A-Z, a-z, 0-9 and . _ : / @ -, which no image reference does. Name an image reference with only those characters, or unset it to build from the Dockerfile's own base image reference." ;;
        esac
        BASE_IMAGE_OPTIONS=(--build-arg "BASE_IMAGE=${ASH_BASE_IMAGE_OVERRIDE}")
        echo "Base image redirected to $(shown "${ASH_BASE_IMAGE_OVERRIDE}") by ASH_BASE_IMAGE_OVERRIDE." >&2
      fi
      # A new BUILD_DATE_EPOCH re-runs the Dockerfile's core stage from its apt-get
      # upgrade step down, offline download included (see ARG BUILD_DATE_EPOCH there).
      # It is UTC midnight of today, so rebuilds on the same day come from the layer
      # cache, and OS packages and offline databases are at most a day old.
      NOW_EPOCH="$(date +%s)"
      BUILD_DATE_EPOCH=$((NOW_EPOCH - NOW_EPOCH % 86400))
      echo "Building image $(shown "${ASH_IMAGE_NAME}") -- this may take a few minutes during the first build..." >&2
      # DOCKER_EXTRA_ARGS is this script's own (--no-cache, -q) and the caller's
      # environment, split on whitespace as it was.
      read -r -d '' -a EXTRA_BUILD_ARGS <<< "${DOCKER_EXTRA_ARGS}"
      BUILD_COMMAND=(
        "${RUNNER_WORDS[@]}" build
          "${CONTAINER_ID_OPTIONS[@]}"
          "${BASE_IMAGE_OPTIONS[@]}"
          --tag "${ASH_IMAGE_NAME}"
          --target "${TARGET_STAGE}"
          --file "${ASH_ROOT_DIR}/Dockerfile"
          --build-arg "OFFLINE=${OFFLINE}"
          --build-arg "INSTALL_ASH_REVISION=${INSTALL_ASH_REVISION}"
          --build-arg "OFFLINE_SEMGREP_RULESETS=${OFFLINE_SEMGREP_RULESETS}"
          --build-arg "BUILD_DATE_EPOCH=${BUILD_DATE_EPOCH}"
          "${EXTRA_BUILD_ARGS[@]}"
          "${ASH_ROOT_DIR}"
      )
      trace_command "${BUILD_COMMAND[@]}"
      "${BUILD_COMMAND[@]}" >&2
      BUILD_RC=$?

      # Captured on the line above, before anything else can overwrite $?.
      #
      # This script does not run under `set -e`, so without an explicit check a
      # failed build falls straight through to the run below. The runner then
      # cannot find the image locally, tries to pull it from docker.io and
      # quay.io, and reports "reading manifest ci in docker.io/..." with exit
      # 125 -- which reads like a registry or credentials problem and says
      # nothing about the build step that actually failed.
      if [ ${BUILD_RC} -ne 0 ]; then
        echo "ERROR: failed to build image $(shown "${ASH_IMAGE_NAME}") (exit ${BUILD_RC}). See the build output above for the failing step." >&2
        exit ${BUILD_RC}
      fi
    fi

    # Run the image if the --no-run flag is not set
    RC=0
    if [ "${NO_RUN}" = "NO" ]; then
      # The source dir is mounted read-only wherever the output dir is. The output
      # dir has its own mount at /out and the scan inside writes there, so nothing
      # writes through /src, also when OUTPUT_DIR is inside SOURCE_DIR (the default
      # .ash/ash_output is).

      # Capture terminal size if tput is available so the container experience can be improved
      if command -v tput >/dev/null 2>&1 && [ -t 1 ]; then
        DOCKER_RUN_EXTRA_ARGS="${DOCKER_RUN_EXTRA_ARGS} -e COLUMNS=$(tput cols) -e LINES=$(tput lines)"
      fi
      if [[ "${COLOR_OUTPUT}" = "true" ]] && [ -t 1 ]; then
        DOCKER_RUN_EXTRA_ARGS="${DOCKER_RUN_EXTRA_ARGS} -t"
      fi
      # The container's stdin is kept open (-i) only for a run that reads it. The
      # subcommands that read stdin are ASH_READS_STDIN: mcp, whose default stdio
      # transport is driven by the client over stdin; inspect, the Textual app, which
      # reads keys; and config, whose init and fix steps prompt for answers. Any
      # subcommand reads stdin when given `--cli-json-input -`, which takes its
      # parameters as a JSON document from stdin. Without -i none of them got any
      # input. No other run reads stdin, and -i on one makes the container consume
      # the caller's input: `while read d; do ./ash --source-dir "$d"; done
      # < dirs.txt` ended after one directory, a job script fed to bash on stdin lost
      # the commands after ./ash, and `./ash scan &` from an interactive shell had the
      # runner read the terminal and stopped on SIGTTIN. SUBCOMMAND is the first of
      # ash's words that names a subcommand (detect_subcommand, above). The list
      # must name the subcommands that read stdin;
      # tests/unit/test_ash_bash_entrypoint_subcommand_args.py checks it against the
      # CLI's own readers.
      ASH_READS_STDIN="config inspect mcp"
      KEEP_STDIN="NO"
      if [[ -n "${SUBCOMMAND}" && " ${ASH_READS_STDIN} " == *" ${SUBCOMMAND} "* ]]; then
        KEEP_STDIN="YES"
      fi
      for ((STDIN_WORD_AT = 0; STDIN_WORD_AT < ${#ASH_ARG_WORDS[@]}; STDIN_WORD_AT++)); do
        case "${ASH_ARG_WORDS[STDIN_WORD_AT]}" in
          --cli-json-input)
            if [[ "${ASH_ARG_WORDS[STDIN_WORD_AT + 1]:-}" = "-" ]]; then
              KEEP_STDIN="YES"
            fi
            ;;
          --cli-json-input=-)
            KEEP_STDIN="YES"
            ;;
        esac
      done
      if [[ "${KEEP_STDIN}" = "YES" ]]; then
        DOCKER_RUN_EXTRA_ARGS="${DOCKER_RUN_EXTRA_ARGS} -i"
      fi
      # --quiet and --no-color are this script's options as well as ash's, and they
      # are handed on to ash in front of its arguments. ash passes an option given
      # before a subcommand on to it only when the subcommand takes it, and refuses
      # it otherwise (`ash --quiet report` exits 5), so each goes only where it is
      # taken. The lists must name the subcommands that declare the option;
      # tests/unit/test_ash_bash_entrypoint_subcommand_args.py checks them against
      # the real commands.
      ASH_TAKES_QUIET="scan build-image mcp"
      ASH_TAKES_COLOR="scan build-image report merge mcp"
      # Container mode never sandboxes the scanners inside the image; the container
      # is the boundary. So the scan is given --sandbox off, as `ash scan --mode
      # container` gives its inner scan sandbox.mode=off (run_ash_scan.py). The scan
      # applies the flag as sandbox.mode after every --config-overrides, which beat
      # a config file, and a flag on the command line beats a --cli-json-input
      # document's sandbox; a document's own config_overrides still apply. Only scan
      # takes --sandbox, as does ash with no command named, which scans; another
      # command refuses it and runs no scanners, so it is given nothing. The command
      # is the first word that names one, not counting the value of a root option,
      # which can be a command's name (`--phases inspect`, `--config config`).
      # utils/ash_helpers.ps1 has the same lists;
      # tests/unit/test_sandbox_refused_by_every_container_entrypoint.py checks both
      # against the real commands and options.
      ASH_TAKES_SANDBOX="scan"
      # Run again rather than reused: the config handling above may have replaced
      # the words of a --config value, which moves a subcommand that stood after
      # them, and the splice below needs the index in the words the scan is given.
      detect_subcommand
      ASH_FLAG_ARGS=""
      if [[ -n "${QUIET_ARG}" ]] && [[ -z "${SUBCOMMAND}" || " ${ASH_TAKES_QUIET} " == *" ${SUBCOMMAND} "* ]]; then
        ASH_FLAG_ARGS="${ASH_FLAG_ARGS} ${QUIET_ARG}"
      fi
      if [[ -n "${NO_COLOR_ARG}" ]] && [[ -z "${SUBCOMMAND}" || " ${ASH_TAKES_COLOR} " == *" ${SUBCOMMAND} "* ]]; then
        ASH_FLAG_ARGS="${ASH_FLAG_ARGS} ${NO_COLOR_ARG}"
      fi
      # --sandbox off goes right after the command word, or before every word when
      # no command is named, never after the caller's words: there a `--` would make
      # it scan's extra arguments, and a value-taking option left last
      # (`--base-ref`) would take --sandbox as its value. Ahead of them, that option
      # fails as a usage error. The position does not change what wins: the scan
      # applies the flag after every override, and every other --sandbox the caller
      # gives is refused above. The config provenance options ride the same splice:
      # they are the scan command's, and they are non-empty only when the config
      # handling above ran, which holds under the same subcommand gate.
      ASH_RUN_WORDS=("${ASH_ARG_WORDS[@]}")
      if [[ -z "${SUBCOMMAND}" || " ${ASH_TAKES_SANDBOX} " == *" ${SUBCOMMAND} "* ]]; then
        SANDBOX_OFF_AT=$((SUBCOMMAND_AT + 1))
        # --offline is this script's option too, read by the argument loop and not
        # forwarded: it cut the container's network and set the image's build
        # argument, but told the scan nothing, so with --no-build and an image built
        # online the scan ran in online mode with no network. The scan's own
        # --offline rides the same splice.
        SCAN_MODE_ARGS=(--sandbox off)
        if [[ "${OFFLINE}" = "YES" ]]; then
          SCAN_MODE_ARGS+=(--offline)
        fi
        ASH_RUN_WORDS=(
          "${ASH_ARG_WORDS[@]:0:SANDBOX_OFF_AT}"
          "${SCAN_MODE_ARGS[@]}"
          "${CONFIG_PROVENANCE_ARGS[@]}"
          "${ASH_ARG_WORDS[@]:SANDBOX_OFF_AT}"
        )
      fi
      echo "Running ASH scan using built image..." >&2
      # The mounted paths go in through ASH_SOURCE_DIR and ASH_OUTPUT_DIR rather than
      # as --source-dir/--output-dir in front of the arguments. A subcommand in the
      # arguments (`./ash report`) would otherwise be refused, because ash passes an
      # option given before a subcommand on to it only when it takes the option, and
      # only scan takes --source-dir. scan, report and merge read the variables;
      # anything set on the command line still wins over them.
      # The image name is quoted, here and in the build, as is the build target that
      # names its default: either is the caller's value, and unquoted, a value with
      # spaces gave the runner options of its own (`-e ASH_CONFIG=...`) or gave the
      # scan in the image words the --sandbox refusal never saw. The runner is
      # RUNNER_WORDS, one argument each (its OCI_RUNNER_WRAPPER prefix split as
      # before; a runner found on PATH whole); DOCKER_RUN_EXTRA_ARGS stays unquoted,
      # as the extra args are this script's own. Under --debug this line is traced
      # shown (trace_command): through a wrapper it carries the runner markers'
      # values, and set -x wrote a control in one to the terminal raw.
      RUN_COMMAND=(
        "${RUNNER_WORDS[@]}" run
          --rm
          -e "ASH_ACTUAL_SOURCE_DIR=${SOURCE_DIR}"
          -e "ASH_ACTUAL_OUTPUT_DIR=${OUTPUT_DIR}"
          -e "ASH_DEBUG=${DEBUG}"
          -e "ASH_SOURCE_DIR=/src"
          -e "ASH_OUTPUT_DIR=/out"
          --mount source="${SOURCE_DIR}",type=bind,destination=/src,readonly
          --mount source="${OUTPUT_DIR}",type=bind,destination=/out
          "${CONFIG_RUN_ARGS[@]}"
          ${DOCKER_RUN_EXTRA_ARGS}
          "${RUNNER_ENV_ARGS[@]}"
          "${ASH_IMAGE_NAME}"
            ash
              ${ASH_FLAG_ARGS}
              "${ASH_RUN_WORDS[@]}"
      )
      trace_command "${RUN_COMMAND[@]}"
      "${RUN_COMMAND[@]}"
      RC=$?
    fi
    exit ${RC}
fi
