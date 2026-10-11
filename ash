#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Resolve the absolute path of the parent of the script directory (ASH repo root)
export ASH_ROOT_DIR="$(cd -- "$(dirname -- "$0")"; pwd)"
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"

# Set local variables
SOURCE_DIR=""
OUTPUT_DIR=".ash/ash_output"
CONTAINER_UID_SPECIFIED="NO"
CONTAINER_GID_SPECIFIED="NO"
OUTPUT_FORMAT="text"
DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS:-}"
DOCKER_RUN_EXTRA_ARGS=""
ASH_ARGS=""
COLOR_OUTPUT="true"
NO_BUILD="NO"
NO_RUN="NO"
DEBUG="NO"
OFFLINE="NO"
OFFLINE_SEMGREP_RULESETS="p/ci"
TARGET_STAGE="non-root"
INSTALL_ASH_REVISION="LOCAL"
CONFIG_GIVEN="NO"
CONFIG_PATH=""
# Parse arguments
while (("$#")); do
  case $1 in
    --source-dir)
      shift
      SOURCE_DIR="$1"
      ;;
    --output-dir)
      shift
      OUTPUT_DIR="$1"
      ;;
    --offline)
      OFFLINE="YES"
      ;;
    --offline-semgrep-rulesets)
      shift
      OFFLINE_SEMGREP_RULESETS="$1"
      OFFLINE="YES"
      ;;
    --force)
      DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} --no-cache"
      ;;
    --quiet | -q)
      DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} -q"
      ASH_ARGS="${ASH_ARGS} --quiet"
      ;;
    --oci-runner | -o)
      shift
      OCI_RUNNER="$1"
      ;;
    --container-uid | -u)
      shift
      CONTAINER_UID_SPECIFIED="YES"
      CONTAINER_UID="$1"
      ;;
    --container-gid | -g)
      shift
      CONTAINER_GID_SPECIFIED="YES"
      CONTAINER_GID="$1"
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
    --format)
      shift
      OUTPUT_FORMAT="$1"
      ;;
    --build-target)
      shift
      TARGET_STAGE="$1"
      ;;
    --ash-revision | -rev)
      shift
      INSTALL_ASH_REVISION="$1"
      ;;
    --config)
      shift
      CONFIG_GIVEN="YES"
      CONFIG_PATH="$1"
      ;;
    --config=*)
      CONFIG_GIVEN="YES"
      CONFIG_PATH="${1#--config=}"
      ;;
    --help | -h)
      python -m automated_security_helper.cli.main --help
      exit 0
      ;;
    --version | -v)
      python -m automated_security_helper.cli.main --version
      exit 0
      ;;
    --no-color | -c)
      COLOR_OUTPUT="false"
      ASH_ARGS="${ASH_ARGS} --no-color"
      ;;
    *)
      ASH_ARGS="${ASH_ARGS} $1"
  esac
  shift
done

# The build reads stage names in any case, so --build-target NON-ROOT is non-root:
# lower-cased once, here, so every check below and the image tag see that name.
TARGET_STAGE="$(printf '%s' "${TARGET_STAGE}" | tr '[:upper:]' '[:lower:]')"

export ASH_IMAGE_NAME=${ASH_IMAGE_NAME:-"automated-security-helper:${TARGET_STAGE}"}

# Default to the pwd
if [ "${SOURCE_DIR}" = "" ]; then
  SOURCE_DIR="$(pwd)"
fi

# Resolve the absolute paths. `--` before each path, so one starting with `-` is not
# read as options; and a directory that cannot be entered ends the run, as the
# Python CLI does, rather than leaving the working directory in its place.
if ! resolved="$(cd -- "${SOURCE_DIR}" && pwd)"; then
  echo "ERROR: Source directory does not exist: '${SOURCE_DIR}'. Check --source-dir." >&2
  exit 1
fi
SOURCE_DIR="${resolved}"
if ! resolved="$(mkdir -p -- "${OUTPUT_DIR}" && cd -- "${OUTPUT_DIR}" && pwd)"; then
  echo "ERROR: Output directory cannot be created: '${OUTPUT_DIR}'. Check --output-dir." >&2
  exit 1
fi
OUTPUT_DIR="${resolved}"

# --mount reads its value as comma-separated fields, so a comma in a host path starts
# a field of its own (a,b), a double quote starts CSV quoting, and a line
# break ends the argument. A path holding one is refused before anything is built or
# run, with exit 3.
require_mountable() {
  case "$2" in
    *,* | *\"* | *$'\n'* | *$'\r'*)
      echo "ERROR: The $1 '$2' cannot be handed to the container runner: --mount reads its value as comma-separated fields, so a path holding a comma, a double quote or a line break would be read as something else. Rename it, or choose another path." >&2
      exit 3
      ;;
  esac
}
if [[ "${NO_RUN}" = "NO" ]]; then
  require_mountable "source directory" "${SOURCE_DIR}"
  require_mountable "output directory" "${OUTPUT_DIR}"
fi

# The file's path with every symlink followed: the link's target is what is read.
resolve_file() {
  local path="$1" target dir
  while [ -L "${path}" ]; do
    target="$(readlink -- "${path}")"
    case "${target}" in
      /*) path="${target}" ;;
      *) path="$(dirname -- "${path}")/${target}" ;;
    esac
  done
  dir="$(cd -- "$(dirname -- "${path}")" && pwd -P)" || return 1
  printf '%s/%s\n' "${dir}" "$(basename -- "${path}")"
}

# The config file, --config or else ASH_CONFIG, is read by the scan inside the
# container, which sees the host only through its mounts: the host path itself
# names nothing there. A config inside the source dir is read through the
# read-only /src mount, with every extends base it can name; one outside it is
# mounted read-only on its own at /ash-config. Refused before any build when it
# is not an existing file, with exit 3 as for any unusable config.
CONFIG_RUN_ARGS=()
CONFIG_ASH_ARGS=()
if [[ "${CONFIG_GIVEN}" = "NO" ]]; then
  CONFIG_PATH="${ASH_CONFIG:-}"
fi
if [[ "${NO_RUN}" = "NO" && ( "${CONFIG_GIVEN}" = "YES" || -n "${CONFIG_PATH}" ) ]]; then
  if [[ -z "${CONFIG_PATH}" || ! -f "${CONFIG_PATH}" ]]; then
    echo "ERROR: Config file not found: ${CONFIG_PATH}. --config (or ASH_CONFIG) has to name an existing file: it is mounted read-only for the scan inside the container." >&2
    exit 3
  fi
  # The runner mounts with its own rights, which can be wider than this user's.
  if [[ ! -r "${CONFIG_PATH}" ]]; then
    echo "ERROR: Config file cannot be read: ${CONFIG_PATH}. ASH does not hand the container runner a file it cannot read itself." >&2
    exit 3
  fi
  CONFIG_REAL="$(resolve_file "${CONFIG_PATH}")"
  CONFIG_NAMED="$(cd -- "$(dirname -- "${CONFIG_PATH}")" && pwd -L)/$(basename -- "${CONFIG_PATH}")"
  require_mountable "config file" "${CONFIG_REAL}"
  SOURCE_REAL="$(cd -- "${SOURCE_DIR}" && pwd -P)"
  # The scanned tree, as a local scan defines it: the outermost directory at or
  # above the source dir holding a .git entry, under its logical and physical names.
  TREES=()
  for start in "${SOURCE_DIR}" "${SOURCE_REAL}"; do
    dir="${start}"
    checkout="${start}"
    while :; do
      if [ -e "${dir}/.git" ]; then checkout="${dir}"; fi
      if [ "${dir}" = "/" ] || [ -z "${dir}" ]; then break; fi
      dir="$(dirname -- "${dir}")"
    done
    TREES+=("${checkout}" "$(cd -- "${checkout}" && pwd -P)")
  done
  named_in_tree="NO"
  real_in_tree="NO"
  for tree in "${TREES[@]}"; do
    case "${CONFIG_NAMED}" in "${tree%/}"/*) named_in_tree="YES" ;; esac
    case "${CONFIG_REAL}" in "${tree%/}"/*) real_in_tree="YES" ;; esac
  done
  # A config named inside the tree is mounted only when its real path, every link
  # on the way resolved, is inside the tree too; otherwise the run is refused.
  if [[ "${named_in_tree}" = "YES" && "${real_in_tree}" = "NO" ]]; then
    echo "ERROR: The config file '${CONFIG_PATH}' is inside the scanned tree but is a link, or is reached through one, to '${CONFIG_REAL}', which is outside it. ASH does not mount a file the repository being scanned points it at." >&2
    exit 3
  fi
  case "${CONFIG_REAL}" in
    "${SOURCE_REAL%/}"/*)
      CONFIG_ASH_ARGS=(--config "/src/${CONFIG_REAL#"${SOURCE_REAL%/}"/}")
      ;;
    *)
      # Mounted on its own, without the files it extends, so a config with an
      # extends entry would not resolve inside the container. Refused, as is every
      # chain `ash --mode container` cannot mount whole.
      if grep -Eq '(^|[{,])[[:space:]]*["'"'"']?extends["'"'"']?[[:space:]]*:' -- "${CONFIG_REAL}"; then
        echo "ERROR: The config file '${CONFIG_PATH}' is outside the source directory and has an extends entry. ./ash mounts such a config on its own, without the files it extends. Run ash --mode container, which mounts the chain, or put the config inside the source directory." >&2
        exit 3
      fi
      CONFIG_RUN_ARGS=(--mount "type=bind,source=${CONFIG_REAL},destination=/ash-config/$(basename -- "${CONFIG_REAL}"),readonly")
      CONFIG_ASH_ARGS=(--config "/ash-config/$(basename -- "${CONFIG_REAL}")")
      # A config elsewhere in the scanned tree, or inside any other git checkout
      # by its named or real path, is one a local scan counts as repository-written
      # (config/sandbox_grants.repository_written). The scan inside sees it only at
      # /ash-config, outside its own tree, so it is told.
      in_checkout="NO"
      for start in "$(dirname -- "${CONFIG_NAMED}")" "$(dirname -- "${CONFIG_REAL}")"; do
        dir="${start}"
        while :; do
          if [ -e "${dir}/.git" ]; then in_checkout="YES"; break; fi
          if [ "${dir}" = "/" ] || [ -z "${dir}" ]; then break; fi
          dir="$(dirname -- "${dir}")"
        done
      done
      if [[ "${real_in_tree}" = "YES" || "${in_checkout}" = "YES" ]]; then
        CONFIG_ASH_ARGS+=(--config-from-scanned-repository)
      fi
      ;;
  esac
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
    echo "ERROR: Container ${id_flag} must be a numeric value: '${!id_value}'." >&2
    exit 1
  fi
done

# The non-root stage creates its user with `adduser --uid <UID> --gid <GID>`. UID 0 is
# root, which already exists: that build fails at that step, after the whole core stage
# has been built. GID 0 is root's group, which would give the unprivileged user root's
# group rights over the image. Either is refused before building, as `ash build-image`
# does. Any spelling of zero counts, since the build reads UID=00 as 0 too.
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
    echo "ERROR: The non-root image stage creates a user with UID 0, which is root: ASH is running as root, or --container-uid 0 was given. Pass --build-target ci to build the image that runs as root, or --container-uid and --container-gid with the IDs the non-root user should have." >&2
    exit 1
  fi
  if [[ "${BUILD_GID}" =~ ^0+$ ]]; then
    echo "ERROR: The non-root image stage gives its user GID 0, which is root's group: ASH is running with GID 0, or --container-gid 0 was given. Pass --build-target ci to build the image that runs as root, or --container-gid with the GID the non-root user should have." >&2
    exit 1
  fi
fi

# Resolve any offline mode flags
if [[ "${OFFLINE}" == "YES" ]]; then
  DOCKER_RUN_EXTRA_ARGS="${DOCKER_RUN_EXTRA_ARGS} --network=none"
fi

# Resolve the OCI_RUNNER
RESOLVED_OCI_RUNNER=${OCI_RUNNER:-$(command -v finch || command -v docker || command -v nerdctl || command -v podman)}
# The runtime's own name, before any wrapper is prefixed, for the few decisions that differ by
# runtime.
OCI_RUNNER_NAME="$(basename -- "${RESOLVED_OCI_RUNNER:-none}")"
# OCI_RUNNER_WRAPPER prefixes all OCI commands (like RUSTC_WRAPPER for cargo)
# Example: OCI_RUNNER_WRAPPER=sudo makes all finch/docker calls use sudo
if [[ -n "${OCI_RUNNER_WRAPPER:-}" ]]; then
    RESOLVED_OCI_RUNNER="${OCI_RUNNER_WRAPPER} ${RESOLVED_OCI_RUNNER}"
fi

# If we couldn't resolve an OCI_RUNNER, exit
if [[ "${RESOLVED_OCI_RUNNER}" == "" ]]; then
    echo "Unable to resolve an OCI_RUNNER -- exiting"
    exit 1
# else, build and run the image
else
    if [[ "${DEBUG}" = "YES" ]]; then
      set -x
    fi
    echo "Resolved OCI_RUNNER to: ${RESOLVED_OCI_RUNNER}"

    # Build the image if the --no-build flag is not set
    if [ "${NO_BUILD}" = "NO" ]; then
      CONTAINER_UID_OPTION=""
      CONTAINER_GID_OPTION=""
      if [[ ${CONTAINER_UID_SPECIFIED} = "YES" ]]; then
        CONTAINER_UID_OPTION="--build-arg UID=${CONTAINER_UID}" # set the UID build-arg if --container-uid is specified
      elif [[ "${HOST_UID}" != "" ]]; then
        CONTAINER_UID_OPTION="--build-arg UID=${HOST_UID}" # set the UID build-arg to the caller's UID if --container-uid is not specified
      fi
      if [[ ${CONTAINER_GID_SPECIFIED} = "YES" ]]; then
        CONTAINER_GID_OPTION="--build-arg GID=${CONTAINER_GID}" # set the GID build-arg if --container-gid is specified
      elif [[ "${HOST_GID}" != "" ]]; then
        CONTAINER_GID_OPTION="--build-arg GID=${HOST_GID}" # set the GID build-arg to the caller's GID if --container-uid is not specified
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
      # above: these expand to nothing when unset, and an image reference contains no
      # whitespace.
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
      BASE_IMAGE_OPTION=""
      if [[ -n "${ASH_BASE_OCI_LAYOUT:-}" ]]; then
        if [[ ! "${ASH_BASE_OCI_LAYOUT}" =~ ^(.+)@(sha256:[0-9a-f]{64})$ ]]; then
          echo "ERROR: ASH_BASE_OCI_LAYOUT is '${ASH_BASE_OCI_LAYOUT}', which is not <layout dir>@sha256:<64 hex>. Unset it to build from the Dockerfile's own base image reference." >&2
          exit 1
        fi
        case "${OCI_RUNNER_NAME}" in
          nerdctl | finch)
            BASE_IMAGE_OPTION="--build-context ash-base-image=oci-layout://${BASH_REMATCH[1]} --build-arg BASE_IMAGE=ash-base-image --pull=false"
            echo "Base image taken from the verified OCI layout named by ASH_BASE_OCI_LAYOUT, with no registry call."
            ;;
          *)
            echo "Base image expected in ${OCI_RUNNER_NAME}'s local store, placed there from the verified OCI layout named by ASH_BASE_OCI_LAYOUT."
            ;;
        esac
      elif [[ -n "${ASH_BASE_IMAGE_OVERRIDE:-}" ]]; then
        BASE_IMAGE_OPTION="--build-arg BASE_IMAGE=${ASH_BASE_IMAGE_OVERRIDE}"
        echo "Base image redirected to ${ASH_BASE_IMAGE_OVERRIDE} by ASH_BASE_IMAGE_OVERRIDE."
      fi
      echo "Building image ${ASH_IMAGE_NAME} -- this may take a few minutes during the first build..."
      ${RESOLVED_OCI_RUNNER} build \
        ${CONTAINER_UID_OPTION} \
        ${CONTAINER_GID_OPTION} \
        ${BASE_IMAGE_OPTION} \
        --tag ${ASH_IMAGE_NAME} \
        --target ${TARGET_STAGE} \
        --file "${ASH_ROOT_DIR}/Dockerfile" \
        --build-arg OFFLINE="${OFFLINE}" \
        --build-arg INSTALL_ASH_REVISION="${INSTALL_ASH_REVISION}" \
        --build-arg OFFLINE_SEMGREP_RULESETS="${OFFLINE_SEMGREP_RULESETS}" \
        --build-arg BUILD_DATE="$(date +%s)" \
        ${DOCKER_EXTRA_ARGS} \
        "${ASH_ROOT_DIR}"
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
        echo "ERROR: failed to build image ${ASH_IMAGE_NAME} (exit ${BUILD_RC}). See the build output above for the failing step." >&2
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
      echo "Running ASH scan using built image..."
      ${RESOLVED_OCI_RUNNER} run \
          --rm \
          -e "ASH_ACTUAL_SOURCE_DIR=${SOURCE_DIR}" \
          -e "ASH_ACTUAL_OUTPUT_DIR=${OUTPUT_DIR}" \
          -e "ASH_DEBUG=${DEBUG}" \
          -e "ASH_OUTPUT_FORMAT=${OUTPUT_FORMAT}" \
          --mount source="${SOURCE_DIR}",type=bind,destination=/src,readonly \
          --mount source="${OUTPUT_DIR}",type=bind,destination=/out \
          "${CONFIG_RUN_ARGS[@]}" \
          ${MOUNT_OUTPUT_DIR} \
          ${DOCKER_RUN_EXTRA_ARGS} \
          ${ASH_IMAGE_NAME} \
            ash \
              --source-dir /src \
              --output-dir /out \
              "${CONFIG_ASH_ARGS[@]}" \
              $ASH_ARGS
      RC=$?
    fi
    if [[ "${DEBUG}" = "YES" ]]; then
      set +x
    fi
    exit ${RC}
fi
