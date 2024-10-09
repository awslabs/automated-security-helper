#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Resolve the absolute path of the parent of the script directory (ASH repo root)
export ASH_ROOT_DIR="$(cd "$(dirname "$0")"; pwd)"
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"
export ASH_IMAGE_NAME=${ASH_IMAGE_NAME:-"automated-security-helper:local"}

# Set local variables
SOURCE_DIR=""
OUTPUT_DIR=""
OUTPUT_DIR_SPECIFIED="NO"
OUTPUT_FORMAT="text"
DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS:-}"
DOCKER_RUN_EXTRA_ARGS=""
ASH_ARGS=""
NO_BUILD="NO"
NO_RUN="NO"
DEBUG="NO"
OFFLINE="NO"
OFFLINE_SEMGREP_RULESETS="p/ci"

# self signed certificate variable
CERT_FILE=""

# Parse arguments
while (("$#")); do
  case $1 in
    --source-dir)
      shift
      SOURCE_DIR="$1"
      ;;
    --cert-file)
      shift
      mkdir -p $ASH_ROOT_DIR/certs
      inp_cert_file="$1"
      inp_cert_file_ext=${inp_cert_file##*.}
      inp_cert_file_basename=$(basename $inp_cert_file $inp_cert_file_ext)
      cert_file_new_name="${inp_cert_file_basename}crt"
      cp $1 $ASH_ROOT_DIR/certs/$cert_file_new_name
      CERT_FILE="certs/$cert_file_new_name"
      ;;
    --output-dir)
      shift
      OUTPUT_DIR="$1"
      OUTPUT_DIR_SPECIFIED="YES"
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
    --no-build)
      NO_BUILD="YES"
      ;;
    --no-run)
      NO_RUN="YES"
      ;;
    --debug)
      DEBUG="YES"
      ;;
    --format)
      shift
      OUTPUT_FORMAT="$1"
      ;;
    --help | -h)
      source "${ASH_ROOT_DIR}/ash-multi" --help
      exit 0
      ;;
    --version | -v)
      source "${ASH_ROOT_DIR}/ash-multi" --version
      exit 0
      ;;
    --finch|-f)
      # Show colored deprecation warning from entrypoint script and exit 1
      source "${ASH_ROOT_DIR}/ash-multi" --finch
      exit 1
      ;;
    *)
      ASH_ARGS="${ASH_ARGS} $1"
  esac
  shift
done

# Default to the pwd
if [ "${SOURCE_DIR}" = "" ]; then
  SOURCE_DIR="$(pwd)"
fi

# Resolve the absolute paths
SOURCE_DIR="$(cd "$SOURCE_DIR"; pwd)"
if [[ "${OUTPUT_DIR_SPECIFIED}" == "YES" ]]; then
  mkdir -p "${OUTPUT_DIR}"
  OUTPUT_DIR="$(cd "$OUTPUT_DIR"; pwd)"
fi

# Resolve any offline mode flags
if [[ "${OFFLINE}" == "YES" ]]; then
  DOCKER_RUN_EXTRA_ARGS="${DOCKER_RUN_EXTRA_ARGS} --network=none"
fi

# Resolve the OCI_RUNNER
RESOLVED_OCI_RUNNER=${OCI_RUNNER:-$(command -v finch || command -v docker || command -v nerdctl || command -v podman)}

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
      echo "Building image ${ASH_IMAGE_NAME} -- this may take a few minutes during the first build..."
      ${RESOLVED_OCI_RUNNER} build \
        --tag ${ASH_IMAGE_NAME} \
        --file "${ASH_ROOT_DIR}/Dockerfile" \
        --build-arg OFFLINE="${OFFLINE}" \
        --build-arg OFFLINE_SEMGREP_RULESETS="${OFFLINE_SEMGREP_RULESETS}" \
        --build-arg CERT_FILE="${CERT_FILE}" \
        --progress=plain --no-cache \
        ${DOCKER_EXTRA_ARGS} \
        "${ASH_ROOT_DIR}"
      eval $build_cmd
    fi

    # Run the image if the --no-run flag is not set
    RC=0
    if [ "${NO_RUN}" = "NO" ]; then
      MOUNT_SOURCE_DIR="--mount type=bind,source=${SOURCE_DIR},destination=/src"
      MOUNT_OUTPUT_DIR=""
      OUTPUT_DIR_OPTION=""
      if [[ ${OUTPUT_DIR_SPECIFIED} = "YES" ]]; then
        MOUNT_SOURCE_DIR="${MOUNT_SOURCE_DIR},readonly" # add readonly source mount when --output-dir is specified
        MOUNT_OUTPUT_DIR="--mount type=bind,source=${OUTPUT_DIR},destination=/out"
        OUTPUT_DIR_OPTION="--output-dir /out"
      fi
      echo "Running ASH scan using built image..."
      eval ${RESOLVED_OCI_RUNNER} run \
          --rm \
          -e ACTUAL_SOURCE_DIR="${SOURCE_DIR}" \
          -e ASH_DEBUG=${DEBUG} \
          -e ASH_OUTPUT_FORMAT=${OUTPUT_FORMAT} \
          ${MOUNT_SOURCE_DIR} \
          ${MOUNT_OUTPUT_DIR} \
          ${DOCKER_RUN_EXTRA_ARGS} \
          ${ASH_IMAGE_NAME} \
            ash \
              --source-dir /src  \
              ${OUTPUT_DIR_OPTION}  \
              $ASH_ARGS
      RC=$?
    fi
    if [[ "${DEBUG}" = "YES" ]]; then
      set +x
    fi
    exit ${RC}
fi
