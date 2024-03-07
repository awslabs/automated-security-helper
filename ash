#!/bin/bash

# Resolve the absolute path of the parent of the script directory (ASH repo root)
export ASH_ROOT_DIR="$(cd "$(dirname "$0")"; pwd)"
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"
export ASH_IMAGE_NAME=${ASH_IMAGE_NAME:-"automated-security-helper:local"}

# Set local variables
SOURCE_DIR=""
OUTPUT_DIR=""
OCI_RUNNER=""
DOCKER_EXTRA_ARGS=""
ASH_ARGS=""
NO_BUILD="NO"
NO_RUN="NO"
DEBUG="NO"
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
    --help | -h)
      source "${ASH_ROOT_DIR}/ash-multi" --help
      exit 0
      ;;
    --version | -v)
      source "${ASH_ROOT_DIR}/ash-multi" --version
      exit 0
      ;;
    --finch | -f)
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

# Default to the pwd/ash_output
if [ "${OUTPUT_DIR}" = "" ]; then
  OUTPUT_DIR="${SOURCE_DIR}/ash_output"
fi

# Create the output directory if it doesn't exist, otherwise the bind mount of the
# OUTPUT_DIR will fail.
if [ ! -d "${OUTPUT_DIR}" ]; then
  mkdir -p "${OUTPUT_DIR}"
fi

# Resolve the absolute paths
SOURCE_DIR="$(cd "$SOURCE_DIR"; pwd)"
OUTPUT_DIR="$(cd "$OUTPUT_DIR"; pwd)"

# Resolve the OCI_RUNNER
RESOLVED_OCI_RUNNER=${OCI_RUNNER:-$(command -v finch || command -v docker || command -v nerdctl || command -v podman)}

# If we couldn't resolve an OCI_RUNNER, exit
if [[ "${RESOLVED_OCI_RUNNER}" == "" ]]; then
    echo "Unable to resolve an OCI_RUNNER -- exiting"
    exit 1
# else, build and run the image
else
    if [ "${DEBUG}" = "YES" ]; then
      set -x
    fi
    echo "Resolved OCI_RUNNER to: ${RESOLVED_OCI_RUNNER}"

    # Build the image if the --no-build flag is not set
    if [ "${NO_BUILD}" = "NO" ]; then
      echo "Building image ${ASH_IMAGE_NAME} -- this may take a few minutes during the first build..."
      ${RESOLVED_OCI_RUNNER} build \
        --tag ${ASH_IMAGE_NAME} \
        --file "${ASH_ROOT_DIR}/Dockerfile" \
        ${DOCKER_EXTRA_ARGS} \
        "${ASH_ROOT_DIR}"
      eval $build_cmd
    fi

    # Run the image if the --no-run flag is not set
    if [ "${NO_RUN}" = "NO" ]; then
      echo "Running ASH scan using built image..."
      ${RESOLVED_OCI_RUNNER} run \
        --rm \
        -e ACTUAL_SOURCE_DIR=${SOURCE_DIR} \
        -e ACTUAL_OUTPUT_DIR=${OUTPUT_DIR} \
        --mount type=bind,source="${SOURCE_DIR}",destination=/src,readonly \
        --mount type=bind,source="${OUTPUT_DIR}",destination=/out \
        --tmpfs /run/scan/src:rw,noexec,nosuid ${ASH_IMAGE_NAME} \
          ash \
            --source-dir /src  \
            --output-dir /out  \
            $ASH_ARGS
    fi
    if [ "${DEBUG}" = "YES" ]; then
      set +x
    fi
fi
