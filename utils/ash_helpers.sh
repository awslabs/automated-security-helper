#!/bin/sh

#################################################################################
###                 ~~ ASH HELPERS ~~
### This script should be sourced in your shell profile:
###
### $ echo ". '${ASH_HELPERS_SCRIPT}'" >> ~/.bashrc
#################################################################################

# Resolve the absolute path of the parent of the script directory (ASH repo root)
export ASH_ROOT_DIR="$(cd $(dirname "$(dirname "$0")"); pwd)"
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"
export ASH_HELPERS_SCRIPT="${ASH_UTILS_DIR}/ash_helpers.sh"
export ASH_IMAGE_NAME=${ASH_IMAGE_NAME:-"automated-security-helper:local"}

# Function to invoke ash CLI in single container executable form
invoke-ash() {
  # Set local variables
  local SOURCE_DIR=""
  local OUTPUT_DIR=""
  local OCI_RUNNER=""
  local DOCKER_EXTRA_ARGS=""
  local ASH_ARGS=""
  local NO_BUILD="NO"
  local NO_RUN="NO"
  # Parse arguments
  while (("$#")); do
    case $1 in
      --source-dir)
        shift
        local SOURCE_DIR="$1"
        ;;
      --output-dir)
        shift
        local OUTPUT_DIR="$1"
        ;;
      --force)
        local DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} --no-cache"
        ;;
      --quiet | -q)
        local DOCKER_EXTRA_ARGS="${DOCKER_EXTRA_ARGS} -q"
        ASH_ARGS="${ASH_ARGS} --quiet"
        ;;
      --oci-runner | -o)
        shift
        local OCI_RUNNER="$1"
        ;;
      --no-build)
        local NO_BUILD="YES"
        ;;
      --no-run)
        local NO_RUN="YES"
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
    OUTPUT_DIR="$(pwd)/ash_output"
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
  local RESOLVED_OCI_RUNNER=${OCI_RUNNER:-$(command -v docker || command -v finch || command -v nerdctl || command -v podman)}

  # If we couldn't resolve an OCI_RUNNER, exit
  if [[ "${RESOLVED_OCI_RUNNER}" == "" ]]; then
      echo "Unable to resolve an OCI_RUNNER -- exiting"
      exit 1
  # else, build and run the image
  else
      echo "Resolved OCI_RUNNER to: ${RESOLVED_OCI_RUNNER}"

      # Build the image if the --no-build flag is not set
      if [ "${NO_BUILD}" = "NO" ]; then
        build_cmd="${RESOLVED_OCI_RUNNER} build --tag ${ASH_IMAGE_NAME} --file \"${ASH_ROOT_DIR}/Dockerfile\"${DOCKER_EXTRA_ARGS} \"${ASH_ROOT_DIR}\""
        echo $build_cmd
        eval $build_cmd
      fi

      # Run the image if the --no-run flag is not set
      if [ "${NO_RUN}" = "NO" ]; then
        run_cmd="${RESOLVED_OCI_RUNNER} run --rm --interactive --tty --mount type=bind,source=\"${SOURCE_DIR}\",destination=/src,readonly --mount type=bind,source=\"${OUTPUT_DIR}\",destination=/out ${ASH_IMAGE_NAME} ash --source-dir /src --output-dir /out $ASH_ARGS"
        echo $run_cmd
        eval $run_cmd
      fi
  fi
}
