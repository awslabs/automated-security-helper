#!/bin/sh

#################################################################################
###                 ~~ ASH HELPERS ~~
### This script should be sourced in your shell profile:
###
### $ echo "source '${ASH_HELPERS_SCRIPT}'" >> ~/.bashrc
#################################################################################

# Resolve the absolute path of the parent of the script directory (ASH repo root)
export ASH_ROOT_DIR="$(cd $(dirname "$(dirname "$0")"); pwd)"
export ASH_UTILS_DIR="${ASH_ROOT_DIR}/utils"
export ASH_HELPERS_SCRIPT="${ASH_UTILS_DIR}/ash_helpers.sh"

# Function to invoke ash CLI in single container executable form.
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
invoke-ash() {
  ash --mode container "$@"
}
