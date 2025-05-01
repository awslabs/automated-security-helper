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

# Function to invoke ash CLI in single container executable form
invoke-ash() {
  $ASH_ROOT_DIR/ash "$@"
}
