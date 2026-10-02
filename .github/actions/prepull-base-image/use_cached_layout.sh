#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The cache-hit half of .github/actions/prepull-base-image: verify the restored OCI layout,
# place it where this runtime's build will read it, and tell the build through GITHUB_ENV.
# The action's header explains the design and the per-runtime table; this file only carries it
# out.
#
# Inputs, all from the environment:
#   RUNTIME           docker, podman, finch or nerdctl; empty means docker
#   WRAPPER           command prefix for the runtime (sudo for finch and nerdctl)
#   DOCKERFILE        where ARG BASE_IMAGE and ARG BASE_IMAGE_DIGEST are read from
#   HELPER            path to oci_layout.py
#   LAYOUT_DIR        the restored layout
#   RUNNER_ARCH       set by Actions
#   BLOCK_REGISTRIES  "true" to make any later registry call for the base image fail
#
# Writes `used=true` to GITHUB_OUTPUT only when the build has been handed verified bytes. Every
# other outcome writes `used=false` and exits 0, so the action's pull step runs exactly as it
# did before the cache existed. The one exception is a registry block that was asked for and
# did not take effect: that exits 1, because a warm leg that goes green without the block is
# not the evidence it claims to be.

set -uo pipefail

runtime="${RUNTIME:-docker}"
# shellcheck disable=SC2206
wrapper=( ${WRAPPER:-} )
run_runtime() { "${wrapper[@]+"${wrapper[@]}"}" "${runtime}" "$@"; }

set_output() {
  if [ -n "${GITHUB_OUTPUT:-}" ]; then
    printf '%s\n' "$1" >> "${GITHUB_OUTPUT}"
  fi
}

# The entry failed verification: it is not used, and it is removed so nothing later in the job
# can read it by accident.
discard() {
  echo "::warning::discarding the cached base image: $1. Falling back to the registry pull."
  rm -rf "${LAYOUT_DIR}"
  set_output "used=false"
  exit 0
}

# The entry verified but could not be handed to this runtime. Left in place (it is sound), not
# exported, and the pull path runs.
not_used() {
  echo "::warning::the cached base image verified but was not used: $1. Falling back to the \
registry pull."
  set_output "used=false"
  exit 0
}

base="$(sed -n '/^ARG BASE_IMAGE=/{s/^ARG BASE_IMAGE=//;p;q;}' "${DOCKERFILE}")"
pin="$(sed -n '/^ARG BASE_IMAGE_DIGEST=/{s/^ARG BASE_IMAGE_DIGEST=//;p;q;}' "${DOCKERFILE}")"
if [ -z "${base}" ] || [ -z "${pin}" ]; then
  not_used "${DOCKERFILE} has no ARG BASE_IMAGE or ARG BASE_IMAGE_DIGEST line"
fi

# GITHUB_ENV is line-oriented, and this value goes into it. runner.temp never carries anything
# outside this set; if it ever did, refusing is cheaper than reasoning about what it injects.
case "${LAYOUT_DIR}" in
  '' | *[!a-zA-Z0-9._/-]*) not_used "the layout path '${LAYOUT_DIR}' has characters this step will not export" ;;
esac

verify_err="$(mktemp)"
if ! manifest="$(python3 "${HELPER}" verify --dir "${LAYOUT_DIR}" --pin "${pin}" \
    --arch "${RUNNER_ARCH}" 2> "${verify_err}")"; then
  discard "verification failed ($(tr '\n' ' ' < "${verify_err}"))"
fi
config="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["config"]["digest"])' \
  "${LAYOUT_DIR}/blobs/sha256/${manifest#sha256:}")"
echo "verified ${LAYOUT_DIR}: index ${pin}, ${RUNNER_ARCH} manifest ${manifest}, config ${config}"

# The local image id is the config digest on docker and on podman (podman prints it without the
# algorithm prefix), so it is compared against the one in the verified manifest: the tag the
# build resolves must hold exactly the verified bytes, whatever the load or import did.
same_id() {
  local id
  id="$(run_runtime image inspect --format '{{.Id}}' "${base}" 2>/dev/null)" || return 1
  id="${id%%$'\n'*}"
  [ "${id#sha256:}" = "${config#sha256:}" ]
}

case "${runtime}" in
  docker)
    # For `docker build` on the docker driver -- ash_helpers.ps1 -- which prefers a
    # local image and cannot take the oci-layout context. The buildx path gets the context and
    # does not need this, but loading costs seconds and keeps the two docker paths alike.
    if ! python3 "${HELPER}" docker-archive --dir "${LAYOUT_DIR}" --pin "${pin}" \
        --arch "${RUNNER_ARCH}" --tag "${base}" | run_runtime load; then
      not_used "docker load of the verified layout failed"
    fi
    same_id || not_used "after the load, ${base} is not image ${config}"
    ;;
  podman)
    # podman cannot take an oci-layout build context, so it gets the image in its own store,
    # through the `oci:` transport, under the reference FROM resolves. `index` is the
    # ref.name oci_layout.py gives the pinned index, so podman selects this platform out of
    # it exactly as a registry pull would.
    if ! id="$(run_runtime pull -q "oci:${LAYOUT_DIR}:index")"; then
      not_used "podman could not import the verified layout"
    fi
    id="${id##*$'\n'}"
    run_runtime tag "${id}" "${base}" || not_used "podman could not tag ${id} as ${base}"
    same_id || not_used "after the import, ${base} is not image ${config}"
    ;;
  nerdctl | finch)
    # Nothing to place. The build reads the layout through --build-context, and --pull=false
    # keeps it off the registry; see the entrypoints.
    ;;
  *)
    not_used "no cached-layout path is known for runtime '${runtime}'"
    ;;
esac

if [ -n "${GITHUB_ENV:-}" ]; then
  printf '%s\n' "ASH_BASE_OCI_LAYOUT=${LAYOUT_DIR}@${manifest}" >> "${GITHUB_ENV}"
fi
echo "::notice::the base image came from the Actions cache, verified against ${pin}; no \
registry was contacted for it. ASH_BASE_OCI_LAYOUT=${LAYOUT_DIR}@${manifest}"

# THE ZERO-CONTACT ASSERTION
#
# From here on in this job, the registries the base image could come from do not resolve. The
# host's /etc/hosts covers dockerd, podman, nerdctl's and finch's buildkitd, all of which run on
# the host; a buildx docker-container builder is a separate container with its own /etc/hosts,
# so that file is edited too. Both address families, because a resolver that finds a name in
# /etc/hosts does not go on to ask DNS for it.
if [ "${BLOCK_REGISTRIES:-false}" = "true" ]; then
  hosts=(public.ecr.aws registry-1.docker.io registry.docker.io index.docker.io docker.io
    auth.docker.io production.cloudflare.docker.com)
  block=""
  for host in "${hosts[@]}"; do
    block+="0.0.0.0 ${host}"$'\n'":: ${host}"$'\n'
  done
  if ! printf '%s' "${block}" | sudo tee -a /etc/hosts > /dev/null; then
    echo "::error::could not block the registry hosts in /etc/hosts"
    exit 1
  fi
  if command -v docker > /dev/null 2>&1; then
    for container in $(docker ps --filter "name=buildx_buildkit_" --format '{{.Names}}' 2>/dev/null); do
      if ! printf '%s' "${block}" | docker exec -i "${container}" sh -c 'cat >> /etc/hosts'; then
        echo "::error::could not block the registry hosts inside buildx builder ${container}"
        exit 1
      fi
      echo "blocked the registry hosts inside buildx builder ${container}"
    done
  fi
  resolved="$(getent hosts public.ecr.aws | awk '{print $1; exit}')"
  case "${resolved}" in
    0.0.0.0 | ::) ;;
    *)
      echo "::error::public.ecr.aws still resolves to '${resolved}' after the block; the \
zero-contact assertion would prove nothing"
      exit 1
      ;;
  esac
  echo "registry hosts blocked for the rest of this job: ${hosts[*]}"
  set_output "blocked=true"
fi

set_output "used=true"
