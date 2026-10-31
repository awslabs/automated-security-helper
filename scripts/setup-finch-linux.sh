#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Installs Finch on Ubuntu 24.04 (noble) for CI environments.
# Checks that a Finch package is available for this host first, then removes
# Docker Engine (it conflicts with Finch's containerd dependency), installs
# Finch from the official APT repo, starts the units and probes the daemon and
# the builder. The workflow that calls this runs finch through `sudo` itself
# (OCI_RUNNER_WRAPPER); no wrapper is created here.
#
# This script is destructive to the host it runs on: it removes the Docker
# packages and the Docker client configuration under /root and /home/runner,
# registry credentials included. It is written for a throwaway CI runner.
#
# Usage: sudo bash scripts/setup-finch-linux.sh

set -euo pipefail

# Keep apt from ever opening a config prompt. DEBIAN_FRONTEND covers debconf;
# dpkg's own conffile question is a separate prompt, which the --force-confold
# option below answers by keeping the installed file.
export DEBIAN_FRONTEND=noninteractive
APT_INSTALL=(apt-get install -y -o Dpkg::Options::=--force-confold)

ARCH=$(dpkg --print-architecture)
KEYRING=/usr/share/keyrings/runfinch-finch-archive-keyring.gpg
SOURCES=/etc/apt/sources.list.d/runfinch-finch.list

# The APT source names the noble suite, so refuse any other release before
# anything is removed: noble packages on another Ubuntu are not what Finch
# publishes for it.
CODENAME=$(. /etc/os-release && echo "${VERSION_CODENAME:-}")
if [ "${CODENAME}" != "noble" ]; then
    echo "ERROR: this script installs Finch's noble packages; this host is Ubuntu '${CODENAME:-unknown}'." >&2
    echo "Nothing was changed." >&2
    exit 1
fi

echo "=== WARNING: this removes Docker Engine and the Docker client configuration ==="
echo "Packages: docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"
echo "Directories: /root/.docker /home/runner/.docker (stored registry credentials included)"

echo "=== Adding Finch APT repository ==="
# --yes lets gpg overwrite the keyring on a re-run; without it gpg asks, and
# with no tty aborts. The key is fetched from the same origin as the packages,
# so the signed-by check anchors the packages to that origin and nothing more.
curl -fsSL https://artifact.runfinch.com/deb/GPG_KEY.pub | gpg --dearmor --batch --yes -o "${KEYRING}"
echo "deb [signed-by=${KEYRING} arch=${ARCH}] https://artifact.runfinch.com/deb noble main" | tee "${SOURCES}"
apt-get update -q

# Download Finch before Docker is removed. A host with no Finch package for its
# architecture, or a repository that cannot be reached, fails here while Docker
# is still installed, instead of after the only container runtime is gone.
echo "=== Fetching the Finch package (Docker is still installed) ==="
"${APT_INSTALL[@]}" --download-only runfinch-finch

echo "=== Removing Docker Engine (conflicts with Finch containerd) ==="
# Only the packages that are installed: under set -e, `apt-get remove` of a
# name apt does not know exits non-zero and aborted the script before the Finch
# install on any image missing one of the five.
DOCKER_PACKAGES=()
for pkg in docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; do
    if dpkg-query -W -f='${db:Status-Status}' "${pkg}" 2>/dev/null | grep -qx installed; then
        DOCKER_PACKAGES+=("${pkg}")
    fi
done
if [ "${#DOCKER_PACKAGES[@]}" -gt 0 ]; then
    # purge, not remove: a removed package's conffiles stay behind for the next
    # install of containerd to collide with. No `autoremove`: that removes every
    # auto-installed package nothing depends on, not only Docker's.
    apt-get purge -y "${DOCKER_PACKAGES[@]}"
else
    echo "  no Docker packages installed"
fi
rm -rf /root/.docker /home/runner/.docker

echo "=== Installing Finch ==="
"${APT_INSTALL[@]}" runfinch-finch

echo "=== Starting Finch services ==="
# A failed start is reported by the wait below, with the unit's status and
# journal; under set -e a non-zero `systemctl start` used to exit here, before
# that diagnostic ran.
for unit in containerd finch-buildkit finch; do
    systemctl start "${unit}" || echo "WARNING: systemctl start ${unit} failed; its state is checked below" >&2
done

# Docker was removed above, so if any of these units is dead there is no runtime
# left to fall back on and the image build that follows blocks instead of
# failing. Confirm each unit is actually active, with a bound, and dump its logs
# if not.
echo "=== Waiting for Finch services to report active ==="
for unit in containerd finch-buildkit finch; do
    for _ in $(seq 1 30); do
        if systemctl is-active --quiet "$unit"; then break; fi
        sleep 2
    done
    if ! systemctl is-active --quiet "$unit"; then
        echo "ERROR: ${unit} did not become active within 60s" >&2
        systemctl status "$unit" --no-pager --lines=40 >&2 || true
        journalctl -u "$unit" --no-pager --lines=60 >&2 || true
        exit 1
    fi
    echo "  ${unit}: active"
done

echo "=== Verifying Finch installation ==="
finch --version

# `finch --version` only proves the binary is on PATH; it passes even when
# buildkit and containerd are unreachable. Probe the daemon so a broken runtime
# surfaces here in under a minute rather than wedging `ash build-image` until the
# job timeout. Both probes are bounded, so this step can never be the thing that
# hangs.
echo "=== Verifying the Finch daemon responds ==="
if ! timeout 60 sh -c 'finch info >/dev/null 2>&1 || finch images >/dev/null 2>&1'; then
    echo "ERROR: Finch did not answer a daemon query within 60s." >&2
    echo "containerd is installed but not usable; refusing to continue." >&2
    systemctl status containerd finch-buildkit finch --no-pager --lines=40 >&2 || true
    journalctl -u finch-buildkit --no-pager --lines=60 >&2 || true
    exit 1
fi

# `finch info` reaches containerd only. The builder is what `ash build-image`
# needs, so build the smallest possible image: FROM scratch pulls nothing and
# exercises finch-buildkit end to end.
echo "=== Verifying the Finch builder responds ==="
PROBE_DIR=$(mktemp -d /tmp/finch-probe.XXXXXX)
printf 'FROM scratch\nLABEL ash.finch.probe=1\n' > "${PROBE_DIR}/Dockerfile"
if ! timeout 120 finch build --quiet -t ash-finch-probe:latest "${PROBE_DIR}" >/dev/null 2>&1; then
    echo "ERROR: finch-buildkit did not complete a FROM scratch build within 120s." >&2
    echo "buildkit is installed but not usable; refusing to continue." >&2
    systemctl status finch-buildkit --no-pager --lines=40 >&2 || true
    journalctl -u finch-buildkit --no-pager --lines=60 >&2 || true
    rm -rf "${PROBE_DIR:?}"
    exit 1
fi
finch rmi ash-finch-probe:latest >/dev/null 2>&1 || true
rm -rf "${PROBE_DIR:?}"

echo "=== Finch setup complete ==="
