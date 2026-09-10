#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Installs nerdctl on Ubuntu Linux for CI environments.
#
# nerdctl is one of the four runners in _OCI_RUNNER_CANDIDATES
# (automated_security_helper/interactions/run_ash_container.py) and had no CI
# coverage at all, so this exists to give it some.
#
# WHY THE `nerdctl-full` BUNDLE RATHER THAN THE CLI ALONE
#
# The hosted runners already run the containerd that ships with Docker, so a
# CLI-only install would appear to be enough. It is not: `nerdctl build` needs
# buildkitd listening on a socket, which no runner image provides, so buildkit
# would have to be installed and version-matched separately. The `nerdctl-full`
# bundle carries nerdctl, containerd, buildkitd, runc and the CNI plugins that
# were built and tested together, which removes the version-skew question
# entirely. It costs a larger download and buys one self-consistent toolchain.
#
# WHY THE VERSION AND THE CHECKSUM ARE BOTH PINNED
#
# A pinned version alone still trusts whatever bytes the URL serves. The
# checksum below was taken from the release's own SHA256SUMS and then confirmed
# against the downloaded artifact, so a re-cut release fails here loudly rather
# than silently changing the toolchain under the gate.
#
# Usage: sudo bash scripts/setup-nerdctl-linux.sh

set -euo pipefail

NERDCTL_VERSION="2.3.5"
# sha256 of nerdctl-full-2.3.5-linux-amd64.tar.gz, from the release SHA256SUMS.
NERDCTL_SHA256_AMD64="b697295c623639734aaab737523c808fd3cc8d3046039fd94fff1744e4c317aa"

ARCH="$(dpkg --print-architecture)"
case "${ARCH}" in
    amd64) EXPECTED_SHA256="${NERDCTL_SHA256_AMD64}" ;;
    *)
        echo "ERROR: no pinned checksum for architecture '${ARCH}'." >&2
        echo "Only linux-amd64 is wired up here. containerd/nerdctl does publish a" >&2
        echo "linux-arm64 bundle, so extending this is a matter of pinning that" >&2
        echo "checksum beside the amd64 one and adding the matrix cell. Downloading" >&2
        echo "unverified bytes instead is not an acceptable substitute, so this" >&2
        echo "fails rather than falling back." >&2
        exit 1
        ;;
esac

TARBALL="nerdctl-full-${NERDCTL_VERSION}-linux-${ARCH}.tar.gz"
URL="https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VERSION}/${TARBALL}"

# Docker's containerd is the same unit name this bundle installs, so leaving
# Docker running means two things contending for one socket. nerdctl is the
# runtime under test in this job; nothing here needs Docker.
echo "=== Stopping Docker so it does not contend for containerd ==="
systemctl stop docker.socket docker.service 2>/dev/null || true

WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

echo "=== Downloading ${TARBALL} ==="
curl -fsSL --retry 3 --retry-delay 5 -o "${WORKDIR}/${TARBALL}" "${URL}"

echo "=== Verifying checksum ==="
echo "${EXPECTED_SHA256}  ${WORKDIR}/${TARBALL}" | sha256sum -c -

echo "=== Installing into /usr/local ==="
tar -C /usr/local -xzf "${WORKDIR}/${TARBALL}"

# nerdctl looks for CNI plugins in /opt/cni/bin before the bundle's own
# /usr/local/libexec/cni on some paths, and a container that cannot get a
# network interface fails at run time rather than at install time. Publishing
# them in both places costs nothing and removes the ordering question.
echo "=== Publishing CNI plugins to /opt/cni/bin ==="
mkdir -p /opt/cni/bin
cp -n /usr/local/libexec/cni/* /opt/cni/bin/ 2>/dev/null || true

# The bundle ships units at /usr/local/lib/systemd/system, which systemd loads
# ahead of /lib/systemd/system, so `containerd` now resolves to the bundle's
# copy running /usr/local/bin/containerd. restart rather than start, because the
# distro containerd.io unit is already running and holding the socket.
echo "=== Reloading systemd and starting containerd and buildkit ==="
systemctl daemon-reload
systemctl restart containerd
systemctl start buildkit

# Docker was stopped above, so if either unit is dead there is no runtime left to
# fall back on and the image build that follows blocks instead of failing.
# Confirm each unit is actually active, with a bound, and dump its logs if not.
echo "=== Waiting for containerd and buildkit to report active ==="
for unit in containerd buildkit; do
    for _ in $(seq 1 30); do
        if systemctl is-active --quiet "${unit}"; then break; fi
        sleep 2
    done
    if ! systemctl is-active --quiet "${unit}"; then
        echo "ERROR: ${unit} did not become active within 60s" >&2
        systemctl status "${unit}" --no-pager --lines=40 >&2 || true
        journalctl -u "${unit}" --no-pager --lines=60 >&2 || true
        exit 1
    fi
    echo "  ${unit}: active"
done

echo "=== Verifying nerdctl installation ==="
nerdctl --version

# `nerdctl --version` only proves the binary is on PATH; it passes even when
# containerd and buildkit are unreachable. Probe both daemons so a broken runtime
# surfaces here in under a minute rather than wedging `ash build-image` until the
# job timeout. Both probes are bounded, so this step can never be the thing that
# hangs.
echo "=== Verifying the containerd daemon responds ==="
if ! timeout 60 sh -c 'nerdctl info >/dev/null 2>&1 || nerdctl images >/dev/null 2>&1'; then
    echo "ERROR: nerdctl did not answer a daemon query within 60s." >&2
    echo "containerd is installed but not usable; refusing to continue." >&2
    systemctl status containerd buildkit --no-pager --lines=40 >&2 || true
    journalctl -u containerd --no-pager --lines=60 >&2 || true
    exit 1
fi

# buildkit answers a different socket from containerd, and `ash build-image` is
# the first thing that needs it. A build is where an unreachable buildkitd would
# otherwise hang, so it is probed separately rather than assumed from the above.
echo "=== Verifying the buildkit daemon responds ==="
if ! timeout 60 buildctl debug workers >/dev/null 2>&1; then
    echo "ERROR: buildkitd did not answer within 60s." >&2
    echo "nerdctl can talk to containerd but cannot build; refusing to continue." >&2
    systemctl status buildkit --no-pager --lines=40 >&2 || true
    journalctl -u buildkit --no-pager --lines=60 >&2 || true
    exit 1
fi

echo "=== nerdctl setup complete ==="
