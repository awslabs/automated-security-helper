#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Installs Finch on Ubuntu Linux for CI environments.
# Removes Docker Engine (conflicts with Finch's containerd dependency),
# installs Finch from the official APT repo, starts required services,
# and creates a sudo wrapper so ASH can invoke finch without running
# the entire process as root.
#
# Usage: sudo bash scripts/setup-finch-linux.sh

set -euo pipefail

# Keep apt from ever opening a config prompt. Without this a package that wants
# to discuss a modified conffile will block forever on a runner with no tty.
export DEBIAN_FRONTEND=noninteractive

ARCH=$(dpkg --print-architecture)

echo "=== Removing Docker Engine (conflicts with Finch containerd) ==="
apt-get remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
apt-get autoremove -y
rm -rf /root/.docker /home/runner/.docker

echo "=== Adding Finch APT repository ==="
curl -fsSL https://artifact.runfinch.com/deb/GPG_KEY.pub | gpg --dearmor -o /usr/share/keyrings/runfinch-finch-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/runfinch-finch-archive-keyring.gpg arch=${ARCH}] https://artifact.runfinch.com/deb noble main" | tee /etc/apt/sources.list.d/runfinch-finch.list
apt-get update -q

echo "=== Installing Finch ==="
apt-get install -y runfinch-finch

echo "=== Starting Finch services ==="
systemctl start containerd
systemctl start finch-buildkit
systemctl start finch

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
    echo "buildkit or containerd is installed but not usable; refusing to continue." >&2
    systemctl status containerd finch-buildkit finch --no-pager --lines=40 >&2 || true
    journalctl -u finch-buildkit --no-pager --lines=60 >&2 || true
    exit 1
fi

echo "=== Finch setup complete ==="
