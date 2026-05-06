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

echo "=== Verifying Finch installation ==="
finch --version

echo "=== Finch setup complete ==="
