# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The image the live-engine CI leg (.github/workflows/ash-image-scan-live-engine.yml)
# builds, pushes to a local registry and scans by tag. It only has to be a real
# image with a real layer of its own; nothing in it is scanned for a finding.
#
# Base: none. `FROM scratch` pulls nothing, so building this image makes no
# registry request and no registry's pull quota can refuse it. Its one layer is
# the file beside this Dockerfile, copied in.
FROM scratch

COPY ash-live-engine /etc/ash-live-engine
