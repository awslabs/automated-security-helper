# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The image the live-engine CI leg (.github/workflows/ash-image-scan-live-engine.yml)
# builds, pushes to a local registry and scans by tag. It only has to be a real
# image with a real layer of its own; nothing in it is scanned for a finding.
#
# Base: busybox 1.37 from the public.ecr.aws gallery, pinned by the digest of its
# multi-platform index (read from the registry on 2026-11-25; the workflow runs
# on amd64, so the engine picks the amd64 manifest from that index).
FROM public.ecr.aws/docker/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec

RUN echo "ash live-engine fixture" > /etc/ash-live-engine
