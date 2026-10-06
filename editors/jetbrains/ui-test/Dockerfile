# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# The image the JetBrains plugin's visual snapshots are rendered in.
#
# A screenshot is only a snapshot if the same commit renders the same pixels, so everything that
# reaches a pixel is fixed here or in ui-test-in-container.sh:
#
#   * the base image, by digest: the same gradle:jdk21 image and digest as every other job in
#     .github/workflows/ash-jetbrains-ci.yml, so the JDK and the fontconfig and fonts-dejavu
#     packages it ships are the ones the other jobs run with;
#   * the X server and its libraries, by package version, from the Ubuntu archive SNAPSHOT of a
#     fixed date (snapshot.ubuntu.com). A plain `apt-get install xvfb` resolves against today's
#     archive, so the same Dockerfile would build a different image next month. The snapshot
#     date pins the whole dependency closure, and the explicit versions make a snapshot that no
#     longer carries them fail the build instead of installing something else;
#   * the IDE build, theme, fonts, scale and window size: ui-test-in-container.sh and
#     build.gradle.kts (the IDE is the 2025.2.5 distribution the build compiles against, and the
#     editor and UI fonts are the ones that distribution bundles).
#
# Built in CI and thrown away with the job. It is never pushed: nothing in this repository
# publishes it, and .github/scripts/assert-no-image-publish.py fails a workflow that would.
FROM gradle:jdk21@sha256:4debe478645a3ad9208f3403ac021859fdf4d1a819d59970d75309b098f28f76

# The archive snapshot the X packages come from; move it together with the versions below.
ARG UBUNTU_SNAPSHOT=20261001T000000Z

RUN apt-get -o Acquire::Retries=3 update --snapshot "${UBUNTU_SNAPSHOT}" \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends --snapshot "${UBUNTU_SNAPSHOT}" \
      xvfb=2:21.1.22-1ubuntu1.2 \
      x11-utils=7.7+7build1 \
      libxtst6=2:1.2.5-1build1 \
      libxi6=2:1.8.2-2 \
      libxrender1=1:0.9.12-1build1 \
      libxrandr2=2:1.5.4-1build1 \
 && rm -rf /var/lib/apt/lists/*
