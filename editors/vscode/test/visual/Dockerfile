# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#checkov:skip=CKV_DOCKER_2:Nothing reads a Docker HEALTHCHECK here. test/snapshots.ts runs this image once per visual run with docker run --rm, waits for it to exit and reads its exit status; there is no orchestrator and no long-running service to probe.

# The environment the VS Code pixel snapshots are rendered in. See README.md beside
# this file for why each pin is here; in short, a pixel baseline is a picture of this
# image as much as of the extension, so everything that can change a pixel is fixed.
#
# Built in CI from this file, never pulled or pushed as a finished image.

# Base image by digest: a tag can be repointed, a digest cannot.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392

# Debian packages from snapshot.debian.org at one fixed instant, so every build of this
# file installs the same versions of Xvfb, fontconfig, FreeType and the fonts. The live
# mirror would give a newer FreeType or font the next time a point release lands, and
# either one moves glyph edges. check-valid-until=no because a snapshot's Release file
# is past its Valid-Until date by design; apt still verifies its signature.
ARG DEBIAN_SNAPSHOT=20261001T000000Z
# DL3008 (pin versions in apt-get install): the pin here is the snapshot instant above,
# which fixes every package's version for every build, and a per-package version would
# repeat it and break on the next snapshot move.
# hadolint ignore=DL3008
RUN rm -f /etc/apt/sources.list.d/debian.sources \
 && printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm-updates main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      > /etc/apt/sources.list \
 && apt-get -o Acquire::Retries=5 update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl xvfb xauth imagemagick fonts-dejavu-core fontconfig \
      libgtk-3-0 libnss3 libgbm1 libasound2 libxkbfile1 libsecret-1-0 libxss1 \
 && rm -rf /var/lib/apt/lists/*

# One font family and nothing else, so fontconfig has no fallback to choose between.
# The check fails the build if a package above brought in a second family.
# DL4006 (set -o pipefail before a RUN with a pipe): the pipe is `fc-list | sort -u` inside
# a command substitution that `test` compares to the expected list, so a failed fc-list
# yields an empty list that is not equal to it and the build stops.
# hadolint ignore=DL4006
RUN test "$(fc-list : family | sort -u)" = "$(printf 'DejaVu Sans\nDejaVu Sans Mono\nDejaVu Serif')" \
 || { echo "unexpected font families:"; fc-list : family | sort -u; exit 1; }

# VS Code itself, at the version the integration job also pins, verified against the
# SHA-256 the update service publishes for that build
# (https://update.code.visualstudio.com/api/versions/1.141.0/linux-x64/stable).
ARG VSCODE_VERSION=1.141.0
ARG VSCODE_COMMIT=2a59476c9bfcb90b3ddc372c36762471b7dfad1c
ARG VSCODE_SHA256=d77d588f0454cbaaa71e723497de4160d15b95fba4988abe177b1432e6bd570a
# DL4006 (set -o pipefail before a RUN with a pipe): the pipe is `echo | sha256sum -c -`,
# whose verdict is sha256sum's own exit status, the last command in it; the left side is a
# literal echo that cannot fail in a way pipefail would catch.
# hadolint ignore=DL4006
RUN curl -fsSL --retry 5 -o /tmp/vscode.tar.gz \
      "https://update.code.visualstudio.com/${VSCODE_VERSION}/linux-x64/stable" \
 && echo "${VSCODE_SHA256}  /tmp/vscode.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/vscode \
 && tar -xzf /tmp/vscode.tar.gz -C /opt/vscode --strip-components=1 \
 && rm /tmp/vscode.tar.gz \
 && grep -q "\"commit\": \"${VSCODE_COMMIT}\"" /opt/vscode/resources/app/product.json \
 && grep -q "\"version\": \"${VSCODE_VERSION}\"" /opt/vscode/resources/app/package.json

ENV ASH_VISUAL_VSCODE=/opt/vscode/code \
    LANG=C.UTF-8 \
    TZ=UTC

# The base image's unprivileged user, so the image never defaults to root.
# test/snapshots.ts passes --user with the invoking uid and gid wherever the platform
# has them, which overrides this, so files written into the mounted tree belong to
# whoever ran the suite; this line decides only the fallback.
USER node
