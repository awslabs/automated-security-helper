# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# The environment the VS Code pixel snapshots are rendered in. See README.md beside
# this file for why each pin is here; in short, a pixel baseline is a picture of this
# image as much as of the extension, so everything that can change a pixel is fixed.
#
# Built in CI from this file, never pulled or pushed as a finished image.

# Base image by digest: a tag can be repointed, a digest cannot.
FROM node:22-bookworm-slim@sha256:1b3abbc0bf2421c8733f58c6fd7bbb961a960f37e05ed7369eccd1fbb0edcc84

# Debian packages from snapshot.debian.org at one fixed instant, so every build of this
# file installs the same versions of Xvfb, fontconfig, FreeType and the fonts. The live
# mirror would give a newer FreeType or font the next time a point release lands, and
# either one moves glyph edges. check-valid-until=no because a snapshot's Release file
# is past its Valid-Until date by design; apt still verifies its signature.
ARG DEBIAN_SNAPSHOT=20261001T000000Z
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
RUN test "$(fc-list : family | sort -u)" = "$(printf 'DejaVu Sans\nDejaVu Sans Mono\nDejaVu Serif')" \
 || { echo "unexpected font families:"; fc-list : family | sort -u; exit 1; }

# VS Code itself, at the version the integration job also pins, verified against the
# SHA-256 the update service publishes for that build
# (https://update.code.visualstudio.com/api/versions/1.140.0/linux-x64/stable).
ARG VSCODE_VERSION=1.140.0
ARG VSCODE_COMMIT=07f806f999227108933c2e30515b26eecc1fda74
ARG VSCODE_SHA256=d32031e9e213d59532af3cf32fcb8b357a1cdd10417967b4f5b5ba30436dc0dc
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
