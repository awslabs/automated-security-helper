#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Installs Finch on Ubuntu 24.04 (noble) for CI environments.
# Checks that the Finch install resolves for this host first, then removes
# Docker Engine and installs Finch from the official APT repo with Ubuntu's
# containerd and runc in Docker's place: Docker's containerd.io declares
# `Conflicts: containerd` and its bundled runc does not satisfy runfinch-finch's
# `runc (>= 1.1.5)`, so the swap is what makes Finch installable at all. The
# units are then started and the daemon and the builder probed. The workflow
# that calls this runs finch through `sudo` itself (OCI_RUNNER_WRAPPER); no
# wrapper is created here.
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
# Acquire::Retries makes apt retry a failed fetch itself; the bounded outer retries
# below (apt-retry.sh and the download loop) cover an outage that outlasts it.
APT_INSTALL=(apt-get install -y -o Acquire::Retries=5 -o Dpkg::Options::=--force-confold)

ARCH=$(dpkg --print-architecture)
KEYRING=/usr/share/keyrings/runfinch-finch-archive-keyring.gpg
SOURCES=/etc/apt/sources.list.d/runfinch-finch.list
APT_RETRY="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../.github/actions/apt-retry/apt-retry.sh"

# apt-retry.sh lives in the repository checkout, next to the action that wraps it.
# Run standalone, as the usage line above allows, from a copy of this script with no
# checkout beside it, the helper is absent: the index refresh then degrades to one
# plain `apt-get update` with apt's own fetch retries, and the Azure mirror fallback
# is skipped. Decided here, before anything is removed.
HAVE_APT_RETRY=0
if [ -f "${APT_RETRY}" ]; then
    HAVE_APT_RETRY=1
else
    echo "WARNING: ${APT_RETRY} not found; apt will not be retried beyond Acquire::Retries and the mirror fallback is off" >&2
fi

# Refreshes the package indexes: through apt-retry.sh when present, else plain apt.
refresh_index() {
    if [ "${HAVE_APT_RETRY}" -eq 1 ]; then
        bash "${APT_RETRY}" --update-only "$@"
    else
        apt-get update -q -o Acquire::Retries=5
    fi
}

# Optional deb cache. When FINCH_DEB_CACHE_DIR is set (the setup-finch action sets it
# and restores/saves that directory with actions/cache), the debs the download step
# fetches are kept there. A later run that finds all three packages in it installs
# with dpkg and never fetches an index. Unset, the script behaves as before: apt's
# own cache, one apt transaction.
CACHE_DIR="${FINCH_DEB_CACHE_DIR:-}"
CACHE_HIT=0
if [ -n "${CACHE_DIR}" ]; then
    CACHE_HIT=1
    for pkg in runfinch-finch containerd runc; do
        if ! compgen -G "${CACHE_DIR}/${pkg}_*.deb" >/dev/null; then
            CACHE_HIT=0
        fi
    done
fi

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

# Adds the Finch APT source and refreshes the package indexes. Skipped on a full
# cache hit, which needs neither; the dpkg-failure fallback below calls it.
add_finch_repo_and_update() {
    echo "=== Adding Finch APT repository ==="
    # --yes lets gpg overwrite the keyring on a re-run; without it gpg asks, and
    # with no tty aborts. The key is fetched from the same origin as the packages,
    # so the signed-by check anchors the packages to that origin and nothing more.
    # --retry-all-errors also retries a name-resolution failure, which curl's plain
    # --retry treats as permanent.
    curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 https://artifact.runfinch.com/deb/GPG_KEY.pub | gpg --dearmor --batch --yes -o "${KEYRING}"
    echo "deb [signed-by=${KEYRING} arch=${ARCH}] https://artifact.runfinch.com/deb noble main" | tee "${SOURCES}"
    refresh_index
}

if [ "${CACHE_HIT}" -eq 1 ]; then
    echo "=== Finch deb cache hit in ${CACHE_DIR}: no index fetch, no download ==="
else
    add_finch_repo_and_update
fi

# Download Finch and its containerd/runc replacements before Docker is removed.
# A host with no Finch package for its architecture, or a repository that
# cannot be reached, fails here while Docker is still installed, instead of
# after the only container runtime is gone.
#
# containerd and runc are NAMED on this command line, and that is load-bearing.
# Docker's containerd.io declares `Conflicts: containerd`, and runfinch-finch
# depends on `runc (>= 1.1.5)`, which containerd.io's bundled copy does not
# satisfy. Asked for runfinch-finch alone, apt refuses with
# "pkgProblemResolver::Resolve generated breaks" rather than deciding on its
# own to remove containerd.io; apt resolves a Conflicts by removal only when
# the command line names the replacements. --download-only performs none of
# that removal -- Docker stays installed, as the banner says -- it only proves
# the end state resolves and fills the apt cache the post-removal install
# reads from.
echo "=== Fetching Finch with containerd and runc (Docker is still installed; its containerd.io is swapped for them at the install below) ==="
#
# With a cache directory, apt is pointed at it (Dir::Cache::archives), so the debs
# land there instead of /var/cache/apt/archives. The download is tried three times,
# 20 s and 60 s apart, with the index refreshed before each retry.
DOWNLOAD_OPTS=()
if [ -n "${CACHE_DIR}" ]; then
    mkdir -p "${CACHE_DIR}/partial"
    DOWNLOAD_OPTS=(-o "Dir::Cache::archives=${CACHE_DIR}")
fi
if [ "${CACHE_HIT}" -eq 0 ]; then
    DOWNLOADED=0
    # The attempt's output is kept so a failure that names the Azure mirror host can
    # switch the mirror before the retry: the outage this guards against can start
    # after the index fetch, during the deb fetch, where nothing else would look.
    DOWNLOAD_LOG=$(mktemp /tmp/finch-download.XXXXXX)
    for attempt in 1 2 3; do
        "${APT_INSTALL[@]}" --download-only "${DOWNLOAD_OPTS[@]}" runfinch-finch containerd runc 2>&1 | tee "${DOWNLOAD_LOG}" && DOWNLOADED=1 && break
        [ "${attempt}" -lt 3 ] || break
        echo "WARNING: download attempt ${attempt} failed; retrying" >&2
        if [ "${HAVE_APT_RETRY}" -eq 1 ]; then
            bash "${APT_RETRY}" --check-log "${DOWNLOAD_LOG}" || true
        fi
        if [ "${attempt}" -eq 1 ]; then sleep 20; else sleep 60; fi
        refresh_index --attempts 1 || true
    done
    rm -f "${DOWNLOAD_LOG:?}"
    if [ "${DOWNLOADED}" -ne 1 ]; then
        echo "ERROR: could not download Finch, containerd and runc after 3 attempts; Docker is still installed." >&2
        exit 1
    fi
    if [ -n "${CACHE_DIR}" ]; then
        # The cache is saved by the runner user: make the debs readable to it and
        # leave out apt's lock file and partial downloads.
        rm -rf "${CACHE_DIR:?}/partial" "${CACHE_DIR:?}/lock"
        chmod -R a+rX "${CACHE_DIR}"
    fi
fi

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

# One transaction naming the same set the download step proved and cached, so
# the resolver here sees the end state it already resolved: Finch on Ubuntu's
# containerd and runc, with Docker's containerd.io already purged above.
#
# With a cache directory the debs are installed with dpkg, which needs no index and
# no network. Only if dpkg leaves a package unconfigured (a dependency the cache did
# not hold) does the apt transaction below run, with -f to repair what dpkg started;
# that path adds the Finch source and refreshes the indexes first. Without a cache
# directory the apt transaction is the whole install, as before.
echo "=== Installing Finch with containerd and runc in Docker's place ==="
INSTALLED=0
FIX_OPTS=()
if [ -n "${CACHE_DIR}" ]; then
    # --force-confold is dpkg's own spelling of the APT_INSTALL option above: with no
    # tty a conffile question would fail the install after Docker is already gone.
    if dpkg -i --force-confold "${CACHE_DIR}"/*.deb; then
        INSTALLED=1
    else
        echo "WARNING: dpkg could not finish the install from ${CACHE_DIR}; repairing with apt" >&2
        FIX_OPTS=(-f)
        # Tell the caller the cached debs needed repair, so it does not save them.
        : > "${CACHE_DIR}.repaired"
        add_finch_repo_and_update
    fi
fi
if [ "${INSTALLED}" -eq 0 ]; then
    "${APT_INSTALL[@]}" "${FIX_OPTS[@]}" runfinch-finch containerd runc
fi

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
# surfaces here in under a minute rather than wedging `ashx build-image` until the
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
