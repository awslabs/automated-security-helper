#!/usr/bin/env bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# apt-get update and install with bounded retries, for CI runners.
#
# Usage: bash apt-retry.sh [--update] [--update-only] [--attempts N]
#                          [--no-install-recommends] [--] [package ...]
#
#   --update                run `apt-get update` before the install, inside every attempt
#   --update-only           run `apt-get update` and install nothing (implies --update)
#   --attempts N            outer attempts, default 3
#   --no-install-recommends pass it to `apt-get install`
#   --check-log FILE        run nothing; if FILE (the output of an apt command the
#                           caller ran) holds the Azure resolve failure, switch the
#                           mirror as below, then exit 0
#
# Why this exists. On 2026-11-11 the hosted runners' DNS resolver failed for a
# stretch of hours ("Temporary failure resolving 'azure.archive.ubuntu.com'"). apt's
# own Acquire::Retries re-tries a single failed fetch within seconds, which does not
# outlast a resolver outage, and a bare `apt-get update && apt-get install` has no
# second chance at all. Each attempt here re-runs the whole update + install after a
# 20 s then 60 s pause, and passes `-o Acquire::Retries=5` so apt also retries inside
# an attempt.
#
# Mirror fallback. When the failed attempt's output says the Azure mirror host did
# not resolve, the runner's mirror list (/etc/apt/apt-mirrors.txt, which the noble
# sources file reads through `mirror+file:`) and any apt source naming the Azure host
# are rewritten to http://archive.ubuntu.com/ubuntu before the next attempt. That
# helps only when the failure is specific to the Azure mirror name. A resolver that
# fails every name is bridged by the backoff alone, and after the last attempt this
# script exits non-zero with that attempt's apt output already printed.

set -uo pipefail

ATTEMPTS=3
CHECK_LOG=""
DO_UPDATE=0
DO_INSTALL=1
INSTALL_OPTS=()
PACKAGES=()

while [ "$#" -gt 0 ]; do
    case "$1" in
        --update) DO_UPDATE=1 ;;
        --update-only) DO_UPDATE=1; DO_INSTALL=0 ;;
        --attempts)
            shift
            ATTEMPTS="${1:-}"
            ;;
        --no-install-recommends) INSTALL_OPTS+=(--no-install-recommends) ;;
        --check-log)
            shift
            CHECK_LOG="${1:-}"
            DO_INSTALL=0
            ;;
        --)
            shift
            PACKAGES+=("$@")
            break
            ;;
        *) PACKAGES+=("$1") ;;
    esac
    shift
done

case "${ATTEMPTS}" in
    '' | *[!0-9]* | 0)
        echo "apt-retry: --attempts must be a positive integer" >&2
        exit 2
        ;;
esac
if [ "${DO_INSTALL}" -eq 1 ] && [ "${#PACKAGES[@]}" -eq 0 ]; then
    echo "apt-retry: no packages given" >&2
    exit 2
fi

SUDO=()
if [ "$(id -u)" -ne 0 ]; then
    SUDO=(sudo)
fi

# Keep apt from ever opening a prompt.
export DEBIAN_FRONTEND=noninteractive
APT_OPTS=(-o Acquire::Retries=5)

AZURE_RESOLVE_FAILURE="Temporary failure resolving 'azure.archive.ubuntu.com'"
FALLBACK_MIRROR="http://archive.ubuntu.com/ubuntu"

prefer_fallback_mirror() {
    echo "apt-retry: the Azure mirror host did not resolve; preferring ${FALLBACK_MIRROR} for the next attempt"
    if [ -f /etc/apt/apt-mirrors.txt ]; then
        # Keep the first copy only: a second fallback must not overwrite the original.
        if [ ! -e /etc/apt/apt-mirrors.txt.apt-retry-orig ]; then
            "${SUDO[@]}" cp -p /etc/apt/apt-mirrors.txt /etc/apt/apt-mirrors.txt.apt-retry-orig 2>/dev/null || true
        fi
        printf '%s/\tpriority:1\n' "${FALLBACK_MIRROR}" | "${SUDO[@]}" tee /etc/apt/apt-mirrors.txt >/dev/null || true
    fi
    local f
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.sources /etc/apt/sources.list.d/*.list; do
        if [ -f "${f}" ] && grep -q 'azure\.archive\.ubuntu\.com' "${f}"; then
            "${SUDO[@]}" sed -i 's#https\?://azure\.archive\.ubuntu\.com/ubuntu#'"${FALLBACK_MIRROR}"'#g' "${f}" || true
        fi
    done
}

run_attempt() {
    if [ "${DO_UPDATE}" -eq 1 ]; then
        "${SUDO[@]}" apt-get update -q "${APT_OPTS[@]}" || return $?
    fi
    if [ "${DO_INSTALL}" -eq 1 ]; then
        "${SUDO[@]}" apt-get install -y "${APT_OPTS[@]}" "${INSTALL_OPTS[@]}" "${PACKAGES[@]}" || return $?
    fi
}

# --check-log FILE: apply only the mirror-fallback check to the output of an apt
# command the caller ran itself (a download, say), then exit 0. Does nothing when
# the Azure signature is absent from FILE.
if [ -n "${CHECK_LOG}" ]; then
    if [ -f "${CHECK_LOG}" ] && grep -qF "${AZURE_RESOLVE_FAILURE}" "${CHECK_LOG}"; then
        prefer_fallback_mirror
    fi
    exit 0
fi

LOG=$(mktemp "${TMPDIR:-/tmp}/apt-retry.XXXXXX")
trap 'rm -f -- "${LOG:?}"' EXIT

attempt=1
rc=0
while :; do
    echo "apt-retry: attempt ${attempt} of ${ATTEMPTS}"
    run_attempt 2>&1 | tee "${LOG}"
    rc=${PIPESTATUS[0]}
    if [ "${rc}" -eq 0 ]; then
        exit 0
    fi
    # Checked before the last-attempt exit, so a caller that runs one attempt at a
    # time (--attempts 1) still switches the mirror for its own next try.
    if grep -qF "${AZURE_RESOLVE_FAILURE}" "${LOG}"; then
        prefer_fallback_mirror
    fi
    if [ "${attempt}" -ge "${ATTEMPTS}" ]; then
        break
    fi
    if [ "${attempt}" -eq 1 ]; then
        pause=20
    else
        pause=60
    fi
    echo "apt-retry: attempt ${attempt} failed (exit ${rc}); waiting ${pause}s"
    sleep "${pause}"
    attempt=$((attempt + 1))
done

echo "::error::apt-retry: apt failed on all ${ATTEMPTS} attempts (last exit ${rc}); the last attempt's output is above"
exit "${rc}"
