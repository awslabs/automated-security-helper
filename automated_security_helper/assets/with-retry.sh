#!/bin/bash
# Retry a command up to $max times with exponential backoff.
#
# `-o pipefail` belongs on the inner shell, not this one. pipefail is a shell
# option rather than an environment variable, so it does not cross a `bash -c`
# boundary: setting it here would leave the command on line 5 running with
# bash's default behaviour, where a pipeline reports only its *last* command's
# status.
#
# That distinction is the whole point of this script. Almost every caller is a
# piped network install of the form
#
#     with-retry 'curl -sSfL https://.../install.sh | sh -s -- -b /usr/local/bin'
#
# and `sh` exits 0 when curl dies and hands it an empty stdin. Without pipefail
# on the inner shell the pipeline "succeeds", this loop exits on the first
# attempt, and the retry never happens -- the failure surfaces several layers
# later as a missing binary. Observed on 2026-08-20: curl hit
# "(35) Recv failure: Connection reset by peer" fetching grype's installer, no
# retry was attempted, and the build died at the next step with
# "grype: not found" (exit 127).
set -o pipefail
# Overridable so the retry behaviour can be exercised without waiting out the
# real backoff. Defaults are what every Dockerfile caller gets.
max=${WITH_RETRY_MAX_ATTEMPTS:-3}; delay=${WITH_RETRY_DELAY:-5}; attempt=1

# Both knobs feed integer arithmetic below -- `$((delay * 2))` and
# `[ $attempt -le $max ]` -- and bash arithmetic cannot parse a non-integer.
# A fractional WITH_RETRY_DELAY such as 0.1, which is the obvious way to ask for
# a fast-but-nonzero backoff, made `delay=$((delay * 2))` a syntax error. That
# error aborts the enclosing `while` WITHOUT aborting the script (there is no
# `set -e` here, and adding one would change how the attempt loop reports), so
# exactly ONE attempt ran and the script still printed "All 3 attempts failed"
# and exited 1. The attempt count was wrong and the only message anybody reads
# said otherwise, which is precisely why no assertion on that message could see
# it. Reject the bad value instead of retrying once and misreporting it.
#
# `case` rather than a regex or `expr` so this stays dependency-free: it runs in
# the container build stage before most of the toolchain exists.
case $max in
  '' | *[!0-9]*)
    echo "with-retry: WITH_RETRY_MAX_ATTEMPTS must be a non-negative integer, got '$max'" >&2
    exit 2
    ;;
esac
case $delay in
  '' | *[!0-9]*)
    echo "with-retry: WITH_RETRY_DELAY must be a whole number of seconds, got '$delay'" >&2
    exit 2
    ;;
esac
# Guarded separately, and only once $max is known to be numeric so `-lt` is
# safe. max=0 would skip the loop entirely and then report "All 0 attempts
# failed" with exit 1 -- a failure indistinguishable from the command having
# been run and failed, when it was never run at all.
if [ "$max" -lt 1 ]; then
  echo "with-retry: WITH_RETRY_MAX_ATTEMPTS must be at least 1, got '$max'" >&2
  exit 2
fi

while [ $attempt -le $max ]; do
  bash -o pipefail -c "$*" && exit 0
  echo "Attempt $attempt/$max failed, retrying in ${delay}s..." >&2
  sleep $delay; delay=$((delay * 2)); attempt=$((attempt + 1))
done
echo "All $max attempts failed" >&2; exit 1
