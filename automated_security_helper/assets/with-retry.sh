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
while [ $attempt -le $max ]; do
  bash -o pipefail -c "$*" && exit 0
  echo "Attempt $attempt/$max failed, retrying in ${delay}s..." >&2
  sleep $delay; delay=$((delay * 2)); attempt=$((attempt + 1))
done
echo "All $max attempts failed" >&2; exit 1
