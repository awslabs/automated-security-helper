#!/bin/bash
set -o pipefail
max=3; delay=5; attempt=1
while [ $attempt -le $max ]; do
  bash -c "$*" && exit 0
  echo "Attempt $attempt/$max failed, retrying in ${delay}s..." >&2
  sleep $delay; delay=$((delay * 2)); attempt=$((attempt + 1))
done
echo "All $max attempts failed" >&2; exit 1
