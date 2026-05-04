#!/bin/bash
# Retry wrapper for network-dependent commands (3 attempts, exponential backoff)
max=3; delay=5; attempt=1
while [ $attempt -le $max ]; do
  eval "$@" && exit 0
  echo "Attempt $attempt/$max failed, retrying in ${delay}s..." >&2
  sleep $delay; delay=$((delay * 2)); attempt=$((attempt + 1))
done
echo "All $max attempts failed" >&2; exit 1
