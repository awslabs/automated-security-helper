#!/usr/bin/env bash
# Regenerate the hashed requirement files the operator image and the e2e ASH image
# install from. Run it from anywhere; it needs uv and network access to PyPI.
#
#   requirements.txt                       the operator's runtime, from pyproject.toml
#   build-requirements.txt                 hatchling, to build the operator wheel
#   tests/e2e/ash-build-requirements.txt   hatchling, to build the ASH wheel
#   tests/e2e/scanner-requirements.txt     bandit and its extras, beside ASH
#
# The ASH image's own runtime is not here. tests/e2e/helpers.py exports it from the
# repository's uv.lock while staging the build context, so it can never disagree with
# the lock the rest of the repository is tested against.
#
# scanner-requirements.txt is resolved against that same export and leaves out every
# package the export already pins. pip accepts one package pinned twice only when both
# pins agree, so a file that repeated rich or pyyaml would fail the image build on the
# next routine bump of uv.lock. The image runs `pip check` after installing both, which
# catches a requirement of bandit's that neither file satisfies.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
e2e="$here/tests/e2e"
compile=(uv pip compile --quiet --universal --python-version 3.12)

(cd "$here" && "${compile[@]}" --generate-hashes pyproject.toml -o requirements.txt)
(cd "$here" && "${compile[@]}" --generate-hashes build-requirements.in -o build-requirements.txt)
(cd "$e2e" && "${compile[@]}" --generate-hashes ash-build-requirements.in -o ash-build-requirements.txt)

scratch="$(mktemp -d)"
# Written beside the .in file rather than in $scratch, so the header uv writes into
# scanner-requirements.txt names a relative path and no machine's temp directory.
constraints="$e2e/ash-runtime-constraints.txt"
trap 'rm -rf "${scratch:?}"; rm -f "${constraints:?}"' EXIT
(cd "$root" && uv export --quiet --frozen --no-dev --no-emit-project --no-header --no-hashes \
  --format requirements.txt -o "$constraints")

names() { grep -oE '^[A-Za-z0-9._-]+==' "$1" | sed 's/==$//' | tr '[:upper:]_.' '[:lower:]--' | sort -u; }

(cd "$e2e" && "${compile[@]}" --no-header -c ash-runtime-constraints.txt \
  scanner-requirements.in -o "$scratch/closure.txt")
skip=()
while read -r name; do
  skip+=(--no-emit-package "$name")
done < <(comm -12 <(names "$scratch/closure.txt") <(names "$constraints"))

(cd "$e2e" && "${compile[@]}" --generate-hashes -c ash-runtime-constraints.txt "${skip[@]}" \
  scanner-requirements.in -o scanner-requirements.txt)
