# A deliberately small ASH image, for the end-to-end test only.
#
# Not a substitute for the real one. It carries the two scanners that are pure
# Python -- bandit and detect-secrets -- and none of the eight that need ruby, node,
# npm or a Go binary. That is enough to prove the contract, because what the e2e has
# to demonstrate is that a real `ashx scan` ran per shard, that its provenance was
# stamped, that the merge consumed every index and that a planted finding came back.
# A scanner that needs a toolchain would add minutes to the build and test nothing
# the operator is responsible for.
#
# The image is loaded into kind with `kind load docker-image`, so it is never pushed
# anywhere. ASH publishes no public image and neither does this.
FROM python:3.12-slim

# A writable HOME that is not root's. Kubernetes' runAsUser overrides the image's
# USER but does NOT consult /etc/passwd for a home directory, so HOME has to come
# from the image environment or it defaults to "/" -- and a scanner that cannot
# write a cache directory comes back MISSING, which merges into a report that reads
# as a complete scan.
RUN useradd --uid 1000 --create-home --home-dir /home/ash --shell /bin/sh ash
ENV HOME=/home/ash \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Kubernetes never reads a Docker HEALTHCHECK, and this image runs `ashx scan` to
# completion in a Job rather than serving anything, so there is nothing to probe.
# NONE says so explicitly instead of leaving it to be inferred.
HEALTHCHECK NONE

WORKDIR /src
COPY ash-source /src

# bandit is installed by name as well as being reachable through `uv tool run`. The
# ASH scanner prefers uv and falls back to a binary on PATH; a pod with no egress
# has only the fallback, and without it bandit reports MISSING rather than failing,
# which is invisible while fail_on_incomplete_scanners stays off.
RUN pip install --no-cache-dir . bandit detect-secrets \
    && python -c "import automated_security_helper; print(automated_security_helper.__version__)" \
    && ashx --version \
    && chown -R 1000:1000 /home/ash

# Warm uv's tool environment as the running user, so the uv path works offline too.
# Non-fatal: the pip-installed binary above is the guarantee, this is the
# optimisation.
USER 1000
RUN uv tool install bandit || echo "uv tool install bandit failed; the PATH binary is the fallback"

WORKDIR /workspace
