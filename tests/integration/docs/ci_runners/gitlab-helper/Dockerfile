#checkov:skip=CKV_DOCKER_2:A helper container runs one copy or ownership command and exits; nothing reads a Docker HEALTHCHECK for it.
#checkov:skip=CKV_DOCKER_3:gitlab-ci-local runs its artifact copies in this image as the image's own user and writes them under /artifacts at the filesystem root, so the user is root, as in gitlab-ci-local's own helper image.
#
# The helper image gitlab-ci-local uses for its own steps around a job: setting the
# ownership of the build directory, and copying artifacts out of the job's volume with
# bash and rsync. Its default helper is a :latest tag on Docker Hub; this one is built in
# the job from a pinned base, so every image the GitLab leg pulls is pinned by digest.
#
# The base is images.debian-bookworm-slim in ../runners.toml, written here as its digest
# reference; tests/unit/test_docs_ci_runner_launchers.py checks that the two agree.
FROM public.ecr.aws/docker/library/debian@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

# rsync is deliberately unpinned: the base image is already pinned by digest above,
# so the resolved rsync version is reproducible, and pinning an exact Debian version
# here would retire with the next bookworm point release, the drift the root
# Dockerfile's weekly pin check exists to catch and which a test fixture should not
# also be exposed to.
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends rsync \
    && rm -rf /var/lib/apt/lists/*
