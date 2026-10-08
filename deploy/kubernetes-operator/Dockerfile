# The operator image. Deliberately does NOT contain ASH.
#
# The operator never imports ASH: it builds argv strings and reads JSON. Keeping
# ASH out means the controller and the scanners can be different versions, which is
# the normal state during a rollout, and it keeps a scanner's dependency tree out
# of the one process that holds API credentials.
#
# The one thing that does need ASH is the CRD generator, and that runs in CI and on
# a developer's machine, not here.
#
# EVERY PACKAGE IS INSTALLED FROM A HASHED, VERSION-PINNED FILE. pip's --require-hashes
# refuses a download whose sha256 is not listed, and refuses any requirement that is not
# pinned with ==, so a dependency cannot move or be swapped between two builds of the
# same commit. requirements.txt is the runtime, build-requirements.txt the build backend;
# regenerate both with relock.sh, never by hand.
#
# The wheel is built in its own stage with --no-build-isolation, because pip's isolated
# build environment fetches the build backend from the index with no hash check. Here
# hatchling comes from build-requirements.txt, and neither it nor its dependencies reach
# the image that holds API credentials.
#
# Pinned by digest (.github/scripts/assert-images-pinned.py enforces it): the multi-arch
# index python:3.12-slim resolved to on 2026-10-05 (Python 3.12.15). Both stages name the
# same digest.
FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d AS build

WORKDIR /build
COPY build-requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r build-requirements.txt
COPY pyproject.toml README.md ./
COPY ash_operator ./ash_operator
RUN pip wheel --no-cache-dir --no-deps --no-build-isolation --no-index --wheel-dir /wheels .

FROM python:3.12-slim@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d

# Non-root from the start. The numeric uid matches manifests/operator.yaml so
# readOnlyRootFilesystem and runAsUser agree. --user-group is explicit because a
# base image that already has a group called "operator" makes a bare useradd warn
# and pick a different gid, and then the uid and gid stop matching the manifest.
RUN groupadd --gid 10001 ashoperator \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /home/operator \
       --shell /usr/sbin/nologin ashoperator

WORKDIR /app
COPY requirements.txt ./
COPY --from=build /wheels /wheels

# The wheel goes in with --no-deps --no-index, so it can add nothing the hashed
# requirements did not; `pip check` then proves those requirements are the wheel's whole
# dependency closure. The last command is the real check. Importing the module only
# proves the Python landed; the operator reads the entrypoint scripts off disk to build
# each run's ConfigMap, so a packaging change that dropped them would produce a
# controller that starts cleanly and then creates Jobs with no command to run.
RUN pip install --no-cache-dir --require-hashes -r requirements.txt \
    && test "$(find /wheels -name 'ash_kubernetes_operator-*.whl' | wc -l)" -eq 1 \
    && pip install --no-cache-dir --no-deps --no-index /wheels/ash_kubernetes_operator-*.whl \
    && pip check \
    && python -c "\
import ash_operator.manifests as m; \
cm = m.build_run_configmap( \
    scan={'metadata': {'name': 'probe', 'namespace': 'n', 'uid': 'u'}}, \
    ash_config=None, \
); \
missing = [k for k in ('shard-entrypoint.sh', 'collect-entrypoint.sh', 'collect.py', \
                       '_attempts.py', '_constants.py') if k not in cm['data']]; \
assert not missing, f'the installed package is missing {missing}'; \
print('entrypoints present:', sorted(cm['data']))"

# Kubernetes never reads a Docker HEALTHCHECK; the kubelet's probes are the only
# health signal a pod has. NONE says so explicitly and also clears any check a future
# base image might declare, which the kubelet would ignore while `docker ps` showed it.
HEALTHCHECK NONE

USER 10001
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["kopf", "run", "--standalone", "-m", "ash_operator.main"]
