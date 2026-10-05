# The operator image. Deliberately does NOT contain ASH.
#
# The operator never imports ASH: it builds argv strings and reads JSON. Keeping
# ASH out means the controller and the scanners can be different versions, which is
# the normal state during a rollout, and it keeps a scanner's dependency tree out
# of the one process that holds API credentials.
#
# The one thing that does need ASH is the CRD generator, and that runs in CI and on
# a developer's machine, not here.
FROM python:3.12-slim

# Non-root from the start. The numeric uid matches manifests/operator.yaml so
# readOnlyRootFilesystem and runAsUser agree. --user-group is explicit because a
# base image that already has a group called "operator" makes a bare useradd warn
# and pick a different gid, and then the uid and gid stop matching the manifest.
RUN groupadd --gid 1000 ashoperator \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/operator \
       --shell /usr/sbin/nologin ashoperator

WORKDIR /app
COPY pyproject.toml ./
COPY README.md ./
COPY ash_operator ./ash_operator

# The second command is the real check. Importing the module only proves the Python
# landed; the operator reads the entrypoint scripts off disk to build each run's
# ConfigMap, so a packaging change that dropped them would produce a controller that
# starts cleanly and then creates Jobs with no command to run.
RUN pip install --no-cache-dir . \
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

USER 1000
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
ENTRYPOINT ["kopf", "run", "--standalone", "-m", "ash_operator.main"]
