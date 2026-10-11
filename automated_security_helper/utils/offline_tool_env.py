# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Environment variables that keep each scanner tool off the network in offline mode.

Offline mode means no scanner contacts the network. Several tools ASH runs check for
a newer version of themselves, or send usage data, on their own, and the offline
flags ASH passes for them do not cover it. Measured with every proxy variable
pointed at a refusing local proxy and fresh tool caches (a warm cache hides most of
these for up to a day, which is why a developer machine usually shows nothing):

* semgrep 1.180 checks semgrep.dev for a newer version in ``semgrep scan`` and in
  ``semgrep --version``; ``--metrics off`` is a different switch.
* checkov asks pypi.org for its newest release when ``checkov.common.util.banner``
  is imported, which every command does, ``--version`` included.
* npm 10.9 runs its update notifier against registry.npmjs.org in
  ``npm audit --offline``.
* trivy 0.75 contacts check.trivy.dev for its version check and its telemetry.
* syft and grype check for a newer release of themselves.

Some tools also read settings from a config file in the scanned tree that turn on
lookups over the network: syft's remote license searches, maven lookups and vcpkg
git clones, and grype's external sources. Setting them false in the environment
overrides the file (measured for syft's Go license search).

On a Go module, syft (``golang.use-packages-lib``, on by default) and grype run the Go
toolchain found on PATH (``go list``; measured with a fake ``go``). A real toolchain
resolves missing modules from GOPROXY and, for a ``go`` or ``toolchain`` line newer
than itself, downloads a toolchain. syft's setting is turned off, and for grype, which
has none, ``GOPROXY=off`` and ``GOTOOLCHAIN=local`` keep that toolchain from
downloading anything.

In offline mode every process started through ``subprocess_utils`` gets the whole
set, whichever tool it is: a variable means nothing to the other tools, and setting
all of them means a tool started through ``uv tool run``, a wrapper script or a
version probe gets its own too. ``PluginBase._run_subprocess`` also applies it to
every scanner command, including one whose own ``offline`` option is set while ASH
runs online. A few spawns call ``subprocess.run`` directly and do not get it: git
for the scan set, nbconvert, the sandbox backends' own probes and the nix wrapper.
None of them starts a tool with a check of this kind.
"""

from typing import Dict, Mapping, Optional

#: Variable -> value that turns the check or lookup off.
OFFLINE_TOOL_ENVIRONMENT: Mapping[str, str] = {
    # semgrep: version check (scan and --version) and metrics.
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "SEMGREP_SEND_METRICS": "off",
    # checkov: the PyPI update check at import.
    "CKV_SKIP_PACKAGE_UPDATE_CHECK": "true",
    # npm: the update notifier.
    "npm_config_update_notifier": "false",
    # trivy: version check and telemetry (--skip-version-check, --disable-telemetry).
    "TRIVY_SKIP_VERSION_CHECK": "true",
    "TRIVY_DISABLE_TELEMETRY": "true",
    # syft: update check, and the lookups a .syft.yaml or `enrich` can turn on.
    "SYFT_CHECK_FOR_APP_UPDATE": "false",
    "SYFT_GOLANG_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_JAVA_USE_NETWORK": "false",
    "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_PYTHON_SEARCH_REMOTE_LICENSES": "false",
    "SYFT_CPP_VCPKG_ALLOW_GIT_CLONE": "false",
    "SYFT_GOLANG_USE_PACKAGES_LIB": "false",
    # grype: update checks, and the external sources a .grype.yaml can turn on.
    "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    "GRYPE_DB_AUTO_UPDATE": "false",
    "GRYPE_EXTERNAL_SOURCES_ENABLE": "false",
    # The Go toolchain syft or grype may run: no module proxy, no toolchain download.
    "GOPROXY": "off",
    "GOTOOLCHAIN": "local",
    # git run by a tool (trivy's Terraform module sources, syft's vcpkg registries)
    # reaches no remote; only local paths are allowed.
    "GIT_ALLOW_PROTOCOL": "file",
}


def offline_tool_environment(offline: Optional[bool] = None) -> Dict[str, str]:
    """The variables to add to a child's environment, or nothing when online.

    Args:
        offline: Whether the process runs offline. None reads ASH's offline mode
            (``--offline`` or ``ASH_OFFLINE``) now.
    """
    if offline is None:
        from automated_security_helper.core.constants import is_offline_mode

        offline = is_offline_mode()
    return dict(OFFLINE_TOOL_ENVIRONMENT) if offline else {}


def with_offline_tool_environment(
    env: Optional[Mapping[str, str]], offline: Optional[bool] = None
) -> Optional[Dict[str, str]]:
    """``env`` with the offline variables set over it.

    ``env`` None means "inherit": it stays None online, and offline it becomes a
    copy of the current environment with the variables added.
    """
    additions = offline_tool_environment(offline)
    if not additions:
        return None if env is None else dict(env)
    if env is None:
        from automated_security_helper.utils.process_env import snapshot_environ

        env = snapshot_environ()
    return {**env, **additions}
