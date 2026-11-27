# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov's VCS server-configuration frameworks: the measured floor and its helpers.

checkov's ``--framework all`` set includes frameworks that audit a remote VCS
platform's settings through its API (reaching for tokens such as
``CI_SERVER_URL``/``CI_JOB_TOKEN`` in GitLab CI) and write the fetched
configuration below checkov's working directory instead of reading files in the
scanned tree. ASH treats those frameworks specially in three ways: it leaves them
out of default scans, it points their cache directories below the scanner's
results directory, and it passes each one's API token to checkov only when that
framework runs in an online scan (``VCS_TOKEN_ENV_VARS``).

The skip set is the measured floor below, not a list derived from the
``CheckFrameworks`` mirror of checkov's registry. checkov ends the run with
``parser.error`` on a ``--skip-framework`` value it does not know
(``normalize_framework_arg``, checkov 3.4.5 main.py), and ASH's default
``>=3.2.0,<4.0.0`` constraint admits releases older than the one the mirror
follows, so a name taken from the mirror would fail every default scan on a
release that predates it. Adding a VCS framework to the set is an explicit
decision that also raises the constraint's lower bound to the first checkov
release that has it. The ``CheckFrameworks`` literal may still grow for typing.

Measured at checkov 3.4.5, the three floor frameworks are ``CheckType``
constants ending in ``_configuration``
(checkov/common/bridgecrew/check_type.py:16-20), and each one's runner wraps a
DAL extending the network-client base class ``BaseVCSDAL``
(checkov/common/vcs/base_vcs_dal.py:16; gitlab/dal.py:10, github/dal.py:16,
bitbucket/dal.py:13). Each DAL reads its cache directory and fetch toggle from
environment variables that follow one pattern:
``os.getenv("CKV_{VENDOR}_CONF_DIR_NAME", "{vendor}_conf")`` and
``os.getenv("CKV_{VENDOR}_CONFIG_FETCH_DATA", "True")`` (gitlab/dal.py:18 and
:67, github/dal.py:24 and :225, bitbucket/dal.py:18 and :77), with ``VENDOR``
the framework name minus the suffix. The helpers below apply that pattern to
the floor; nothing re-reads checkov's DAL source, so a renamed variable is not
caught by a test.

tests/integration/scanners/test_checkov_real_config_and_paths.py compares the
installed checkov's registry with the mirror and with the floor: a release
whose ``*_configuration`` names differ from the floor fails there until the
set (and the constraint) is decided.
"""

from typing import Iterable, Mapping, Tuple

VCS_CONFIGURATION_SUFFIX = "_configuration"

# The floor, measured at checkov 3.4.5 and present throughout the supported
# constraint range. Sorted, because the argv and the environment follow it.
KNOWN_VCS_CONFIGURATION_FRAMEWORKS: Tuple[str, ...] = (
    "bitbucket_configuration",
    "github_configuration",
    "gitlab_configuration",
)

# The variable each floor framework's DAL reads its API token from. The three
# names share no pattern, so each one is measured rather than derived. Read at
# checkov 3.3.26, and the same at 3.4.11: ``discover()`` sets ``self.token`` from
# ``os.getenv('APP_PASSWORD', '')`` (bitbucket/dal.py:31),
# ``os.getenv('GITHUB_TOKEN', '')`` (github/dal.py:47) and
# ``os.getenv('CI_JOB_TOKEN', '')`` (gitlab/dal.py:33). ``BaseVCSDAL.__init__``
# calls ``discover()`` (common/vcs/base_vcs_dal.py:34), and each runner builds its
# DAL in its own ``__init__`` (bitbucket/runner.py:19, github/runner.py:20,
# gitlab/runner.py:18), which checkov runs for all three when ``checkov.main`` is
# imported (main.py:118, :119 and :121), so the token is read whichever
# frameworks the scan runs. The DAL sends it only from its requests
# (base_vcs_dal.py:85-92 and :111-119, bitbucket/dal.py:39-45), which a runner
# reaches only when its framework runs (``prepare_data``, then
# ``persist_all_confs`` behind the fetch toggle below).
#
# Bitbucket's DAL also reads ``BITBUCKET_USERNAME`` (bitbucket/dal.py:36), the user
# its token is sent with. It is not listed: it holds no secret, and checkov's
# terraform module loader reads it too, for Bitbucket module downloads
# (terraform/module_loading/loaders/bitbucket_access_token_loader.py:15).
VCS_TOKEN_ENV_VARS: Mapping[str, str] = {
    "bitbucket_configuration": "APP_PASSWORD",
    "github_configuration": "GITHUB_TOKEN",
    "gitlab_configuration": "CI_JOB_TOKEN",
}


def vcs_vendor(framework: str) -> str:
    """The vendor part of a VCS configuration framework name: ``gitlab`` for
    ``gitlab_configuration``."""
    return framework[: -len(VCS_CONFIGURATION_SUFFIX)]


def vcs_conf_dir_env_vars(
    frameworks: Iterable[str],
) -> Tuple[Tuple[str, str], ...]:
    """Each framework's cache-directory variable with its default directory
    name, by the pattern every checkov VCS DAL uses:
    ``os.getenv("CKV_{VENDOR}_CONF_DIR_NAME", "{vendor}_conf")`` (checkov 3.4.5
    gitlab/dal.py:18, github/dal.py:24, bitbucket/dal.py:18)."""
    return tuple(
        (
            f"CKV_{vcs_vendor(framework).upper()}_CONF_DIR_NAME",
            f"{vcs_vendor(framework)}_conf",
        )
        for framework in frameworks
    )


def vcs_config_fetch_env_vars(frameworks: Iterable[str]) -> Tuple[str, ...]:
    """Each framework's fetch toggle, by the pattern every checkov VCS DAL
    uses: ``os.getenv("CKV_{VENDOR}_CONFIG_FETCH_DATA", "True")`` (checkov
    3.4.5 gitlab/dal.py:67, github/dal.py:225, bitbucket/dal.py:77)."""
    return tuple(
        f"CKV_{vcs_vendor(framework).upper()}_CONFIG_FETCH_DATA"
        for framework in frameworks
    )
