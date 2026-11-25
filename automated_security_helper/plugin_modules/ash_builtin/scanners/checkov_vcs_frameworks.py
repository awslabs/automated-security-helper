# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov's VCS server-configuration frameworks, derived rather than hardcoded.

checkov's ``--framework all`` set includes frameworks that audit a remote VCS
platform's settings through its API (reaching for tokens such as
``CI_SERVER_URL``/``CI_JOB_TOKEN`` in GitLab CI) and write the fetched
configuration below checkov's working directory instead of reading files in the
scanned tree. ASH treats those frameworks specially in two ways: it leaves them
out of default scans, and it points their cache directories below the scanner's
results directory.

Rather than hardcoding the vendor list, this module derives it from an iterable
of framework names (the mirror ASH keeps of checkov's registry) by checkov's
own naming rule, measured at checkov 3.4.5, the newest release ASH's default
``>=3.2.0,<4.0.0`` constraint admits:

* Every VCS server-configuration framework is a ``CheckType`` constant ending
  in ``_configuration`` (checkov/common/bridgecrew/check_type.py:16-20, the
  module ``checkov_runners`` - checkov's ``--framework``/``--skip-framework``
  vocabulary - is built from), and each one's runner wraps a DAL extending the
  network-client base class ``BaseVCSDAL``
  (checkov/common/vcs/base_vcs_dal.py:16; gitlab/dal.py:10, github/dal.py:16,
  bitbucket/dal.py:13). The two views name the same three frameworks, so a new
  ``*_configuration`` entry added to the mirror is covered here with no
  further change.
* Each DAL reads its cache directory and fetch toggle from environment
  variables that follow one pattern:
  ``os.getenv("CKV_{VENDOR}_CONF_DIR_NAME", "{vendor}_conf")`` and
  ``os.getenv("CKV_{VENDOR}_CONFIG_FETCH_DATA", "True")`` (gitlab/dal.py:18
  and :67, github/dal.py:24 and :225, bitbucket/dal.py:18 and :77), with
  ``VENDOR`` the framework name minus the suffix.

Drift gates keep a checkov refactor loud instead of letting this module cover
less than it should: tests/unit/plugin_modules/ash_builtin/
test_checkov_vcs_frameworks.py pins the floor, the structural rule and the
environment-variable pattern, and tests/integration/scanners/
test_checkov_real_config_and_paths.py reads the installed checkov's own
registry and compares it with the mirror and with the floor below.
"""

from typing import Iterable, Tuple

VCS_CONFIGURATION_SUFFIX = "_configuration"

# The floor, measured at checkov 3.4.5 and present throughout the supported
# constraint range. The derivation below always includes it, whatever happens
# to the mirror it is given: the vendor names here are a measured safety net,
# not the detection mechanism.
KNOWN_VCS_CONFIGURATION_FRAMEWORKS: Tuple[str, ...] = (
    "bitbucket_configuration",
    "github_configuration",
    "gitlab_configuration",
)


def vcs_configuration_frameworks(frameworks: Iterable[str]) -> Tuple[str, ...]:
    """The VCS server-configuration frameworks among ``frameworks``, sorted.

    A framework qualifies by checkov's naming rule for its VCS configuration
    runners: a non-empty vendor name followed by ``_configuration``. The
    measured floor rides along unconditionally, so an edit that drops those
    entries from the mirror cannot silently re-enable the frameworks this
    module exists to keep under control. Every name the floor or the mirror
    contributes exists in every checkov release the version constraint admits,
    which matters because checkov rejects an unknown ``--skip-framework`` value
    outright (checkov 3.4.5 main.py, ``normalize_framework_arg``:
    ``parser.error`` ends the run).
    """
    derived = {
        framework
        for framework in frameworks
        if framework.endswith(VCS_CONFIGURATION_SUFFIX)
        and framework != VCS_CONFIGURATION_SUFFIX
    }
    return tuple(sorted(derived.union(KNOWN_VCS_CONFIGURATION_FRAMEWORKS)))


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
