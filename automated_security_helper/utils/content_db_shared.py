# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the content database refresh and its staleness probes share.

``utils/content_db_refresh.py`` runs grype's and trivy's database updates, and
``utils/content_db_staleness.py`` runs their status commands. The markdown, text
and flat-json reporters reach the staleness module, so it may not import the
refresh module: that would put the database updates in a reporter's import graph
(tests/unit/config/test_off_host_plugin_modules_from_repo_config.py). Both import
what they share from here instead.

Standard library only, so a module that imports it reaches nothing else.
"""

from pathlib import Path

#: An empty file, shipped with ASH, passed as the config file of every grype and
#: trivy command ASH runs on a scan's behalf (the refresh and the staleness
#: probes), so the tool reads no config of its own finding: not ``trivy.yaml``,
#: ``.grype.yaml`` or ``.grype/config.yaml`` in its working directory, nor one
#: under the home directory. In ASH's package because every sandbox backend
#: mounts that read-only (``sandbox.policy._ash_paths``) and a probe runs inside
#: the scanner's sandbox, where a file in a temporary directory would not be
#: visible and one in the results directory would be writable by the scanner. An
#: empty file rather than trivy's ``--config ""``, which disables loading only
#: from trivy 0.75.0 (pkg/commands/app.go initConfig; 0.74.0 and earlier fail on
#: it).
EMPTY_TOOL_CONFIG = Path(__file__).resolve().with_name("empty-tool-config.yaml")
