# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan tool's config pre-check resolves the chain the scan loads.

The pre-check reads the selected config's chain once, before the scan is
registered, and its environment values are attached to the scan's registry
entry as the redaction set for every failure surface. The scan's own load
reads the same chain with the scanned repository's settings: what a
repository file writes for the operator-only options is left out, and an
operator file's patch pointers fold against the section keys the operator's
own files wrote. Resolved without those settings, a chain the scan loads can
raise only in the pre-check -- an operator file's pointer that a
repository-written case-variant twin makes ambiguous stays as typed and fits
nothing -- and the pre-check swallows resolution refusals, so the scan would
run while the redaction set silently lacked the chain's values.

The cell builds exactly that chain. An operator config outside the scanned
tree extends an operator base, which reads a value from the environment, and
a repository file inside the tree, which writes a case-variant twin of the
base's reporter section; the config's own patch names that section in a
third spelling. The section name is no declared plugin's, so the merge keeps
the two spellings apart -- a declared name folds onto the plugin's one key as
the chain merges, and no twin survives for a pointer to be ambiguous
against. The scan-side read is the control on the premise: with the
repository settings, the pointer folds onto the key the operator's own base
wrote and the chain loads with the value. The pre-check must answer with the
same value and no refusal.
"""

import pytest

pytestmark = pytest.mark.unit

_VALUE = "a-chain-value-the-pre-check-must-keep"


def test_a_chain_the_scan_loads_keeps_its_values_in_the_pre_check(
    tmp_path, monkeypatch
):
    from automated_security_helper.cli.mcp_tools import _config_pre_check
    from automated_security_helper.config.config_sources import (
        default_confinement_root,
        resolve_config_document,
    )
    from automated_security_helper.config.operator_only_options import (
        RepositorySettings,
    )
    from automated_security_helper.config.sandbox_grants import scanned_trees

    # Local-caller mode, as the sibling get_config cells run: no scan roots, no
    # shared workspace, so the base gate permits the chain and nothing here is a
    # client-delivered file. The named config sits in a configured config root,
    # so it is the operator's: the scan reads a named file the operator did not
    # set aside with every chain file confined (client_named_config_is_untrusted),
    # and the control below reads with the repository's settings only.
    operator = tmp_path / "operator"
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.setenv("ASH_PRE_CHECK_CELL", _VALUE)

    source = operator / "repo"
    source.mkdir(parents=True)
    # The repository's file writes a case-variant twin of the operator's
    # section key. The name is no declared plugin's, so deep_merge keeps the
    # two spellings apart, and a pointer fold over every key finds two
    # matches where a fold over the operator's own writes finds one.
    (source / "twin.ash.yaml").write_text(
        "reporters:\n  ACME:\n    options: {}\n",
        encoding="utf-8",
    )
    (operator / "base.ash.yaml").write_text(
        "reporters:\n"
        "  acme:\n"
        "    options:\n"
        "      output_file: ${ASH_PRE_CHECK_CELL:unset}\n",
        encoding="utf-8",
    )
    config = operator / "ash.yaml"
    config.write_text(
        "extends:\n"
        "  - base.ash.yaml\n"
        "  - repo/twin.ash.yaml\n"
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/Acme/options/output_file\n"
        "    value: pinned-by-the-cell\n",
        encoding="utf-8",
    )

    # Control on the premise: read with the scan's own settings, the pointer
    # folds onto the key the operator's base wrote, and the chain loads with
    # the value the base read from the environment.
    settings = RepositorySettings(scanned_trees(source))
    scan_read = resolve_config_document(
        config,
        confine_to=default_confinement_root(config, source),
        confine=settings.confine,
        repository_file=settings.is_repository_file,
    )
    assert _VALUE in tuple(scan_read.environment_values)
    assert scan_read.data["reporters"]["acme"]["options"] == {
        "output_file": "pinned-by-the-cell"
    }

    pre_check = _config_pre_check(config, source, None)
    assert pre_check.env_refusal is None
    assert pre_check.load_refusal is None
    # Resolved without the scan's settings, the pointer stayed as typed, the
    # refusal was swallowed, and the values came back empty: the scan then
    # runs while the redaction set lacks the value the control read.
    assert _VALUE in pre_check.environment_values
