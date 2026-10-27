"""The operator-only gate resolves override keys with the caller's values.

Both confinement walks (the reporters options and the scanner options) resolve
each override segment through the shared resolver. The resolver's respelling
refusal redacts section keys read from the environment only with the caller's
environment values, and the gate's answer must reach the caller with the
arguments in their declared places: a value landing in another parameter's
slot turns the gate off silently.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.operator_only_options import (
    RepositorySettings,
    _confine_scanner_options,
    confine_operator_only_options,
)
from automated_security_helper.config.resolve_config import load_config_file_for_run
from automated_security_helper.core.exceptions import ASHConfigValidationError

VAR = "ASH_OO_SECT"
VALUE = "env-oo-sect"


def _loaded(tmp_path, text, repository, config_overrides=None):
    """The config a scan of *tmp_path* loads from its file, with what that file
    wrote for an operator-only option recorded on *repository*, as a scan
    records it."""
    path = tmp_path / "ash.yaml"
    path.write_text(text, encoding="utf-8")
    return load_config_file_for_run(
        path, confine=repository.confine, config_overrides=config_overrides
    )[1]


def test_the_scanners_gate_refusal_names_no_env_value(tmp_path, monkeypatch):
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR, VALUE)
    repository = RepositorySettings([tmp_path])
    config = _loaded(
        tmp_path,
        "project_name: t\n"
        "scanners:\n"
        "  detect-secrets:\n"
        "    options:\n"
        "      max_worker_output_mib: 7\n"
        f"  ${{{VAR}}}:\n"
        "    enabled: true\n",
        repository,
    )
    # The control: the file's write is recorded, so the gate resolves the
    # override's segments for it.
    assert repository.written("scanners"), repository.written("scanners")
    with pytest.raises(ASHConfigValidationError) as refused:
        _confine_scanner_options(
            config, AshConfig(), ["scanners.EnvOoSect.options.x=1"], repository
        )
    assert VALUE not in str(refused.value), str(refused.value)


def test_the_reporters_gate_counts_an_operator_override(tmp_path, monkeypatch):
    """An override that writes an operator-only reporter option is the
    operator's and is kept; a gate whose arguments shifted out of their slots
    answers False for every override, so the option is silently dropped."""
    from automated_security_helper.config.ash_config import AshConfig

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    override = "reporters.aws-security-hub.options.findings_scope=suppressed"
    repository = RepositorySettings([tmp_path])
    config = _loaded(
        tmp_path,
        "project_name: t\n"
        "reporters:\n"
        "  aws-security-hub:\n"
        "    enabled: true\n"
        "    options:\n"
        "      findings_scope: suppressed\n",
        repository,
        config_overrides=[override],
    )
    # The control: the file's write is recorded, so the gate settles it.
    assert repository.written("reporters"), repository.written("reporters")
    confine_operator_only_options(
        config,
        AshConfig(),
        [override],
        in_tree=[],
        repository=repository,
        checkout_membership=False,
        mixed_membership=False,
        given_root_membership=False,
        undecided_membership=False,
    )
    section = (config.reporters.model_extra or {})["aws-security-hub"]
    assert section.get("options", {}).get("findings_scope") == "suppressed", section
