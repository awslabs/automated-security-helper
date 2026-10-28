# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config validate`` reads each config file from disk once.

The check's resolution reads each file (and keeps its text); the as-written
reference builder inside resolve_config_document re-read every file from disk
(config_sources._file_references -> read_config_file_as_written). Besides the
extra read, that opened a window: a file changed between the two reads gave
the record a document the resolution never saw. The builder now parses the
as-written view from the text the resolution read.
"""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from automated_security_helper.cli.main import app


def test_validate_reads_each_file_of_both_chains_once(tmp_path, monkeypatch):
    import automated_security_helper.config.config_sources as sources
    import automated_security_helper.config.config_validator as validator

    operator = tmp_path / "operator.yaml"
    operator.write_text("project_name: base\n", encoding="utf-8")
    base = tmp_path / "base.yaml"
    base.write_text("project_name: under\n", encoding="utf-8")
    config = tmp_path / "ash.yaml"
    config.write_text("extends: base.yaml\nproject_name: demo\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    monkeypatch.chdir(tmp_path / "src")
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    reads: dict[str, int] = {}
    real_text = sources.read_config_text

    def spy_text(path, *args, **kwargs):
        name = Path(path).name
        reads[name] = reads.get(name, 0) + 1
        return real_text(path, *args, **kwargs)

    monkeypatch.setattr(sources, "read_config_text", spy_text)
    # The validator imported the name into its own namespace.
    monkeypatch.setattr(validator, "read_config_text", spy_text)

    result = CliRunner().invoke(app, ["config", "validate", "--config", str(config)])

    assert result.exit_code == 0, result.output
    assert reads and all(count == 1 for count in reads.values()), reads
