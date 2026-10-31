# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of the detect-secrets scanner's settings and its worker exchange.

Each test pins one behavior the scanner lacked:

* a relative or empty ``sandbox.extra_read_paths`` entry became a root at the
  process's working directory for the baseline gate, which the sandbox policy
  itself never grants;
* ``baseline_file: ""`` resolved to the source directory, was chosen, failed as
  not a regular file and kept the tree's own ``.secrets.baseline`` out;
* the baseline was opened without ``O_NONBLOCK`` and decoded with the locale's
  encoding;
* a second ``_process_config_options`` pass kept the trust refusal, the resolved
  path and the parsed document of the first;
* naming ``scan_settings.version`` alone kept the baseline's plugins and filters
  from loading;
* a baseline's wordlist filter reached the worker with a relative file name it
  opened from its own empty working directory, and failed the scan;
* the tree's own baseline could name a word list of values to drop from the
  report, and the entry reached the worker unjudged by the settings-trust rule
  the verification filter and ``file://`` entries follow;
* a configured wordlist entry's relative name was anchored at the baseline's
  directory whenever the baseline's filters were loaded, not at the config
  file that wrote it;
* a word list name could reach any file the scanning user can read, through
  ``..``, an absolute name or a link, once its entry was trusted;
* a word list entry of a configuration read from the repository's own files
  was exempt from that confinement, as the operator's entries are, so the
  tree could name any regular file on the host as its word list;
* a non-string exclude pattern raised TypeError past the ``re.error`` handler;
* a request the scanner could not serialize was left part-written in the
  results directory;
* a worker run ASH could not record was graded as complete;
* the converted target's invocation record carried the source target's errors;
* a failed scan left ``end_time`` at the previous target's value;
* a config passed to ``scan()`` replaced the processed one, so default settings
  failed with "no detect-secrets plugins";
* the module's command line built the scanner without a context and raised.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.path_trust import OperatorPaths
from automated_security_helper.config.secret_verification_trust import (
    UntrustedDetectSecretsSettings,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    detect_secrets_scanner as module,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    SHOULD_EXCLUDE_FILE_FILTER,
    WORDLIST_FILTER,
    WORKER_REQUEST_FILE_NAME,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    (context.source_dir / "settings.py").write_text("value = 1\n", encoding="utf-8")
    return context


def _record_worker(scanner, monkeypatch) -> dict:
    seen: dict = {}

    def recorded(self, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(type(scanner), "_scan_in_worker", recorded)
    return seen


def _baseline(**fields) -> dict:
    return {"version": "1.5.0", "results": {}, **fields}


def _scanner(context, **options) -> DetectSecretsScanner:
    return DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(**options)
        ),
    )


# --------------------------------------------------------------------------- #
# The baseline gate reads extra_read_paths as the sandbox policy does
# --------------------------------------------------------------------------- #


def _sandboxed_outside_baseline(tmp_path, entries: list):
    context = _context(tmp_path)
    context.config.sandbox.mode = "bwrap"
    context.config.sandbox.read_path_scanners = ["detect-secrets"]
    context.config.sandbox.extra_read_paths = entries
    granted = tmp_path / "granted"
    granted.mkdir()
    baseline = granted / "baseline.json"
    baseline.write_text(json.dumps(_baseline()), encoding="utf-8")
    return _scanner(context, baseline_file=str(baseline))


def test_a_relative_or_empty_extra_read_path_grants_no_baseline(tmp_path, monkeypatch):
    """Resolved from the working directory, "granted" and "" covered the
    baseline; the sandbox mounts neither, so the gate read a file the worker
    could not."""
    monkeypatch.chdir(tmp_path)
    scanner = _sandboxed_outside_baseline(tmp_path, ["granted", ""])
    assert scanner._baseline_trust_refused is True
    assert scanner._baseline_in_use() is False


def test_an_absolute_extra_read_path_grants_the_baseline(tmp_path, monkeypatch):
    """Control: the policy's own reading admits an absolute entry."""
    monkeypatch.chdir(tmp_path)
    scanner = _sandboxed_outside_baseline(tmp_path, [str(tmp_path / "granted")])
    assert scanner._baseline_trust_refused is False
    assert scanner._baseline_in_use() is True


# --------------------------------------------------------------------------- #
# An empty baseline_file names nothing
# --------------------------------------------------------------------------- #


def test_an_empty_baseline_file_option_reads_as_unset(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    in_tree = context.source_dir / ".secrets.baseline"
    in_tree.write_text(json.dumps(_baseline()), encoding="utf-8")
    scanner = _scanner(context, baseline_file="")
    assert scanner._chosen_baseline == Path(os.path.realpath(in_tree))
    assert scanner._baseline_from_option is False
    assert scanner._baseline_in_use() is True


# --------------------------------------------------------------------------- #
# How the baseline is opened and decoded
# --------------------------------------------------------------------------- #


def test_the_baseline_is_opened_without_blocking_and_read_as_utf_8(
    tmp_path, monkeypatch
):
    document = _baseline(results={"café.py": []})
    path = tmp_path / "baseline.json"
    path.write_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))
    calls: dict = {}
    real_open, real_fdopen = os.open, os.fdopen

    def recording_open(name, flags, *args, **kwargs):
        calls["flags"] = flags
        return real_open(name, flags, *args, **kwargs)

    def recording_fdopen(fd, *args, **kwargs):
        calls["fdopen"] = kwargs
        return real_fdopen(fd, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", recording_open)
    monkeypatch.setattr(module.os, "fdopen", recording_fdopen)

    assert DetectSecretsScanner._read_baseline(path) == document
    if hasattr(os, "O_NONBLOCK"):
        assert calls["flags"] & os.O_NONBLOCK
    assert calls["fdopen"].get("encoding") == "utf-8"


# --------------------------------------------------------------------------- #
# A second pass starts from its own config
# --------------------------------------------------------------------------- #


def test_a_second_pass_resets_the_first_passs_baseline_records(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scanner = _scanner(_context(tmp_path))
    scanner._baseline_trust_refused = True
    scanner._baseline_real = tmp_path / "stale.json"
    scanner._baseline_document = _baseline()
    scanner._process_config_options()
    assert scanner._baseline_trust_refused is False
    assert scanner._baseline_real is None
    assert scanner._baseline_document is None


# --------------------------------------------------------------------------- #
# version alone does not switch the baseline's settings off
# --------------------------------------------------------------------------- #


def test_naming_a_version_still_loads_the_baselines_plugins_and_filters(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    (context.source_dir / ".secrets.baseline").write_text(
        json.dumps(
            _baseline(
                plugins_used=[{"name": "AWSKeyDetector"}],
                filters_used=[
                    {"path": "detect_secrets.filters.heuristic.is_likely_id_string"}
                ],
            )
        ),
        encoding="utf-8",
    )
    scanner = _scanner(
        context, scan_settings=DetectSecretsScanSettings(version="1.5.0")
    )
    settings = scanner.config.options.scan_settings
    assert [plugin.name for plugin in settings.plugins_used] == ["AWSKeyDetector"]
    assert "detect_secrets.filters.heuristic.is_likely_id_string" in [
        item.path for item in settings.filters_used
    ]
    assert settings.version == "1.5.0"


# --------------------------------------------------------------------------- #
# The wordlist filter reaches the worker only when the worker can apply it
# --------------------------------------------------------------------------- #


_WORDLIST_BASELINE = _baseline(
    plugins_used=[{"name": "AWSKeyDetector"}],
    filters_used=[{"path": WORDLIST_FILTER, "file_name": "words.txt"}],
)


def _wordlist_scanner(
    tmp_path, monkeypatch, *, words: bool, importable: bool, trusted: bool = True
):
    """A scanner whose baseline names a relative word list.

    ``trusted``: the baseline is the operator's, named by ``baseline_file`` and
    kept outside the scanned tree (``ops/``), with the word list beside it;
    otherwise it is the tree's own ``.secrets.baseline`` with the list in the
    tree.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "_module_importable", lambda name: importable)
    context = _context(tmp_path)
    if trusted:
        home = tmp_path / "ops"
        home.mkdir()
        baseline = home / "baseline.json"
    else:
        home = context.source_dir
        baseline = home / ".secrets.baseline"
    if words:
        (home / "words.txt").write_text("AKIATEST\n", encoding="utf-8")
    baseline.write_text(json.dumps(_WORDLIST_BASELINE), encoding="utf-8")
    if trusted:
        return _scanner(context, baseline_file=str(baseline))
    return _scanner(context)


def _wordlist_entries(scanner) -> list:
    return [
        item
        for item in scanner.config.options.scan_settings.filters_used
        if item.path == WORDLIST_FILTER
    ]


def _handed_wordlists(scanner, monkeypatch) -> list:
    """The word lists the worker request names; none when every filter was refused.

    The request's settings are ``model_dump(exclude_defaults=True)``, which drops
    an empty ``filters_used``, and the scanner puts the key back only when its own
    list is not empty, so a request left with no filter has no key at all.
    """
    seen = _record_worker(scanner, monkeypatch)
    scanner.scan(target=scanner.context.source_dir, target_type="source")
    return [
        item["file_name"]
        for item in seen["scan_settings_dict"].get("filters_used", [])
        if item["path"] == WORDLIST_FILTER
    ]


def test_a_relative_word_list_is_anchored_at_the_baseline_and_handed_over(
    tmp_path, monkeypatch
):
    scanner = _wordlist_scanner(tmp_path, monkeypatch, words=True, importable=True)
    (entry,) = _wordlist_entries(scanner)
    expected = Path(os.path.realpath(tmp_path / "ops" / "words.txt"))
    assert entry.file_name == expected.as_posix()
    assert entry.min_length == 3
    assert entry.file_hash == ""
    assert _handed_wordlists(scanner, monkeypatch) == [expected.as_posix()]


def test_an_untrusted_baselines_word_list_is_refused_before_it_is_read(
    tmp_path, monkeypatch, caplog
):
    """The tree's own baseline named a list of values to drop from the report;
    the entry was anchored at the baseline, admitted on the file being there,
    and handed to the worker. It is refused as the verification filter is."""
    with caplog.at_level(logging.WARNING):
        scanner = _wordlist_scanner(
            tmp_path, monkeypatch, words=True, importable=True, trusted=False
        )
    assert _wordlist_entries(scanner) == []
    assert "Ignoring the detect-secrets wordlist filter" in caplog.text
    assert "inside the scanned directory" in caplog.text
    assert "words.txt" not in caplog.text
    assert _handed_wordlists(scanner, monkeypatch) == []


def _configured_wordlist_scanner(tmp_path, monkeypatch, *, config_file: bool):
    """A config-written wordlist entry beside the tree's own baseline, whose
    filters are loaded beside it. With ``config_file`` the config was read from
    ``<tmp>/cfg/ash.yaml`` and the list sits beside that file; otherwise the
    config has no file and the list sits in the source directory."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "_module_importable", lambda name: True)
    context = _context(tmp_path)
    if config_file:
        cfg = tmp_path / "cfg"
        cfg.mkdir()
        context.config._loaded_from = cfg / "ash.yaml"
        home = cfg
    else:
        home = context.source_dir
    (home / "words.txt").write_text("AKIATEST\n", encoding="utf-8")
    (context.source_dir / ".secrets.baseline").write_text(
        json.dumps(_WORDLIST_BASELINE), encoding="utf-8"
    )
    scanner = _scanner(
        context,
        scan_settings=DetectSecretsScanSettings(
            filters_used=[{"path": WORDLIST_FILTER, "file_name": "words.txt"}]
        ),
    )
    return scanner, Path(os.path.realpath(home / "words.txt"))


def test_the_operators_own_word_list_entry_is_kept_beside_an_untrusted_baseline(
    tmp_path, monkeypatch
):
    """Judged by the entry's source, not by which baseline is in use: the
    operator's configured entry stays, anchored at the source directory when
    the config was not read from a file."""
    scanner, expected = _configured_wordlist_scanner(
        tmp_path, monkeypatch, config_file=False
    )
    (entry,) = _wordlist_entries(scanner)
    assert entry.file_name == expected.as_posix()
    assert _handed_wordlists(scanner, monkeypatch) == [expected.as_posix()]


def _trusted_scanner_naming(tmp_path, monkeypatch, file_name: str):
    """The operator's baseline at ``<tmp>/ops/baseline.json`` naming
    ``file_name`` as its word list; ``<tmp>/secret/words.txt`` exists outside
    both the baseline's directory and the scanned tree."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "_module_importable", lambda name: True)
    context = _context(tmp_path)
    (tmp_path / "ops").mkdir()
    (tmp_path / "secret").mkdir()
    (tmp_path / "secret" / "words.txt").write_text("AKIATEST\n", encoding="utf-8")
    baseline = tmp_path / "ops" / "baseline.json"
    baseline.write_text(
        json.dumps(
            _baseline(
                plugins_used=[{"name": "AWSKeyDetector"}],
                filters_used=[{"path": WORDLIST_FILTER, "file_name": file_name}],
            )
        ),
        encoding="utf-8",
    )
    return _scanner(context, baseline_file=str(baseline))


def test_a_word_list_that_leaves_its_anchor_with_dot_dot_is_refused(
    tmp_path, monkeypatch, caplog
):
    """A trusted entry still may not reach a file outside the directory that
    named it and outside the scanned tree: the file is there, and refused."""
    with caplog.at_level(logging.WARNING):
        scanner = _trusted_scanner_naming(tmp_path, monkeypatch, "../secret/words.txt")
    assert _wordlist_entries(scanner) == []
    assert "resolves outside the directory of the file that named the entry" in (
        caplog.text
    )
    assert "words.txt" not in caplog.text


def test_an_absolute_word_list_outside_the_anchor_and_the_tree_is_refused(
    tmp_path, monkeypatch, caplog
):
    with caplog.at_level(logging.WARNING):
        scanner = _trusted_scanner_naming(
            tmp_path, monkeypatch, str(tmp_path / "secret" / "words.txt")
        )
    assert _wordlist_entries(scanner) == []
    assert "resolves outside the directory of the file that named the entry" in (
        caplog.text
    )


def test_a_link_out_of_the_anchor_is_refused_by_what_it_resolves_to(
    tmp_path, monkeypatch, caplog
):
    """The name stays inside the baseline's directory; the file it resolves to
    does not. The link is laid before the scanner reads the baseline."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "_module_importable", lambda name: True)
    context = _context(tmp_path)
    (tmp_path / "ops").mkdir()
    (tmp_path / "secret").mkdir()
    (tmp_path / "secret" / "words.txt").write_text("AKIATEST\n", encoding="utf-8")
    try:
        os.symlink(tmp_path / "secret" / "words.txt", tmp_path / "ops" / "words.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links cannot be made here")
    baseline = tmp_path / "ops" / "baseline.json"
    baseline.write_text(json.dumps(_WORDLIST_BASELINE), encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        scanner = _scanner(context, baseline_file=str(baseline))
    assert _wordlist_entries(scanner) == []
    assert "resolves outside the directory of the file that named the entry" in (
        caplog.text
    )


def test_an_absolute_word_list_inside_the_anchor_is_kept(tmp_path, monkeypatch):
    """Control: the confinement is on where the file resolves, not on the
    spelling; an absolute name inside the baseline's directory is admitted."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "_module_importable", lambda name: True)
    context = _context(tmp_path)
    (tmp_path / "ops").mkdir()
    words = tmp_path / "ops" / "words.txt"
    words.write_text("AKIATEST\n", encoding="utf-8")
    baseline = tmp_path / "ops" / "baseline.json"
    baseline.write_text(
        json.dumps(
            _baseline(
                plugins_used=[{"name": "AWSKeyDetector"}],
                filters_used=[{"path": WORDLIST_FILTER, "file_name": str(words)}],
            )
        ),
        encoding="utf-8",
    )
    scanner = _scanner(context, baseline_file=str(baseline))
    (entry,) = _wordlist_entries(scanner)
    expected = Path(os.path.realpath(words))
    assert entry.file_name == expected.as_posix()
    assert _handed_wordlists(scanner, monkeypatch) == [expected.as_posix()]


def test_a_configured_word_list_is_anchored_at_the_config_file_not_the_baseline(
    tmp_path, monkeypatch
):
    """A relative name is taken from the directory of the file that wrote the
    entry, per entry: the config's list sits beside the config file, and the
    baseline's filters being loaded beside it does not move it."""
    scanner, expected = _configured_wordlist_scanner(
        tmp_path, monkeypatch, config_file=True
    )
    (entry,) = _wordlist_entries(scanner)
    assert entry.file_name == expected.as_posix()
    assert expected.parent == Path(os.path.realpath(tmp_path / "cfg"))
    assert _handed_wordlists(scanner, monkeypatch) == [expected.as_posix()]


def _operator_scanner_naming(tmp_path, monkeypatch, file_name: str, *, config_file):
    """The operator's own config names ``file_name`` as its word list; the file
    sits at ``<tmp>/secret/words.txt``, outside the scanned tree and outside
    the directory of the config file (``<tmp>/cfg/ash.yaml``) when there is one."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "_module_importable", lambda name: True)
    context = _context(tmp_path)
    (tmp_path / "secret").mkdir()
    (tmp_path / "secret" / "words.txt").write_text("AKIATEST\n", encoding="utf-8")
    if config_file:
        (tmp_path / "cfg").mkdir()
        context.config._loaded_from = tmp_path / "cfg" / "ash.yaml"
    return _scanner(
        context,
        scan_settings=DetectSecretsScanSettings(
            filters_used=[{"path": WORDLIST_FILTER, "file_name": file_name}]
        ),
    )


def test_the_operators_absolute_word_list_outside_the_tree_is_kept(
    tmp_path, monkeypatch
):
    """An operator's config naming an absolute list on the host worked before
    the confinement; the confinement is for what a baseline supplies."""
    words = tmp_path / "secret" / "words.txt"
    scanner = _operator_scanner_naming(
        tmp_path, monkeypatch, str(words), config_file=False
    )
    (entry,) = _wordlist_entries(scanner)
    expected = Path(os.path.realpath(words))
    assert entry.file_name == expected.as_posix()
    assert _handed_wordlists(scanner, monkeypatch) == [expected.as_posix()]


def test_the_operators_relative_word_list_may_leave_its_config_files_directory(
    tmp_path, monkeypatch
):
    scanner = _operator_scanner_naming(
        tmp_path, monkeypatch, "../secret/words.txt", config_file=True
    )
    (entry,) = _wordlist_entries(scanner)
    expected = Path(os.path.realpath(tmp_path / "secret" / "words.txt"))
    assert entry.file_name == expected.as_posix()


def _operator_document_naming(file_name):
    """The operator's trusted base config, as ``resolve_config`` records it in
    ``AshConfig._operator_paths``, naming ``file_name`` as a word list."""
    return {
        "scanners": {
            "detect_secrets": {
                "options": {
                    "scan_settings": {
                        "filters_used": [
                            {"path": WORDLIST_FILTER, "file_name": file_name}
                        ]
                    }
                }
            }
        }
    }


def _repository_written_scanner_naming(
    tmp_path, monkeypatch, file_name, *, operator_names=None, config_file=False
):
    """A configuration read from the repository's own files (the record
    resolve_config leaves on it) names ``file_name`` as its word list; no
    baseline is in use. ``<tmp>/secret/words.txt`` lies outside the scanned
    tree, and the scanned tree holds ``words.txt`` too. ``operator_names`` is
    a word list the operator's own config names as well (the trusted base the
    record keeps in ``_operator_paths``), or None for no such record."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(module, "_module_importable", lambda name: True)
    context = _context(tmp_path)
    (tmp_path / "secret").mkdir(exist_ok=True)
    (tmp_path / "secret" / "words.txt").write_text("AKIATEST\n", encoding="utf-8")
    (context.source_dir / "words.txt").write_text("AKIATEST\n", encoding="utf-8")
    if config_file:
        (tmp_path / "cfg").mkdir()
        context.config._loaded_from = tmp_path / "cfg" / "ash.yaml"
    if operator_names is not None:
        context.config._operator_paths = OperatorPaths(
            documents=[_operator_document_naming(operator_names)]
        )
    context.config._untrusted_detect_secrets_settings = UntrustedDetectSecretsSettings(
        reason="the configuration was read from the scanned repository"
    )
    return _scanner(
        context,
        scan_settings=DetectSecretsScanSettings(
            filters_used=[{"path": WORDLIST_FILTER, "file_name": file_name}]
        ),
    )


def test_a_repository_written_configs_word_list_outside_the_tree_is_refused(
    tmp_path, monkeypatch, caplog
):
    """The operator's own entry may name a list anywhere on the host; an entry
    of a configuration the repository wrote may not, or the tree would choose
    which host file the worker reads and which findings leave the report."""
    outside = tmp_path / "secret" / "words.txt"
    with caplog.at_level(logging.WARNING):
        scanner = _repository_written_scanner_naming(
            tmp_path, monkeypatch, str(outside)
        )
    assert _wordlist_entries(scanner) == []
    assert "Ignoring the detect-secrets wordlist filter" in caplog.text
    assert "resolves outside the directory of the file that named the entry" in (
        caplog.text
    )
    assert "words.txt" not in caplog.text
    assert _handed_wordlists(scanner, monkeypatch) == []


def test_a_repository_written_configs_word_list_inside_the_tree_is_kept(
    tmp_path, monkeypatch
):
    """Control: the confinement is on where the file resolves; a list the
    scanned tree holds was accepted before and still is."""
    scanner = _repository_written_scanner_naming(tmp_path, monkeypatch, "words.txt")
    (entry,) = _wordlist_entries(scanner)
    expected = Path(os.path.realpath(tmp_path / "src" / "words.txt"))
    assert entry.file_name == expected.as_posix()


def test_the_operators_absolute_word_list_survives_a_repository_config_beside_it(
    tmp_path, monkeypatch
):
    """The repository commits a config, so the record is set; the operator's own
    config names an absolute list on the host. The merged entry is the
    operator's list, and it is kept, not refused with the repository's."""
    outside = tmp_path / "secret" / "words.txt"
    scanner = _repository_written_scanner_naming(
        tmp_path, monkeypatch, str(outside), operator_names=str(outside)
    )
    (entry,) = _wordlist_entries(scanner)
    expected = Path(os.path.realpath(outside))
    assert entry.file_name == expected.as_posix()
    assert _handed_wordlists(scanner, monkeypatch) == [expected.as_posix()]


def test_a_repository_config_cannot_borrow_the_operators_word_list_exemption(
    tmp_path, monkeypatch, caplog
):
    """The operator's config names one list; the repository's entry names a
    different one outside the tree. The exemption is for the operator's name
    only, so the repository's entry is refused."""
    operators = tmp_path / "secret" / "words.txt"
    other = tmp_path / "secret" / "other-words.txt"
    other.parent.mkdir(exist_ok=True)
    other.write_text("AKIATEST\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        scanner = _repository_written_scanner_naming(
            tmp_path, monkeypatch, str(other), operator_names=str(operators)
        )
    assert _wordlist_entries(scanner) == []
    assert "resolves outside the directory of the file that named the entry" in (
        caplog.text
    )


def test_a_relative_word_list_the_operator_also_names_is_still_confined(
    tmp_path, monkeypatch, caplog
):
    """A relative name is anchored at the config file's directory, which is the
    repository's when its config was read, so the operator naming the same text
    does not exempt it."""
    with caplog.at_level(logging.WARNING):
        scanner = _repository_written_scanner_naming(
            tmp_path,
            monkeypatch,
            "../secret/words.txt",
            operator_names="../secret/words.txt",
            config_file=True,
        )
    assert _wordlist_entries(scanner) == []
    assert "resolves outside the directory of the file that named the entry" in (
        caplog.text
    )


def test_a_word_list_that_is_not_there_drops_the_filter_with_a_warning(
    tmp_path, monkeypatch, caplog
):
    with caplog.at_level(logging.WARNING):
        scanner = _wordlist_scanner(tmp_path, monkeypatch, words=False, importable=True)
    assert _wordlist_entries(scanner) == []
    assert "Ignoring the detect-secrets wordlist filter" in caplog.text
    assert "words.txt" not in caplog.text


def test_a_missing_wordlist_package_drops_the_filter(tmp_path, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        scanner = _wordlist_scanner(tmp_path, monkeypatch, words=True, importable=False)
    assert _wordlist_entries(scanner) == []
    assert "pyahocorasick" in caplog.text


# --------------------------------------------------------------------------- #
# Exclude patterns that are not strings
# --------------------------------------------------------------------------- #


def test_a_non_string_exclude_pattern_is_skipped_not_raised():
    patterns = DetectSecretsScanner._get_baseline_exclude_patterns(
        {
            "filters_used": [
                {"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": [5, "^tests/"]}
            ]
        }
    )
    assert [pattern.pattern for pattern in patterns] == ["^tests/"]


def test_a_pattern_field_that_is_not_a_list_excludes_nothing():
    assert (
        DetectSecretsScanner._get_baseline_exclude_patterns(
            {"filters_used": [{"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": 7}]}
        )
        == []
    )


# --------------------------------------------------------------------------- #
# The worker exchange
# --------------------------------------------------------------------------- #


def test_a_request_that_cannot_be_written_leaves_no_file_behind(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    scanner = _scanner(context)
    work_dir = Path(scanner.results_dir) / "source"
    work_dir.mkdir(parents=True)
    with pytest.raises(TypeError):
        scanner._scan_in_worker(
            baseline=None,
            scan_paths=[str(context.source_dir / "settings.py")],
            scan_settings_dict={"plugins_used": [object()]},
            work_dir=work_dir,
            scan_timeout=None,
        )
    assert not (work_dir / WORKER_REQUEST_FILE_NAME).exists()


def test_a_run_ash_could_not_record_fails_the_scan(tmp_path, monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    scanner = _scanner(context)

    def unrecorded(**kwargs):
        return {
            "returncode": 0,
            "post_run_error": True,
            "error": "the stderr log could not be written",
        }

    monkeypatch.setattr(
        subprocess_utils, "run_command_with_output_handling", unrecorded
    )
    with pytest.raises(ScannerError, match="could not record"):
        scanner.scan(target=context.source_dir, target_type="source")


def test_the_invocation_record_holds_only_this_targets_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    scanner = _scanner(context)
    scanner.errors.append("the previous target failed")
    _record_worker(scanner, monkeypatch)
    report = scanner.scan(target=context.source_dir, target_type="source")
    assert isinstance(report, SarifReport)
    assert report.runs[0].invocations[0].exitCodeDescription == ""


def test_a_failed_scan_records_its_end_time(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    scanner = _scanner(context)

    def failing(self, **kwargs):
        raise RuntimeError("the worker died")

    monkeypatch.setattr(DetectSecretsScanner, "_scan_in_worker", failing)
    with pytest.raises(ScannerError):
        scanner.scan(target=context.source_dir, target_type="source")
    assert scanner.end_time is not None
    assert scanner.end_time >= scanner.start_time


def test_a_config_passed_to_scan_is_processed_before_it_is_used(tmp_path, monkeypatch):
    """The base swaps the config in; this scanner's settings come from processing
    it, so a default config arrived with no plugins and the scan refused."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    scanner = _scanner(context)
    seen = _record_worker(scanner, monkeypatch)
    scanner.scan(
        target=context.source_dir,
        target_type="source",
        config=DetectSecretsScannerConfig(),
    )
    assert seen["scan_settings_dict"]["plugins_used"]


# --------------------------------------------------------------------------- #
# The module's own command line
# --------------------------------------------------------------------------- #


def test_the_module_command_line_scans_its_working_directory(tmp_path, monkeypatch):
    project = tmp_path / "project"
    project.mkdir()
    (project / "settings.py").write_text("value = 1\n", encoding="utf-8")
    monkeypatch.chdir(project)
    seen: dict = {}

    def recorded(self, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(DetectSecretsScanner, "_scan_in_worker", recorded)
    report = module._main(project)
    assert isinstance(report, SarifReport)
    assert any(path.endswith("settings.py") for path in seen["scan_paths"])
