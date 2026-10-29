# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``validate_config`` judges the runtime-override policy of the documents it validated.

The validator reads the named file and every base its ``extends`` chain reaches
once and holds what it read (``ConfigCheck.documents``, ``names`` and ``texts``).
The policy check runs on those documents and reads no file a second time, so the
verdict is never one file's validation beside another file's policy. A file
rewritten in place (same inode, which no identity check can tell from the file
that was read) or replaced after the validator read it changes nothing about the
answer.

Every cell edits the file inside a stand-in for the validator's check, after the
real check returned, so the edit lands between the validation and the policy
check.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_all_session_state,
    clear_profile_registry,
)
from automated_security_helper.cli.mcp_tools import (
    _validated_document_denials,
    mcp_validate_config,
)
from automated_security_helper.config import config_sources
from automated_security_helper.config.config_validator import (
    ConfigCheck,
    ConfigValidator,
)

REMOTE = "client-1"
PROBE_VAR = "ASH_ENV_PROBE"
PROBE = "probe-value-7f3a"
CLEAN = "project_name: clean-text\n"
DENIED = "project_name: denied-text\nfail_on_findings: false\n"
# A word the test's temporary directory does not hold, so an answer that quotes
# the denied file is told from one that does not.
DENIED_MARK = "denied-text"
# A bidirectional override, then an ESC, then an SGR sequence: text no reply line
# may carry as it is.
HOSTILE = "a" + chr(0x202E) + "b" + chr(0x1B) + "[31mc"
ENV_REFUSED = "config_env_not_resolved"


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan_root = tmp_path / "scan-root"
    (scan_root / "repo").mkdir(parents=True)
    operator = tmp_path / "operator"
    operator.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "workspaces"))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(operator))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.setenv(PROBE_VAR, PROBE)
    clear_profile_registry()
    clear_all_session_state()
    yield {"repo": scan_root / "repo", "operator": operator}
    clear_profile_registry()
    clear_all_session_state()


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _types(result: Dict[str, Any]) -> List[str]:
    return [error["type"] for error in result["errors"]]


def _after_the_validator_reads(monkeypatch, action: Callable[[], None]) -> list:
    """Run `action` right after the validator's check of the file returns.

    That is the window between the validation and the policy check. Returns the
    checks the validator made, so a cell can show its premise: the validator
    read the file.
    """
    real = ConfigValidator.check_config_file
    checks: list = []

    def check_then_act(*args, **kwargs):
        result = real(*args, **kwargs)
        checks.append(result)
        action()
        return result

    monkeypatch.setattr(
        ConfigValidator, "check_config_file", staticmethod(check_then_act)
    )
    return checks


def _rewrite_in_place(path: Path, text: str) -> Callable[[], None]:
    """Rewrite `path` through the same inode, as a writer holding the file open would."""

    def rewrite() -> None:
        inode = os.stat(path).st_ino
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        assert os.stat(path).st_ino == inode, "premise: the same file was rewritten"

    return rewrite


def _replace_with_a_new_file(path: Path, text: str) -> Callable[[], None]:
    def replace() -> None:
        replacement = path.with_name(path.name + ".new")
        replacement.write_text(text, encoding="utf-8")
        os.replace(replacement, path)

    return replace


REWRITES = [
    pytest.param(_rewrite_in_place, id="in-place"),
    pytest.param(_replace_with_a_new_file, id="new-file"),
]


class TestTheVerdictIsMadeOfTheBytesTheValidatorRead:
    @pytest.mark.parametrize("rewrite", REWRITES)
    def test_a_clean_file_rewritten_with_a_denied_field_is_valid(
        self, _server, monkeypatch, rewrite
    ):
        named = _write(_server["repo"] / "ash.yaml", CLEAN)
        checks = _after_the_validator_reads(monkeypatch, rewrite(named, DENIED))

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert checks and checks[0].scan_accepts, "premise: the validator accepted"
        assert result["errors"] == [], result
        assert result["valid"] is True, result
        assert DENIED_MARK not in json.dumps(result), result

    @pytest.mark.parametrize("rewrite", REWRITES)
    def test_a_denied_file_rewritten_clean_is_still_denied(
        self, _server, monkeypatch, rewrite
    ):
        named = _write(_server["repo"] / "ash.yaml", DENIED)
        checks = _after_the_validator_reads(monkeypatch, rewrite(named, CLEAN))

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert checks, "premise: the validator read the file"
        assert result["valid"] is False, result
        assert _types(result) == ["denied_by_runtime_policy"], result
        assert result["errors"][0]["field"] == "fail_on_findings", result

    @pytest.mark.parametrize("rewrite", REWRITES)
    def test_a_base_rewritten_after_the_validator_read_it_is_not_judged_in_its_place(
        self, _server, monkeypatch, rewrite
    ):
        base = _write(_server["repo"] / "base.yaml", CLEAN)
        child = _write(_server["repo"] / "ash.yaml", "extends: base.yaml\n")
        checks = _after_the_validator_reads(monkeypatch, rewrite(base, DENIED))

        result = mcp_validate_config(config_path=str(child), session_id=REMOTE)

        assert checks and checks[0].scan_accepts, "premise: the validator accepted"
        assert result["errors"] == [], result
        assert result["valid"] is True, result

    def test_a_file_removed_after_the_validator_read_it_is_judged_as_it_was_read(
        self, _server, monkeypatch
    ):
        named = _write(_server["repo"] / "ash.yaml", DENIED)
        checks = _after_the_validator_reads(monkeypatch, named.unlink)

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert checks, "premise: the validator read the file"
        assert _types(result) == ["denied_by_runtime_policy"], result

    def test_control_a_file_nothing_changes_in_is_judged(self, _server, monkeypatch):
        named = _write(_server["repo"] / "ash.yaml", DENIED)
        checks = _after_the_validator_reads(monkeypatch, lambda: None)

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert checks, "premise: the validator read the file"
        assert _types(result) == ["denied_by_runtime_policy"], result

    def test_control_a_clean_chain_nothing_changes_in_is_valid(
        self, _server, monkeypatch
    ):
        _write(_server["repo"] / "base.yaml", CLEAN)
        child = _write(_server["repo"] / "ash.yaml", "extends: base.yaml\n")
        checks = _after_the_validator_reads(monkeypatch, lambda: None)

        result = mcp_validate_config(config_path=str(child), session_id=REMOTE)

        assert checks and checks[0].scan_accepts, "premise: the validator accepted"
        assert result["errors"] == [], result
        assert result["valid"] is True, result

    def test_the_policy_check_reads_no_file_of_the_chain(self, _server, monkeypatch):
        """The held documents are all the check needs: a read of a file of the
        chain after the validator's check returns is a second read."""
        base = _write(_server["repo"] / "base.yaml", CLEAN)
        child = _write(_server["repo"] / "ash.yaml", "extends: base.yaml\n")
        chain = {base.resolve(), child.resolve()}
        opened: list = []
        real = config_sources.read_config_bytes

        def counting(path, *args, **kwargs):
            opened.append(Path(path).resolve())
            return real(path, *args, **kwargs)

        checks = _after_the_validator_reads(
            monkeypatch,
            lambda: monkeypatch.setattr(config_sources, "read_config_bytes", counting),
        )

        result = mcp_validate_config(config_path=str(child), session_id=REMOTE)

        assert checks and checks[0].scan_accepts, "premise: the validator accepted"
        assert result["valid"] is True, result
        assert chain.isdisjoint(opened), opened


class TestTheCheckHoldsWhatItRead:
    def test_the_check_holds_the_documents_and_texts_of_a_chain(self, tmp_path):
        base = _write(tmp_path / "base.yaml", CLEAN)
        child = _write(tmp_path / ".ash.yaml", "extends: base.yaml\n")

        check = ConfigValidator.check_config_file(child, source_dir=tmp_path)

        assert check.scan_accepts, check.errors
        assert set(check.documents) == {base.resolve(), child.resolve()}
        assert check.texts[base.resolve()] == CLEAN
        assert check.texts[child.resolve()] == "extends: base.yaml\n"
        # The names a file was reached by, kept for the policy check. A file
        # reached only by its own resolved path has no entry, and the readers of
        # the names take a missing entry as "no name but its own path", so the
        # root here (passed by its resolved path) is not listed. The base is, with
        # the file that named it, which chose it.
        assert set(check.document_names) <= set(check.documents)
        assert child.resolve() in check.document_names[base.resolve()]

    def test_a_check_that_resolved_no_chain_holds_nothing(self, tmp_path):
        child = _write(tmp_path / ".ash.yaml", "extends: missing.yaml\n")

        check = ConfigValidator.check_config_file(child, source_dir=tmp_path)

        assert not check.scan_accepts
        assert check.documents == {}

    def test_control_a_check_the_model_refused_still_holds_its_documents(
        self, tmp_path
    ):
        """The policy is judged beside the validator's errors, so a config the
        model refuses is judged too."""
        child = _write(
            tmp_path / ".ash.yaml",
            "project_name: x\nglobal_settings:\n  severity_threshold: SEVERE\n",
        )

        check = ConfigValidator.check_config_file(child, source_dir=tmp_path)

        assert not check.scan_accepts
        assert child.resolve() in check.documents, list(check.documents)

    def test_an_accepted_check_that_holds_no_document_is_not_valid(self, _server):
        """No check that accepted a config holds none; a caller handed one must
        not read it as a config the policy accepts."""
        named = _write(_server["repo"] / "ash.yaml", CLEAN)

        denied = _validated_document_denials(None, str(named), REMOTE, ConfigCheck())

        assert [d["type"] for d in denied] == ["validation_error"], denied

    def test_a_check_the_validator_refused_without_a_chain_adds_nothing(self, _server):
        named = _write(_server["repo"] / "ash.yaml", CLEAN)
        refused = ConfigCheck(errors=["the validator said why"], could_not_read=True)

        denied = _validated_document_denials(None, str(named), REMOTE, refused)

        assert denied == []


class TestEveryDenialOfTheWalkIsReportedBesideTheValidatorsErrors:
    def test_a_model_error_and_an_environment_read_in_one_file_report_the_read_first(
        self, _server
    ):
        """The validator reads a remote caller's file under the caller's rule
        (``config_sources.env_refused_for``), so a file that reads the
        environment is refused before its references are resolved and nothing
        else of that file is judged: its model error is reported once the read
        is gone from it. No line of the answer depends on a value of the
        server's environment."""
        named = _write(
            _server["repo"] / "ash.yaml",
            f"project_name: ${{{PROBE_VAR}:unset}}\n"
            "global_settings:\n  severity_threshold: SEVERE\n",
        )

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert result["valid"] is False, result
        assert _types(result) == [ENV_REFUSED], result
        assert PROBE not in json.dumps(result), result

    def test_a_denial_in_one_file_and_an_environment_read_in_another_report_the_read_first(
        self, _server
    ):
        _write(_server["repo"] / "base.yaml", f"project_name: ${{{PROBE_VAR}:unset}}\n")
        named = _write(
            _server["repo"] / "ash.yaml",
            "extends: base.yaml\nfail_on_findings: false\n",
        )

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert result["valid"] is False, result
        assert _types(result) == [ENV_REFUSED], result
        assert PROBE not in json.dumps(result), result

    def test_a_denial_and_a_model_error_are_both_reported(self, _server):
        """Findings that need no read of the environment are all reported at
        once: the severity threshold the model refuses, and the field the policy
        denies."""
        named = _write(
            _server["repo"] / "ash.yaml",
            "project_name: x\nfail_on_findings: false\n"
            "global_settings:\n  severity_threshold: SEVERE\n",
        )

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert result["valid"] is False, result
        assert "denied_by_runtime_policy" in _types(result), result
        assert "invalid_field" in _types(result), result

    def test_a_denial_in_a_file_that_read_the_environment_is_not_judged(self, _server):
        """The validator parsed that file with the environment's values; a denial
        quoting one would send it to the client."""
        named = _write(
            _server["repo"] / "ash.yaml",
            f"project_name: ${{{PROBE_VAR}:unset}}\nfail_on_findings: false\n",
        )

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert result["valid"] is False, result
        assert _types(result) == [ENV_REFUSED], result
        assert PROBE not in json.dumps(result), result

    def test_a_message_the_validator_gave_is_not_repeated_by_the_policy_check(
        self, monkeypatch
    ):
        """No chain makes the two give one message today; the reply holds a
        message once whichever of them gave it."""
        from automated_security_helper.cli import mcp_tools

        content = "global_settings:\n  severity_threshold: SEVERE\n"
        first = mcp_validate_config(config_content=content)
        assert first["valid"] is False and first["errors"], first
        monkeypatch.setattr(
            mcp_tools,
            "_validated_document_denials",
            lambda *args, **kwargs: [dict(first["errors"][0])],
        )

        result = mcp_validate_config(config_content=content)

        assert result["errors"] == first["errors"], result


class TestAnEnvironmentReadInARemoteCallersFileIsRefused:
    """For a remote caller the environment is read in no file of a client's chain
    that the operator did not set aside, not only in a file a client delivered.
    The validator reads the chain under that rule, so such a file is refused in
    its read and the check holds no document of it for the policy to judge."""

    def test_a_named_file_that_reads_the_environment_is_refused(
        self, _server, monkeypatch
    ):
        named = _write(
            _server["repo"] / "ash.yaml", f"project_name: ${{{PROBE_VAR}:unset}}\n"
        )
        checks = _after_the_validator_reads(monkeypatch, lambda: None)

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert checks and not checks[0].scan_accepts, "premise: the validator refused"
        assert result["valid"] is False, result
        assert _types(result) == [ENV_REFUSED], result
        assert "ash.yaml" in result["errors"][0]["message"], result
        assert PROBE not in json.dumps(result), result

    def test_a_base_of_a_refused_file_is_refused_by_the_name_that_chose_it(
        self, _server, monkeypatch
    ):
        _write(_server["repo"] / "base.yaml", f"project_name: ${{{PROBE_VAR}:unset}}\n")
        child = _write(_server["repo"] / "ash.yaml", "extends: base.yaml\n")
        checks = _after_the_validator_reads(monkeypatch, lambda: None)

        result = mcp_validate_config(config_path=str(child), session_id=REMOTE)

        assert checks and not checks[0].scan_accepts, "premise: the validator refused"
        assert result["valid"] is False, result
        assert _types(result) == [ENV_REFUSED], result
        assert "base.yaml" in result["errors"][0]["message"], result

    def test_control_a_file_the_operator_set_aside_resolves_the_environment(
        self, _server, monkeypatch
    ):
        named = _write(
            _server["operator"] / "ash.yaml", f"project_name: ${{{PROBE_VAR}:unset}}\n"
        )
        checks = _after_the_validator_reads(monkeypatch, lambda: None)

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert checks and checks[0].scan_accepts, "premise: the validator accepted"
        assert result["valid"] is True, result
        assert result["errors"] == [], result

    def test_control_a_file_without_a_read_of_the_environment_is_not_refused(
        self, _server
    ):
        named = _write(_server["repo"] / "ash.yaml", CLEAN)

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert result["valid"] is True, result


class TestNoReplyLineCarriesTheConfigsOwnControlCharacters:
    @staticmethod
    def _lines(result: Dict[str, Any]) -> List[str]:
        return [e["message"] + e["field"] for e in result["errors"]]

    @staticmethod
    def _clean_of_controls(text: str) -> bool:
        return all(ch not in text for ch in (chr(0x1B), chr(0x202E), "\n", "\r"))

    def test_a_denial_that_names_a_value_of_the_config_is_one_sanitized_line(
        self, _server
    ):
        text = (
            "project_name: x\nsandbox:\n  network_scanners: ["
            + json.dumps(HOSTILE)
            + "]\n"
        )
        named = _write(_server["repo"] / "ash.yaml", text)

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)
        content = mcp_validate_config(config_content=text, session_id=REMOTE)

        for answer in (result, content):
            denied = [
                e for e in answer["errors"] if e["type"] == "denied_by_runtime_policy"
            ]
            assert len(denied) == 1, answer
            assert all(self._clean_of_controls(line) for line in self._lines(answer)), (
                answer
            )

    def test_an_extends_entry_the_validator_cannot_resolve_is_one_sanitized_line(
        self, _server
    ):
        entry = HOSTILE + ".yaml"
        named = _write(
            _server["repo"] / "ash.yaml", "extends: " + json.dumps(entry) + "\n"
        )

        result = mcp_validate_config(config_path=str(named), session_id=REMOTE)

        assert result["valid"] is False, result
        assert _types(result) == ["extends_error"], result
        assert all(self._clean_of_controls(line) for line in self._lines(result)), (
            result
        )

    def test_a_base_removed_after_the_validator_read_it_adds_no_line(
        self, _server, monkeypatch
    ):
        entry = HOSTILE + ".yaml"
        try:
            base = _write(_server["repo"] / entry, CLEAN)
        except OSError as error:
            pytest.skip(f"this file system cannot name such a file: {error}")
        child = _write(
            _server["repo"] / "ash.yaml", "extends: " + json.dumps(entry) + "\n"
        )
        checks = _after_the_validator_reads(monkeypatch, base.unlink)

        result = mcp_validate_config(config_path=str(child), session_id=REMOTE)

        assert checks and checks[0].scan_accepts, "premise: the validator accepted"
        assert result["errors"] == [], result
        assert result["valid"] is True, result

    def test_a_walk_failure_is_typed_by_the_validators_prefixes_on_one_line(
        self,
    ):
        from automated_security_helper.cli.mcp_tools import _unchecked_against_policy
        from automated_security_helper.config.config_validator import ConfigValidator
        from automated_security_helper.core.exceptions import ASHConfigSourceError

        error = ASHConfigSourceError(
            f"{ConfigValidator.NOT_PERMITTED_ERROR_PREFIX}{HOSTILE} is outside the roots"
        )

        problem = _unchecked_against_policy(error)

        assert problem["type"] == "config_input_not_permitted", problem
        assert self._clean_of_controls(problem["message"]), problem
        assert self._clean_of_controls(problem["field"]), problem
