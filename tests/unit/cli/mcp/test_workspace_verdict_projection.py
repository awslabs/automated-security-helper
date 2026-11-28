#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP workspace response must carry every field the model declares.

Why a key-set assertion rather than a list of fields
---------------------------------------------------
``_project_verdicts`` hand-builds a closed dictionary from a
``WorkspaceProjectResult``. A hand-maintained projection of a declared model is a
standing invitation to add a field to the model and forget the projection, and
that is what happened: ``scanners``, ``incomplete_scanners``, ``scan_incomplete``
and ``ceiling_unreachable_findings`` were all declared on the model and absent
from the response, so an MCP client could not learn that a project's scanners did
not run. Nothing else under ``cli/mcp/`` mentioned either completeness field.

Asserting the key *set* against ``model_fields`` is the class fix. A test that
listed the four missing names would pass again the next time a field is added.
The exclusion list is deliberately empty -- every declared field is projected --
so a future field has to be either projected or explicitly excused here, and the
excusing is visible in the diff.

The envelope carries the aggregate too
--------------------------------------
A client that reads only the top level of the response, which is the common shape
for a gate, sees ``exit_code`` and no reason for it. ``scan_incomplete`` is
surfaced there as well so that reason is available without walking ``projects``.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceExitCode,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_REASON,
    could_not_stop_default,
    could_not_stop_sentence,
    without_process_ids,
)

pytestmark = pytest.mark.unit

MODULE_UNDER_TEST = "automated_security_helper.cli.mcp.workspace"

#: Declared fields deliberately kept out of the MCP response. Empty on purpose:
#: see the module docstring. An entry here needs a comment saying why a client
#: must not see that field.
PROJECTED_EXCLUSIONS: frozenset[str] = frozenset()

#: The one response key that is not a model field. It joins a verdict to the
#: registry entry the client was handed, which the model knows nothing about.
NON_MODEL_KEYS = frozenset({"scan_id"})


def _module():
    return importlib.import_module(MODULE_UNDER_TEST)


def _outcome(key: str, **overrides: Any) -> WorkspaceProjectResult:
    """One completed project, with every optional field given a distinct value.

    Distinct rather than defaulted so that a projection which reads the wrong
    attribute is visible as a wrong value and not merely as a present key.
    """
    fields: Dict[str, Any] = {
        "project": key,
        "relative_path": key,
        "display_label": key.upper(),
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "finding_count": 3,
        "actionable_finding_count": 1,
        "exceeds_threshold": True,
        "duration_seconds": 1.5,
        "output_path": f"projects/{key}",
        "sarif_run_index": 0,
        "scanners": {"bandit": "PASSED", "cfn-nag": "MISSING"},
        "incomplete_scanners": ["cfn-nag"],
        "no_scanner_ran": False,
        "scan_incomplete": True,
        "ceiling_unreachable_findings": {"grype": 2},
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _payload(*outcomes: WorkspaceProjectResult) -> WorkspaceResults:
    return WorkspaceResults(
        workspace_file="/ws/dev.code-workspace",
        workspace_root="/ws",
        exit_code=int(WorkspaceExitCode.INTERNAL_ERROR),
        projects=list(outcomes),
    )


class TestUnstoppableToolReasonsNameProcessIdsOnlyToALocalCaller:
    """The executor records each ``unstoppable_tools`` reason naming the pid of
    the tool the stop could not end (``could_not_stop_default``). The field was
    projected to every client as recorded, while the cancel warning withheld
    the same pids from a network transport: a remote client learned a
    server-side pid here that it cannot act on. ``name_process_ids`` False drops
    them; the call site passes ``not caller_is_remote(session_id)``."""

    def test_the_helper_drops_the_pid_and_nothing_else(self):
        assert (
            without_process_ids(could_not_stop_default(4242)) == COULD_NOT_STOP_REASON
        )
        assert without_process_ids(
            could_not_stop_sentence("python3 (pid 7)")
        ) == could_not_stop_sentence("python3")
        assert without_process_ids("no pid here") == "no pid here"

    def test_a_remote_caller_reads_the_reason_without_the_pid(self):
        """Red at the base: the projection took no such argument and the reason
        reached the client with the pid in it."""
        payload = _payload(
            _outcome("api", unstoppable_tools={"bandit": could_not_stop_default(4242)})
        )

        verdicts = _module()._project_verdicts(
            payload, {"api": "scan-1"}, name_process_ids=False
        )

        assert verdicts[0]["unstoppable_tools"] == {"bandit": COULD_NOT_STOP_REASON}
        assert "4242" not in json.dumps(verdicts[0]["unstoppable_tools"])

    def test_a_local_caller_reads_the_reason_as_recorded(self):
        reason = could_not_stop_default(4242)
        payload = _payload(_outcome("api", unstoppable_tools={"bandit": reason}))

        verdicts = _module()._project_verdicts(
            payload, {"api": "scan-1"}, name_process_ids=True
        )

        assert verdicts[0]["unstoppable_tools"] == {"bandit": reason}


class TestTheProjectionCarriesEveryDeclaredField:
    def test_the_response_key_set_is_the_model_field_set(self):
        """The class fix. A missing projection is a missing key, and this sees it."""
        payload = _payload(_outcome("api"))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        assert len(verdicts) == 1
        expected = set(WorkspaceProjectResult.model_fields) - PROJECTED_EXCLUSIONS
        assert set(verdicts[0]) == expected | NON_MODEL_KEYS

    @pytest.mark.parametrize(
        "field,expected",
        [
            ("scanners", {"bandit": "PASSED", "cfn-nag": "MISSING"}),
            ("incomplete_scanners", ["cfn-nag"]),
            ("scan_incomplete", True),
            ("no_scanner_ran", False),
            ("ceiling_unreachable_findings", {"grype": 2}),
        ],
    )
    def test_the_completeness_fields_carry_their_values(self, field, expected):
        """Presence is not enough: a projection can read the wrong attribute.

        These five are the ones that were dropped, so they are asserted on their
        values rather than left to the key-set test above.
        """
        payload = _payload(_outcome("api"))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        assert verdicts[0][field] == expected

    def test_a_projected_enum_is_a_plain_value(self):
        """The response is serialized to a client, so an enum member would leak.

        ``status`` already went through ``_enum_value``; the assertion is here so
        that adding a field of enum type cannot quietly ship a member.
        """
        payload = _payload(_outcome("api"))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        json.dumps(verdicts)
        assert verdicts[0]["status"] == ProjectRunStatus.COMPLETED.value


class TestTheEnvelopeSurfacesTheAggregate:
    """A client reading only the top level still learns the scan was incomplete."""

    @pytest.fixture(autouse=True)
    def _clear_policy_env(self, monkeypatch):
        monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
        monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)

    @staticmethod
    def _workspace(root: Path, folders: List[str]) -> Path:
        for entry in folders:
            (root / entry).mkdir(parents=True, exist_ok=True)
        path = root / "dev.code-workspace"
        path.write_text(
            json.dumps({"folders": [{"path": entry} for entry in folders]}),
            encoding="utf-8",
        )
        return path

    def _stub_execution(self, monkeypatch, tmp_path, payload: WorkspaceResults):
        from automated_security_helper.workspace.execution import WorkspaceRunResult

        results_path = tmp_path / "out" / "ash_aggregated_results.json"
        results_path.parent.mkdir(parents=True, exist_ok=True)
        results_path.write_text("{}", encoding="utf-8")

        def _execute(plan, settings, *args, **kwargs):
            return WorkspaceRunResult(
                results_path=results_path,
                exit_code=payload.exit_code,
                payload=payload,
            )

        monkeypatch.setattr(_module(), "execute_workspace", _execute)

    @pytest.mark.asyncio
    async def test_an_incomplete_project_sets_the_top_level_flag(
        self, tmp_path, monkeypatch
    ):
        workspace = self._workspace(tmp_path, ["api", "web"])
        self._stub_execution(
            monkeypatch,
            tmp_path,
            _payload(
                _outcome("api", scan_incomplete=False, incomplete_scanners=[]),
                _outcome("web"),
            ),
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace),
            output_dir=str(tmp_path / "out"),
        )

        assert response["success"] is True
        assert response["scan_incomplete"] is True

    @pytest.mark.asyncio
    async def test_a_complete_workspace_does_not_set_the_flag(
        self, tmp_path, monkeypatch
    ):
        """The control. Without it, a hardcoded True satisfies the test above."""
        workspace = self._workspace(tmp_path, ["api"])
        self._stub_execution(
            monkeypatch,
            tmp_path,
            _payload(_outcome("api", scan_incomplete=False, incomplete_scanners=[])),
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace),
            output_dir=str(tmp_path / "out"),
        )

        assert response["success"] is True
        assert response["scan_incomplete"] is False

    @pytest.mark.asyncio
    async def test_the_ceiling_disclosure_reaches_the_envelope(
        self, tmp_path, monkeypatch
    ):
        """Why it is echoed: a client reading only the envelope cannot see a
        per-project mapping, and a tightened ceiling that could not reach some
        findings changes what the verdict means."""
        workspace = self._workspace(tmp_path, ["api"])
        self._stub_execution(
            monkeypatch,
            tmp_path,
            _payload(_outcome("api", ceiling_unreachable_findings={"grype": 2})),
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace),
            output_dir=str(tmp_path / "out"),
        )

        assert response["ceiling_unreachable_findings"] == {"grype": 2}


#: ESC, and its escape written twice: what a client must never read.
ESC = "\x1b"
SHOWN_TWICE = "\\\\x1b"


class TestTheTextAClientMayDisplayIsShownOnOneLine:
    """A verdict's text written for a reader reaches the client with each
    control character written as its escape, on one line.

    A project refused for its configuration has the refusal as its ``error``,
    and the refusal quotes what refused it as written: a lock's key, a
    suppression's path (utils/ash_lock.py). The response handed the field over
    as recorded, so a client displaying the error read a raw ESC, where what a
    client may display holds no control character (cli/mcp_server.py). The
    other messages, and the reasons the mappings and records carry, are shown
    the same way. The project's key and paths are not: a client joins on the
    one and opens the others.
    """

    @pytest.fixture(autouse=True)
    def _isolated(self, monkeypatch):
        """No confinement, which these cells do not measure, and a registry and
        a profile state of their own, so another cell's scan or bound profile
        cannot decide what a scan here reads."""
        from automated_security_helper.cli.mcp.profile_registry import (
            clear_all_session_state,
            clear_profile_registry,
        )
        from automated_security_helper.core.resource_management import (
            scan_registry as scan_registry_module,
        )

        for name in (
            "ASH_MCP_ALLOWED_ROOTS",
            "ASH_MCP_ALLOWED_CONFIG_ROOTS",
            "ASH_MCP_WORKSPACE_ROOT",
        ):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setattr(
            scan_registry_module, "_scan_registry", scan_registry_module.ScanRegistry()
        )
        clear_profile_registry()
        clear_all_session_state()
        yield
        clear_profile_registry()
        clear_all_session_state()

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("lock", "suppression_path", "shown"),
        [
            pytest.param(
                '{"version": 2, "files": {}, "a\\u001bb": 0}',
                "src/app.py",
                "has an unknown key 'a\\x1bb' in the document",
                id="lock-key",
            ),
            pytest.param(
                None,
                "a\\x1bb.py",
                "'a\\x1bb.py' no longer exists",
                id="suppression-path",
            ),
        ],
    )
    async def test_a_refusal_reaches_the_client_with_its_value_shown_once(
        self, tmp_path, lock, suppression_path, shown
    ):
        """Through the scan: the project's own orchestrator refuses the lock's
        unknown key, or the suppression whose file is gone, and the response
        carries the refusal. Red at the base: a raw ESC where the escape is."""
        from automated_security_helper.utils.ash_lock import LOCK_RELATIVE_PATH

        project = tmp_path / "ws" / "app"
        (project / "src").mkdir(parents=True)
        (project / "src" / "app.py").write_text("x = 1\n", encoding="utf-8")
        (project / ".ash.yaml").write_text(
            "project_name: demo\n"
            "global_settings:\n"
            "  suppressions:\n"
            "    - rule_id: R1\n"
            f'      path: "{suppression_path}"\n'
            "      symbol: MyClass.my_method\n"
            "      reason: probe\n",
            encoding="utf-8",
        )
        if lock is not None:
            (project / LOCK_RELATIVE_PATH).write_text(lock, encoding="utf-8")
        workspace = tmp_path / "ws" / "dev.code-workspace"
        workspace.write_text(
            json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace), output_dir=str(tmp_path / "out")
        )

        assert response["success"] is True, response
        (verdict,) = response["projects"]
        assert verdict["invalid_config"] is True, verdict
        assert shown in verdict["error"], verdict["error"]
        assert SHOWN_TWICE not in verdict["error"], verdict["error"]
        assert ESC not in verdict["error"], verdict["error"]

    @pytest.mark.asyncio
    async def test_a_missing_projects_detail_reaches_the_client_shown_once(
        self, tmp_path, monkeypatch
    ):
        """A project skipped at resolution, under allow_missing_projects, has a
        detail quoting its folder as the workspace file writes it. The response
        carries that text twice, in the verdict's skip_detail and in
        skipped_projects, and shows it the same way in both. A workspace whose
        every folder is skipped is refused, so the other folder is a project
        whose orchestrator refuses it before anything is scanned."""
        from automated_security_helper.core.exceptions import ASHConfigValidationError
        from automated_security_helper.workspace import execution as execution_module

        real = execution_module.execute_workspace

        def _refused(**_kwargs):
            raise ASHConfigValidationError("refused before the scan")

        def _execute(plan, settings, **kwargs):
            kwargs["orchestrator_factory"] = _refused
            return real(plan, settings, **kwargs)

        monkeypatch.setattr(_module(), "execute_workspace", _execute)
        root = tmp_path / "ws"
        (root / "app").mkdir(parents=True)
        workspace = root / "dev.code-workspace"
        workspace.write_text(
            json.dumps({"folders": [{"path": "app"}, {"path": "a\x1bb"}]}),
            encoding="utf-8",
        )

        response = await _module().mcp_scan_workspace(
            workspace_file=str(workspace),
            allow_missing_projects=True,
            output_dir=str(tmp_path / "out"),
        )

        assert response["success"] is True, response
        (verdict,) = [
            entry for entry in response["projects"] if entry["status"] == "skipped"
        ]
        (skipped,) = response["skipped_projects"]
        shown = "'a\\x1bb' does not exist as a directory"
        assert shown in verdict["skip_detail"], verdict["skip_detail"]
        assert SHOWN_TWICE not in verdict["skip_detail"], verdict["skip_detail"]
        assert ESC not in verdict["skip_detail"], verdict["skip_detail"]
        assert skipped["detail"] == verdict["skip_detail"], skipped

    @pytest.mark.parametrize(
        ("field", "recorded", "handed"),
        [
            pytest.param(
                "error",
                "Invalid configuration: key 'a\x1bb'\n  the next line",
                "Invalid configuration: key 'a\\x1bb'\\x0a  the next line",
                id="error",
            ),
            pytest.param(
                "error",
                "cannot read 'a\\x1bb'",
                "cannot read 'a\\x1bb'",
                id="error-with-an-escape-already",
            ),
            pytest.param(
                "skip_detail",
                "skipped: a\x1bb",
                "skipped: a\\x1bb",
                id="skip_detail",
            ),
            pytest.param(
                "display_label",
                "demo\x1b]0;x\x07",
                "demo\\x1b]0;x\\x07",
                id="display_label",
            ),
        ],
    )
    def test_a_message_is_handed_over_on_one_line(self, field, recorded, handed):
        """The error-with-an-escape-already row is the control: an escape the
        text holds keeps its one backslash, as the registry's copy of the error
        reads, where shown_on_one_line would double it."""
        payload = _payload(_outcome("api", **{field: recorded}))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        assert verdicts[0][field] == handed

    @pytest.mark.parametrize(
        "field",
        [
            "incomplete_converters",
            "incomplete_scanner_details",
            "scanner_reasons",
            "unstoppable_tools",
        ],
    )
    def test_each_reason_of_a_mapping_is_shown(self, field):
        payload = _payload(_outcome("api", **{field: {"bandit": "stopped: a\x1bb"}}))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        assert verdicts[0][field] == {"bandit": "stopped: a\\x1bb"}

    def test_a_records_reason_is_shown_and_its_path_kept(self):
        from automated_security_helper.models.workspace import (
            ProjectConverterRefusal,
            ProjectInputNotScanned,
        )

        not_scanned = ProjectInputNotScanned(
            scanner="npm-audit", path="api/a\x1bb.lock", reason="offline: a\x1bb"
        )
        refused = ProjectConverterRefusal(
            converter="archive", path="api/a\x1bb.zip", reason="over: a\x1bb"
        )
        payload = _payload(
            _outcome(
                "api", inputs_not_scanned=[not_scanned], converter_refusals=[refused]
            )
        )

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        (shown_not_scanned,) = verdicts[0]["inputs_not_scanned"]
        (shown_refused,) = verdicts[0]["converter_refusals"]
        assert shown_not_scanned["reason"] == "offline: a\\x1bb"
        assert shown_not_scanned["path"] == "api/a\x1bb.lock"
        assert shown_refused["reason"] == "over: a\\x1bb"
        assert shown_refused["path"] == "api/a\x1bb.zip"

    def test_the_projects_key_and_paths_are_handed_over_as_recorded(self):
        """A client joins a verdict on its key and opens its paths: an escape
        written into one would name another project or another file."""
        key = "a\x1bb"
        payload = _payload(_outcome(key))

        verdicts = _module()._project_verdicts(payload, {key: "scan-1"})

        assert verdicts[0]["project"] == key
        assert verdicts[0]["relative_path"] == key
        assert verdicts[0]["output_path"] == f"projects/{key}"
        assert verdicts[0]["scan_id"] == "scan-1"

    def test_an_archive_members_name_is_shown(self):
        """A converter refusal names the archive member it refused as the archive
        spells it: the archive's text, and not a path a client opens, so the
        reply shows it as it shows the refusal's reason."""
        from automated_security_helper.models.workspace import ProjectConverterRefusal

        refused = ProjectConverterRefusal(
            converter="archive",
            path="api/bundle.zip",
            member="../a\x1bb.py",
            reason="a member names a parent directory",
        )
        payload = _payload(_outcome("api", converter_refusals=[refused]))

        verdicts = _module()._project_verdicts(payload, {"api": "scan-1"})

        (shown,) = verdicts[0]["converter_refusals"]
        assert shown["member"] == "../a\\x1bb.py"
        assert shown["path"] == "api/bundle.zip"
