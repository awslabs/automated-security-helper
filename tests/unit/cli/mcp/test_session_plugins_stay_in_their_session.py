# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin module one MCP session's profile loads stays out of another session.

The question
------------
The MCP server runs every session's scans in its own process, and plugins
register into one process-wide registry when their module is first imported.
After session A's profile has loaded a module, session B, whose profile lists
none, might find A's plugins in its own scan: its scanners, its reporters
(``ash_aws_plugins`` sends results to an AWS account), or its event handlers,
which are handed the run's context. The listing tools load modules into the same
registry: ``list_scanners`` imports the ferret-scan, snyk-code and trivy-repo
packages to describe them.

What the test does
------------------
One child interpreter plays the server and imports the tree this file is in.
Two profiles are registered the way ``ash mcp --profile`` registers them:

* ``with-plugins`` lists ``ash_aws_plugins`` and a small test package,
  ``sessiona_ash_plugins`` (a scanner, a reporter and an EXECUTION_START
  handler), and enables the off-host aws-security-hub reporter;
* ``plain`` lists no module.

Both disable every built-in scanner but detect-secrets, so each scan is quick.
Session A binds ``with-plugins`` and scans. Then the listing tools run
(``list_scanners``, ``check_installation``, ``list_profiles``), and session B
binds ``plain`` and scans. Each scan goes through ``run_ash_scan`` with the config
path the session's binding resolves to, or through the MCP scan tool with that
path and the session id, which is what the server's scan tool does.

For each scan the child records the plugin classes the scan engine resolved,
every boto3 or botocore session, client or resource anything asked for, and how
often A's handler ran. boto3 and botocore are replaced by stand-ins that record
the request and raise, the credentials in the environment are obvious fakes, and
every AWS endpoint and proxy refuses connections, so nothing reaches AWS.
Container runtimes are guard stand-ins first on PATH.

A's scan is the control: its engine has A's plugins, the AWS reporter asks for
an AWS session, and A's handler runs. B's engine must have none of A's plugins
and none of the packages the listing loaded, nothing may ask for AWS during B's
scan, and A's handler must not run in it.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - a fresh interpreter is the property under test
import sys
import textwrap
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout
from tests.utils.tool_guard import (
    CHILD_TOOL_PROBE_STUBS,
    install_tool_guard,
    reset_tool_lookup_caches,
)

# e2e, for the CI budget rather than for what the tests reach: the module-scoped
# fixture runs two whole child scans (api and mcp, 900 s each) and the
# vendored-scanner test a third (600 s), with stub probes answering for every
# scanner. By tests/NAMING_CONVENTIONS.md a child Python running a test-written
# script is integration, and the integration job runs every Python on every OS in
# four shards (25 legs), where the e2e job runs once per runner (5 legs). Without a
# measured wall time under a minute for this module, moving it would put three
# child scans on whichever integration shard it hashes to, five times as often.
# The tier owner decides once the wall is measured.
pytestmark = pytest.mark.e2e

REPO_ROOT = Path(__file__).resolve().parents[4]

AWS_PLUGINS = "automated_security_helper.plugin_modules.ash_aws_plugins"
A_CLASSES = {"SessionAScanner", "SessionAReporter", "SecurityHubReporter"}
LISTED_CLASSES = {"FerretScanScanner", "SnykCodeScanner", "TrivyRepoScanner"}

SESSION_A_PACKAGE = textwrap.dedent(
    """
    from typing import Literal

    from automated_security_helper.base.reporter_plugin import (
        ReporterPluginBase,
        ReporterPluginConfigBase,
    )
    from automated_security_helper.base.scanner_plugin import (
        ScannerPluginBase,
        ScannerPluginConfigBase,
    )
    from automated_security_helper.plugins.decorators import (
        ash_reporter_plugin,
        ash_scanner_plugin,
    )
    from automated_security_helper.plugins.events import AshEventType


    class SessionAScannerConfig(ScannerPluginConfigBase):
        name: Literal["session-a-scanner"] = "session-a-scanner"


    @ash_scanner_plugin
    class SessionAScanner(ScannerPluginBase[SessionAScannerConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = SessionAScannerConfig()
            return super().model_post_init(context)

        def validate_plugin_dependencies(self):
            return True

        def scan(self, *args, **kwargs):
            raise NotImplementedError


    class SessionAReporterConfig(ReporterPluginConfigBase):
        name: Literal["session-a-reporter"] = "session-a-reporter"
        extension: str = "session-a.txt"
        enabled: bool = True


    @ash_reporter_plugin
    class SessionAReporter(ReporterPluginBase[SessionAReporterConfig]):
        def model_post_init(self, context):
            if self.config is None:
                self.config = SessionAReporterConfig()
            return super().model_post_init(context)

        def report(self, model):
            return "session a"


    def record_session_a_start(*args, **kwargs):
        import builtins

        builtins.__dict__.setdefault("_SESSION_A_HANDLER_CALLS", []).append(1)
        return True


    ASH_EVENT_HANDLERS = {AshEventType.EXECUTION_START: [record_session_a_start]}
    """
)

# Each child's probes are answered first (CHILD_TOOL_PROBE_STUBS): list_scanners ran
# every scanner's dependency check with the uv installed with ASH, which started
# checkov and semgrep and left their files and uv's in the test's HOME.
#: argv: work dir, test package dir, tree to import, "api" or "mcp".
DRIVER = CHILD_TOOL_PROBE_STUBS + textwrap.dedent(
    """
    import asyncio, builtins, json, sys
    from pathlib import Path

    work, packages, root, via = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    sys.path.insert(0, packages)
    sys.path.insert(0, root)

    # Every way ASH can ask for AWS records the request and raises. Only the
    # service name is recorded: nothing credential-shaped is ever printed.
    import boto3
    import boto3.session
    import botocore.session

    asked = []


    def _refuse(request):
        asked.append(request)
        raise RuntimeError("this test reaches no AWS service")


    class _NoBoto3Session:
        def __init__(self, *args, **kwargs):
            _refuse("boto3.Session")


    class _NoBotocoreSession:
        def __init__(self, *args, **kwargs):
            _refuse("botocore.Session")


    boto3.Session = boto3.session.Session = _NoBoto3Session
    boto3.DEFAULT_SESSION = None
    boto3.client = lambda name, *a, **k: _refuse("boto3.client:" + str(name))
    boto3.resource = lambda name, *a, **k: _refuse("boto3.resource:" + str(name))
    botocore.session.Session = _NoBotocoreSession
    botocore.session.get_session = lambda *a, **k: _refuse("botocore.get_session")

    import automated_security_helper
    from automated_security_helper.core import execution_engine

    engines = []
    original_init = execution_engine.ScanExecutionEngine.__init__


    def recording_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        engines.append(
            {kind: sorted(c.__name__ for c in classes)
             for kind, classes in self.plugins.items()}
        )


    execution_engine.ScanExecutionEngine.__init__ = recording_init

    from automated_security_helper.cli.mcp.profile_registry import (
        register_profiles,
        resolve_session_config_path,
        set_profile_registry,
    )
    from automated_security_helper.cli.mcp_tools import (
        mcp_check_installation,
        mcp_list_profiles,
        mcp_list_scanners,
        mcp_scan_directory,
        mcp_select_profile,
    )
    from automated_security_helper.core.enums import AshLogLevel, RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.plugins.loader import load_internal_plugins


    def _config_name(cls):
        field = getattr(cls, "model_fields", {}).get("config")
        for arg in getattr(getattr(field, "annotation", None), "__args__", None) or ():
            fields = getattr(arg, "model_fields", None) or {}
            if isinstance(arg, type) and arg.__name__.endswith("ScannerConfig") and "name" in fields:
                if fields["name"].default:
                    return fields["name"].default
        raise RuntimeError("no config name for " + cls.__name__)


    # Every built-in scanner but detect-secrets is disabled, in both profiles.
    disabled = sorted(
        {_config_name(c) for c in load_internal_plugins()["scanners"]} - {"detect-secrets"}
    )
    scanners = "scanners:\\n" + "".join(
        "  " + name + ":\\n    enabled: false\\n" for name in disabled
    )
    (work / "with-plugins.yaml").write_text(
        "project_name: session-a\\n"
        "ash_plugin_modules:\\n"
        "  - automated_security_helper.plugin_modules.ash_aws_plugins\\n"
        "  - sessiona_ash_plugins\\n"
        + scanners
        + "reporters:\\n"
        "  aws-security-hub:\\n"
        "    enabled: true\\n"
        "    options:\\n"
        "      aws_region: us-east-1\\n",
        encoding="utf-8",
    )
    (work / "plain.yaml").write_text(
        "project_name: session-b\\n" + scanners, encoding="utf-8"
    )

    set_profile_registry(register_profiles([
        "with-plugins=" + str(work / "with-plugins.yaml"),
        "plain=" + str(work / "plain.yaml"),
    ]))


    def _scan(session, source):
        config = resolve_session_config_path(session)
        if via == "api":
            try:
                run_ash_scan(
                    source_dir=str(source),
                    output_dir=str(work / session / "out"),
                    config=config,
                    mode=RunMode.local,
                    offline=True,
                    fail_on_findings=False,
                    show_summary=False,
                    log_level=AshLogLevel.ERROR,
                )
            except SystemExit:
                pass
            return None

        async def _go():
            started = await mcp_scan_directory(
                str(source), config_path=config, session_id=session
            )
            pending = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            await asyncio.gather(*pending, return_exceptions=True)
            return started

        started = asyncio.run(_go())
        return bool(started.get("success"))


    outcome = {"ash": automated_security_helper.__file__, "via": via}
    handler_calls = builtins.__dict__.setdefault("_SESSION_A_HANDLER_CALLS", [])
    for session, profile in (("session-a", "with-plugins"), ("session-b", "plain")):
        if session == "session-b":
            # The listing tools, between the two scans.
            before_asked = len(asked)
            listed = sorted(e["name"] for e in mcp_list_scanners())
            asyncio.run(mcp_check_installation())
            mcp_list_profiles()
            outcome["listing"] = {
                "listed_scanners": listed,
                "asked_aws": asked[before_asked:],
            }
        bound = mcp_select_profile(profile, session_id=session)
        assert bound["success"], bound
        source = work / session / "src"
        source.mkdir(parents=True)
        (source / "app.py").write_text("x = 1\\n", encoding="utf-8")
        before_asked, before_engines = len(asked), len(engines)
        before_handler = len(handler_calls)
        started = _scan(session, source)
        outcome[session] = {
            "started": started,
            "engines": engines[before_engines:],
            "asked_aws": asked[before_asked:],
            "a_handler_calls": len(handler_calls) - before_handler,
        }
    # On a line of its own: a progress display may not end its last line.
    print("\\nOUTCOME " + json.dumps(outcome), flush=True)
    """
)

GUARD = '#!/bin/sh\necho "$0 $*" >> "$GUARD_LOG"\nexit 97\n'

#: A port nothing listens on, so a connection or a proxied one is refused at once.
REFUSING = "http://127.0.0.1:9"


def _child_env(tmp_path: Path) -> dict:
    guards = tmp_path / "guards"
    guards.mkdir()
    for runtime in ("docker", "finch", "nerdctl", "podman"):
        script = guards / runtime
        script.write_text(GUARD, encoding="utf-8")
        script.chmod(0o755)
    home = tmp_path / "home"
    tools = tmp_path / "tools"
    for path in (home, tools):
        path.mkdir()
    empty_aws_config = tmp_path / "empty-aws-config"
    empty_aws_credentials = tmp_path / "empty-aws-credentials"
    for path in (empty_aws_config, empty_aws_credentials):
        path.write_text("", encoding="utf-8")
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("AWS_", "ASH_", "BOTO", "SNYK_"))
    }
    env.update(
        {
            "PATH": os.pathsep.join([str(guards), env.get("PATH", "")]),
            "GUARD_LOG": str(tmp_path / "guards.log"),
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CACHE_HOME": str(tools / "xdg-cache"),
            "XDG_DATA_HOME": str(tools / "xdg-data"),
            "XDG_CONFIG_HOME": str(tools / "xdg-config"),
            "XDG_BIN_HOME": str(tools / "xdg-bin"),
            "UV_TOOL_DIR": str(tools / "uv-tools"),
            "UV_TOOL_BIN_DIR": str(tools / "uv-tool-bin"),
            "ASH_BIN_PATH": str(tools / "ash-bin"),
            "UV_OFFLINE": "1",
            "ASH_OFFLINE": "YES",
            "ASH_MCP_WORKSPACE_ROOT": str(tmp_path / "mcp-workspaces"),
            "ASH_MCP_TRANSPORT": "stdio",
            "ASH_MCP_ALLOWED_ROOTS": str(tmp_path),
            # Obvious fakes, files with nothing in them, no instance metadata and
            # a refusing endpoint: the server's credentials are never real here.
            "AWS_ACCESS_KEY_ID": "fake-access-key-id",
            "AWS_SECRET_ACCESS_KEY": "fake-secret-access-key",  # pragma: allowlist secret
            "AWS_CONFIG_FILE": str(empty_aws_config),
            "AWS_SHARED_CREDENTIALS_FILE": str(empty_aws_credentials),
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": REFUSING,
            "AWS_REGION": "us-east-1",
            "HTTP_PROXY": REFUSING,
            "HTTPS_PROXY": REFUSING,
            "http_proxy": REFUSING,
            "https_proxy": REFUSING,
            "NO_PROXY": "",
            "no_proxy": "",
            "NO_COLOR": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    return env


@pytest.fixture(scope="module", params=["api", "mcp"])
def two_sessions(request, tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp(f"two-sessions-{request.param}")
    work = tmp_path / "work"
    work.mkdir()
    packages = tmp_path / "packages"
    (packages / "sessiona_ash_plugins").mkdir(parents=True)
    (packages / "sessiona_ash_plugins" / "__init__.py").write_text(
        SESSION_A_PACKAGE, encoding="utf-8"
    )

    # Module-scoped, so the child runs before any test's tool guard
    # (tests/unit/conftest.py) is in: it gets one of its own, with the same check.
    with pytest.MonkeyPatch.context() as patch:
        guard = install_tool_guard(
            patch,
            tmp_path / "guard-bin",
            own_directories=(tmp_path_factory.getbasetemp(),),
        )
        completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
            [
                sys.executable,
                "-I",
                "-c",
                DRIVER,
                str(work),
                str(packages),
                str(REPO_ROOT),
                request.param,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=900,
            env=_child_env(tmp_path),
            cwd=tmp_path,
        )
        started = guard.tool_starts
    reset_tool_lookup_caches()
    assert started == [], f"the two sessions' child started a tool: {started}"
    lines = [
        line for line in completed.stdout.splitlines() if line.startswith("OUTCOME ")
    ]
    assert lines, (
        f"the child printed no outcome (exit {completed.returncode})\n"
        + completed.stdout[-3000:]
        + completed.stderr[-3000:]
    )
    outcome = json.loads(lines[-1][len("OUTCOME ") :])
    guard_log = tmp_path / "guards.log"
    outcome["container_runtime_calls"] = (
        guard_log.read_text(encoding="utf-8").splitlines() if guard_log.exists() else []
    )
    return outcome


def _resolved(engines) -> set:
    return {name for engine in engines for names in engine.values() for name in names}


def test_the_child_ran_the_tree_under_test(two_sessions):
    assert Path(two_sessions["ash"]).resolve().is_relative_to(REPO_ROOT), two_sessions


def test_session_a_has_its_plugins(two_sessions):
    """The control: A's profile loads the modules, and the AWS reporter is tried."""
    a = two_sessions["session-a"]
    assert a["engines"], f"session A's scan built no scan engine: {a}"
    assert A_CLASSES <= _resolved(a["engines"]), a["engines"]
    assert a["asked_aws"], "control: session A's AWS reporter asked for no AWS session"
    assert a["a_handler_calls"] > 0, "control: A's handler did not run in A's scan"


def test_session_b_resolves_none_of_session_as_plugins(two_sessions):
    b = two_sessions["session-b"]
    assert b["engines"], f"session B's scan built no scan engine: {b}"
    leaked = A_CLASSES & _resolved(b["engines"])
    assert leaked == set(), (
        f"session B's scan engine resolved {sorted(leaked)}, which only session A's "
        "profile loads"
    )


def test_session_b_resolves_none_of_the_listed_packages(two_sessions):
    """list_scanners imported them between the scans; B's profile names none."""
    leaked = LISTED_CLASSES & _resolved(two_sessions["session-b"]["engines"])
    assert leaked == set(), (
        f"session B's scan engine resolved {sorted(leaked)}, which only the listing "
        "tools loaded"
    )


def test_session_b_asks_aws_for_nothing(two_sessions):
    assert two_sessions["session-b"]["asked_aws"] == []


def test_session_as_event_handler_does_not_run_in_session_bs_scan(two_sessions):
    """An event handler is plugin code too, and it is handed the run's context."""
    assert two_sessions["session-b"]["a_handler_calls"] == 0, two_sessions


def test_session_b_is_not_offered_session_as_scanner(two_sessions):
    listed = two_sessions["listing"]["listed_scanners"]
    assert "session_a_scanner" not in listed
    assert "session-a-scanner" not in listed


def test_no_container_runtime_was_called(two_sessions):
    assert two_sessions["container_runtime_calls"] == []


LIST_THEN_SCAN = CHILD_TOOL_PROBE_STUBS + textwrap.dedent(
    """
    import json, sys
    from pathlib import Path

    work = Path(sys.argv[1])
    from automated_security_helper.core import execution_engine

    engines = []
    original_init = execution_engine.ScanExecutionEngine.__init__


    def recording_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        engines.append(sorted(c.__name__ for c in self.plugins["scanner"]))


    execution_engine.ScanExecutionEngine.__init__ = recording_init

    from automated_security_helper.cli.mcp_tools import mcp_list_scanners
    from automated_security_helper.core.enums import AshLogLevel, RunMode
    from automated_security_helper.interactions.run_ash_scan import run_ash_scan

    listed = sorted(entry["name"] for entry in mcp_list_scanners())
    source = work / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\\n", encoding="utf-8")
    try:
        run_ash_scan(
            source_dir=str(source),
            output_dir=str(work / "out"),
            mode=RunMode.local,
            scanners=["detect-secrets"],
            offline=True,
            fail_on_findings=False,
            show_summary=False,
            log_level=AshLogLevel.ERROR,
        )
    except SystemExit:
        pass
    print("\\nOUTCOME " + json.dumps({"listed": listed, "engines": engines}))
    """
)

VENDORED_SCANNERS = {"FerretScanScanner", "SnykCodeScanner", "TrivyRepoScanner"}


def test_a_scan_after_list_scanners_resolves_no_vendored_scanner(tmp_path):
    """list_scanners loads ferret, snyk and trivy to describe them; a scan whose
    config lists none of them must not get them from that."""
    work = tmp_path / "work"
    work.mkdir()
    completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            importing_this_checkout(LIST_THEN_SCAN),
            str(work),
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=_child_env(tmp_path),
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr[-4000:]
    lines = [
        line for line in completed.stdout.splitlines() if line.startswith("OUTCOME ")
    ]
    assert lines, completed.stdout[-3000:] + completed.stderr[-3000:]
    outcome = json.loads(lines[-1][len("OUTCOME ") :])

    # The premise: list_scanners did load and describe them.
    assert "snyk_code" in outcome["listed"], outcome["listed"]
    assert len(outcome["engines"]) == 1, outcome
    assert VENDORED_SCANNERS & set(outcome["engines"][0]) == set(), outcome
