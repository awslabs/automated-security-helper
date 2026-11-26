# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Claims of six docs pages that no claims test, runnable block or inventory held.

A classification of the docs found these pages with nothing that runs against the
sentences they make about behavior: how-to/deploy-on-aws.md, how-to/aidlc-workflows.md,
how-to/express-mode.md, integrations.md, and the two builtin scanner pages
docs/plugins/builtin/gitleaks.md and docs/plugins/builtin/zizmor.md. Each test here
follows the pattern of test_page_claims.py, in two halves: ``assert_on_page`` checks that
the sentence is still on its page, and the test then probes the code, the committed
deployment templates or the plugin files that make it true. A test goes red when either
half moves.

What each page has pinned, and where a claim on it is not:

- deploy-on-aws: the five targets and the template and module each names, the
  ``AshVersion`` default and the Terraform ``ash_version`` that has none, the ingress
  CIDR that rejects ``0.0.0.0/0``, the empty auth-header defaults, the sandbox backends
  the image lacks, ``ash mcp --stateless-http``, and the unpublished ``ASHScanStep``.
  Not pinned: the network defaults of the Terraform modules, and what a deployed stack
  does.
- aidlc-workflows: the plugin directory, its manifest and the two checkpoint commands,
  its rules, and the suppression fields the page tells an agent to record. Not pinned:
  anything AI-DLC itself does (its commands are that project's).
- express-mode: the idle default and its two settings, the options of ``ash express``
  and of ``ash scan``, the private socket directory, the environment the daemon keeps
  and the one marker a request drops. Not pinned: forking, the handshake and the
  fallback, which need a running daemon.
- integrations: what each pre-commit hook runs, the sixteen agent platforms and their
  directories, ``ash-mode`` of the reusable workflow, the three ways to name plugin
  modules, and the AWS reporters the page lists.
- gitleaks and zizmor: the options and their defaults, the flags ASH always passes, the
  exit codes that count as success, and for zizmor the environment variables removed
  and the severity table. Not pinned: the re-scan of a ``.gitleaksignore`` and every
  sandbox behavior.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Dict, List

import pytest
import yaml

from tests.snapshot.support.reporter_catalog import AWS_REPORTER_NAMES
from tests.unit.docs.test_page_claims import CONTENT, assert_on_page

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
DEPLOY_PAGE = "how-to/deploy-on-aws.md"
INTEGRATIONS_PAGE = "integrations.md"
AIDLC_PAGE = "how-to/aidlc-workflows.md"
EXPRESS_PAGE = "how-to/express-mode.md"
GITLEAKS_PAGE = "docs/plugins/builtin/gitleaks.md"
ZIZMOR_PAGE = "docs/plugins/builtin/zizmor.md"

CDK_TEMPLATES = REPO_ROOT / "deploy" / "cdk" / "templates"
TERRAFORM_MODULES = REPO_ROOT / "deploy" / "terraform" / "modules"
AIDLC_PLUGIN = REPO_ROOT / "examples" / "aidlc-workflows" / "ash-scan"
SCANNERS = (
    REPO_ROOT
    / "automated_security_helper"
    / "plugin_modules"
    / "ash_builtin"
    / "scanners"
)


def _page_lines(page: str) -> List[str]:
    return (CONTENT / page).read_text(encoding="utf-8").splitlines()


def _table_rows(page: str, header: str) -> List[List[str]]:
    """The cells of each data row of the table whose header row starts ``header``."""
    lines = _page_lines(page)
    start = next(
        (i for i, line in enumerate(lines) if line.strip().startswith(header)), None
    )
    assert start is not None, f"docs/content/{page} has no table headed {header!r}"
    rows = []
    for line in lines[start + 2 :]:
        if not line.startswith("|"):
            break
        rows.append([cell.strip() for cell in line.strip().strip("|").split("|")])
    assert rows, f"docs/content/{page}: the table headed {header!r} has no rows"
    return rows


def _code(cell: str) -> str:
    return cell.strip().strip("`")


def _click_commands():
    from automated_security_helper.cli.main import app
    from typer.main import get_command

    return get_command(app)


def _options(command) -> set:
    return {opt for p in command.params for opt in (*p.opts, *p.secondary_opts)}


# --------------------------------------------------------------------------- #
# how-to/deploy-on-aws.md
# --------------------------------------------------------------------------- #


def _template_parameters(target: str) -> Dict[str, dict]:
    document = json.loads(
        (CDK_TEMPLATES / f"{target}.template.json").read_text(encoding="utf-8")
    )
    return document["Parameters"]


def test_each_deploy_target_has_the_template_and_module_the_page_names():
    assert_on_page(
        DEPLOY_PAGE,
        "Each target comes as a CDK stack, with its synthesized CloudFormation "
        "template committed, and as a Terraform module.",
    )
    rows = _table_rows(DEPLOY_PAGE, "| Target |")
    assert len(rows) == 5, rows
    for _target, _what, template, module in rows:
        template_file = CDK_TEMPLATES / f"{_code(template)}.template.json"
        assert template_file.is_file(), f"no committed template {template_file.name}"
        assert (TERRAFORM_MODULES / _code(module) / "main.tf").is_file(), module
    assert {p.name for p in TERRAFORM_MODULES.iterdir() if p.is_dir()} == {
        _code(row[3]) for row in rows
    }, "the deploy directory holds a Terraform module the page does not list"


def test_the_templates_default_one_release_and_terraform_has_no_default():
    assert_on_page(
        DEPLOY_PAGE,
        "`AshVersion`, the git ref the image is built from, defaults in the "
        "CloudFormation templates to the ASH release they ship in. The Terraform "
        "`ash_version` variable has no default, and the Terraform examples pin the "
        "same release.",
    )
    defaults = {
        template.name: _template_parameters(template.name.split(".")[0])["AshVersion"][
            "Default"
        ]
        for template in CDK_TEMPLATES.glob("*.template.json")
    }
    assert len(defaults) == 5, defaults
    assert len(set(defaults.values())) == 1, defaults
    (release,) = set(defaults.values())
    assert re.fullmatch(r"v\d+\.\d+\.\d+", release), release

    variables = (TERRAFORM_MODULES / "ash-image-pipeline" / "variables.tf").read_text(
        encoding="utf-8"
    )
    block = variables[variables.index('variable "ash_version"') :]
    block = block[: block.index("\nvariable ", 1)]
    assert not re.search(r"^\s*default\s*=", block, re.MULTILINE), block

    pins = re.findall(
        r'^\s*ash_version\s*=\s*"([^"]+)"',
        "\n".join(
            path.read_text(encoding="utf-8")
            for path in TERRAFORM_MODULES.glob("*/examples/*/main.tf")
        ),
        re.MULTILINE,
    )
    assert len(pins) >= 5 and set(pins) == {release}, pins


def test_the_fargate_ingress_cidr_is_empty_by_default_and_rejects_the_whole_internet():
    assert_on_page(
        DEPLOY_PAGE,
        "has no ingress rule until you set `McpIngressCidr`, which rejects "
        "`0.0.0.0/0`. With it empty, nothing can reach the endpoint.",
    )
    parameter = _template_parameters("AshFargate")["McpIngressCidr"]
    assert parameter["Default"] == ""
    pattern = re.compile(parameter["AllowedPattern"])
    assert pattern.fullmatch("") and pattern.fullmatch("10.0.0.0/8")
    assert pattern.fullmatch("0.0.0.0/0") is None


def test_the_mcp_targets_leave_the_auth_header_empty_by_default():
    assert_on_page(
        DEPLOY_PAGE,
        "Both MCP targets: the server checks a shared header only when you set "
        "`McpAuthHeaderName` and `McpAuthHeaderValue`. Both are empty by default",
    )
    for target in ("AshFargate", "AshAgentCore"):
        parameters = _template_parameters(target)
        assert parameters["McpAuthHeaderName"]["Default"] == "", target
        assert parameters["McpAuthHeaderValue"]["Default"] == "", target


def test_the_image_the_targets_build_has_no_sandbox_backend():
    assert_on_page(
        DEPLOY_PAGE, "The image the targets build has neither bubblewrap nor firejail."
    )
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8").lower()
    assert "hadolint" in dockerfile, "the control read nothing: no hadolint stage"
    for backend in ("bubblewrap", "bwrap", "firejail"):
        assert backend not in dockerfile, f"the Dockerfile installs {backend}"


def test_the_stateless_mcp_option_the_page_relies_on_exists():
    assert_on_page(
        DEPLOY_PAGE,
        "The targets need options that no release up to 3.7.1 has: stateless MCP "
        "(`ash mcp --stateless-http`)",
    )
    assert "--stateless-http" in _options(_click_commands().commands["mcp"])


def test_the_scan_step_construct_exists_and_is_not_published():
    assert_on_page(
        DEPLOY_PAGE,
        "`ASHScanStep`, a construct that adds an ASH scan to a CDK Pipelines "
        "pipeline. It is not published to npm or any other registry; you build it "
        "from the repository to use it.",
    )
    constructs = REPO_ROOT / "deploy" / "cdk-constructs"
    source = (constructs / "src" / "ash-scan-step.ts").read_text(encoding="utf-8")
    assert "export class ASHScanStep" in source
    package = json.loads((constructs / "package.json").read_text(encoding="utf-8"))
    assert package["private"] is True


# --------------------------------------------------------------------------- #
# integrations.md
# --------------------------------------------------------------------------- #


def test_the_pre_commit_hooks_run_the_modes_the_page_gives_them():
    assert_on_page(
        INTEGRATIONS_PAGE,
        "The `ash` and `ash-simple-scan` hooks use `--mode=precommit`, which runs a "
        "fixed, fast scanner set. The `ash-full-scan` hook uses `--mode=container`.",
    )
    hooks = {
        hook["id"]: hook["entry"]
        for hook in yaml.safe_load(
            (REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
        )
    }
    assert "--mode=precommit" in hooks["ash"]
    assert "--mode=precommit" in hooks["ash-simple-scan"]
    assert "--mode=container" in hooks["ash-full-scan"]


def test_the_page_lists_a_directory_for_every_agent_platform_there_is():
    assert_on_page(
        INTEGRATIONS_PAGE,
        "The [agent plugin guide](how-to/agent-plugins.md#choose-your-platform) has "
        "setup steps for these 16 platforms:",
    )
    rows = _table_rows(INTEGRATIONS_PAGE, "| Client |")
    listed = {_code(row[1]).rstrip("/") for row in rows}
    assert len(rows) == 16 and len(listed) == 16, rows
    plugins = (REPO_ROOT / "ash-agent-plugins" / "agentic-coding" / "plugins").iterdir()
    assert {p.name for p in plugins if p.is_dir()} == listed


def test_the_reusable_workflow_takes_a_local_or_container_mode():
    assert_on_page(
        INTEGRATIONS_PAGE,
        "Reusable workflows; `ash-mode` takes `local` or `container`",
    )
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml").read_text(
            encoding="utf-8"
        )
    )
    # PyYAML reads the key `on` as the boolean True.
    inputs = (workflow.get("on") or workflow[True])["workflow_call"]["inputs"]
    assert inputs["ash-mode"]["default"] == "local"
    assert "container" in inputs["ash-mode"]["description"]


def test_plugin_modules_are_named_by_a_config_key_an_option_and_an_environment_variable():
    assert_on_page(
        INTEGRATIONS_PAGE,
        "Tell ASH which Python modules hold your plugins with any of three inputs:",
    )
    assert_on_page(
        INTEGRATIONS_PAGE,
        "the `ASH_PLUGIN_MODULES` environment variable, which `ash scan` reads as the "
        "option's default.",
    )
    from automated_security_helper.config.ash_config import AshConfig

    assert "ash_plugin_modules" in AshConfig.model_fields
    scan = _click_commands().commands["scan"]
    option = next(p for p in scan.params if "--ash-plugin-modules" in p.opts)
    assert option.envvar == "ASH_PLUGIN_MODULES"


def test_the_aws_reporters_the_page_lists_are_registered():
    assert_on_page(
        INTEGRATIONS_PAGE,
        "| AWS Security Hub | [Security Hub reporter](plugins/aws.md) |",
    )
    assert {
        "aws-security-hub",
        "s3",
        "cloudwatch-logs",
        "bedrock-summary-reporter",
    } == set(AWS_REPORTER_NAMES)


# --------------------------------------------------------------------------- #
# how-to/aidlc-workflows.md
# --------------------------------------------------------------------------- #


def test_the_aidlc_plugin_the_page_points_to_is_there_and_named_as_the_page_says():
    assert_on_page(
        AIDLC_PAGE,
        "ASH's repository ships an AI-DLC plugin,",
    )
    manifest = json.loads(
        (AIDLC_PLUGIN / ".aidlc-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    assert manifest["name"] == "ash-scan"
    assert manifest["dependencies"] == ["core"]


def test_the_plugin_runs_the_two_scans_at_the_two_checkpoints_the_page_names():
    assert_on_page(
        AIDLC_PAGE,
        "the developer agent runs `ash --mode precommit --no-progress` and fixes "
        "actionable findings, or records suppressions with reasons and expiration "
        "dates, before the Unit's completion handoff.",
    )
    assert_on_page(
        AIDLC_PAGE,
        "the quality agent runs a full `ash scan --no-progress`, copies the scanner "
        "table into the stage summary for the approval gate, and does not proceed "
        "while the scan exits 1 or 2.",
    )
    construction = AIDLC_PLUGIN / "contributions" / "construction"
    generation = (construction / "code-generation.md").read_text(encoding="utf-8")
    assert "ash --mode precommit --no-progress" in generation
    build = (construction / "build-and-test.md").read_text(encoding="utf-8")
    assert "ash scan --no-progress" in build

    commands = _click_commands()
    assert "--no-progress" in _options(commands.commands["scan"])
    mode = next(p for p in commands.commands["scan"].params if "--mode" in p.opts)
    assert "precommit" in list(getattr(mode.type, "choices", []))


def test_the_plugin_rules_keep_the_habits_the_page_lists_and_ship_no_compose_hook():
    assert_on_page(
        AIDLC_PAGE,
        "a short rules file keeps the ASH habits in front of the agent: read the exit "
        "code, never loosen the gate to pass, never commit `.ash/ash_output/`.",
    )
    assert_on_page(
        AIDLC_PAGE,
        "Validation notes that the plugin ships no `hooks/compose.ts`; that is "
        "expected.",
    )
    rules = " ".join(
        (AIDLC_PLUGIN / "memory" / "rules.md").read_text(encoding="utf-8").split()
    )
    assert "Read the exit code" in rules
    assert "Never turn off `fail_on_findings`" in rules
    assert "never commit it" in rules and ".ash/ash_output/" in rules
    assert not (AIDLC_PLUGIN / "hooks" / "compose.ts").exists()


def test_a_suppression_takes_the_reason_and_expires_the_page_says_agents_record():
    assert_on_page(
        AIDLC_PAGE,
        "a finding it accepts becomes an entry under `global_settings.suppressions` "
        "with a reason and an `expires` date",
    )
    from automated_security_helper.models.core import AshSuppression

    fields = AshSuppression.model_fields
    assert "reason" in fields and "expires" in fields


# --------------------------------------------------------------------------- #
# how-to/express-mode.md
# --------------------------------------------------------------------------- #

unix_only = pytest.mark.skipif(
    os.name == "nt", reason="express mode is unix only, as the page says"
)


def test_the_daemon_idles_out_after_30_minutes_and_two_settings_change_that():
    assert_on_page(
        EXPRESS_PAGE,
        "The daemon retires itself after 30 minutes without a request (configure "
        "with the `--idle-seconds` option of `ash express start`, or the "
        "`ASH_EXPRESS_IDLE_SECONDS` environment variable)",
    )
    from automated_security_helper.express import runtime

    assert runtime.DEFAULT_IDLE_SECONDS == 30 * 60
    assert runtime.IDLE_ENV == "ASH_EXPRESS_IDLE_SECONDS"
    assert runtime.idle_seconds({}) == 1800
    assert runtime.idle_seconds({runtime.IDLE_ENV: "60"}) == 60
    start = _click_commands().commands["express"].commands["start"]
    assert {"--idle-seconds", "--foreground"} <= _options(start)


def test_the_express_commands_and_scan_flags_the_page_uses_exist():
    assert_on_page(
        EXPRESS_PAGE,
        "Or manage it explicitly -- `start` is idempotent, takes `--idle-seconds` and "
        "`--foreground`, and `status` takes `--json` for scripts:",
    )
    express = _click_commands().commands["express"]
    assert {"start", "status", "stop"} <= set(express.commands)
    assert "--json" in _options(express.commands["status"])
    assert {"--express", "--no-express"} <= _options(_click_commands().commands["scan"])


@unix_only
def test_the_socket_lives_in_a_private_directory_the_page_names(tmp_path):
    assert_on_page(
        EXPRESS_PAGE,
        "It lives in a **0700 directory owned by you** (`$XDG_RUNTIME_DIR/ash-express`, "
        "or `~/.ash/run`), and the socket file itself is 0600.",
    )
    from automated_security_helper.express import runtime

    runtime_base = tmp_path / "xdg"
    runtime_base.mkdir()
    directory = runtime.runtime_dir({"XDG_RUNTIME_DIR": str(runtime_base)})
    assert directory == runtime_base / "ash-express"
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700

    home = tmp_path / "home"
    home.mkdir()
    fallback = runtime.runtime_dir({"HOME": str(home)})
    assert fallback == home / ".ash" / "run"
    assert stat.S_IMODE(fallback.stat().st_mode) == 0o700


def test_the_daemon_keeps_the_environment_the_page_lists_and_a_request_drops_one_marker():
    assert_on_page(
        EXPRESS_PAGE,
        "`PYTHONPATH`, `PYTHONHOME`, `PYTHONUSERBASE`, `PYTHONNOUSERSITE` and "
        "`VIRTUAL_ENV`.",
    )
    assert_on_page(
        EXPRESS_PAGE,
        "minus ASH's internal express child marker.",
    )
    from automated_security_helper.express import runtime

    kept = {
        "PATH": "/usr/bin",
        "HOME": "/home/x",
        "PYTHONHOME": "/py",
        "PYTHONUSERBASE": "/ub",
        "PYTHONNOUSERSITE": "1",
        "VIRTUAL_ENV": "/venv",
    }
    dropped = {"AWS_PROFILE": "p", "GIT_INDEX_FILE": "/i", "LD_PRELOAD": "/x.so"}
    scrubbed = runtime.scrubbed_daemon_environment({**kept, **dropped})
    assert scrubbed == kept
    assert runtime.REQUEST_ENV_DENYLIST == frozenset({"ASH_EXPRESS_CHILD"})


# --------------------------------------------------------------------------- #
# docs/plugins/builtin/gitleaks.md
# --------------------------------------------------------------------------- #


def test_gitleaks_is_on_by_default_and_its_options_default_as_the_page_shows():
    assert_on_page(
        GITLEAKS_PAGE,
        "Gitleaks is a builtin scanner, enabled by default: a default scan runs it.",
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
        GitleaksScannerConfig,
        GitleaksScannerConfigOptions,
    )

    assert GitleaksScannerConfig.model_fields["enabled"].default is True
    options = GitleaksScannerConfigOptions()
    assert options.config_file is None
    assert options.baseline_path is None
    assert options.honor_inline_ignores is False
    assert options.max_target_megabytes is None
    assert options.scan_timeout == 1800
    assert options.severity_threshold is None


def test_gitleaks_is_run_the_way_the_page_says_and_exits_2_for_leaks():
    assert_on_page(
        GITLEAKS_PAGE,
        "ASH always runs `gitleaks --redact=100`, so gitleaks writes `REDACTED` in "
        "place of each secret in its report and its log.",
    )
    assert_on_page(
        GITLEAKS_PAGE,
        "ASH runs `gitleaks --exit-code=2`, because gitleaks otherwise exits 1 both "
        "when it finds leaks and when it fails. 0 (nothing found) and 2 (leaks "
        "found) are success",
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
        LEAKS_EXIT_CODE,
        GitleaksScanner,
    )

    source = (SCANNERS / "gitleaks_scanner.py").read_text(encoding="utf-8")
    for flag in (
        '"--redact=100"',
        'f"--exit-code={LEAKS_EXIT_CODE}"',
        "--ignore-gitleaks-allow",
    ):
        assert flag in source, flag
    assert 'self.subcommands = ["dir"]' in source
    assert LEAKS_EXIT_CODE == 2
    assert GitleaksScanner.success_exit_codes == {0, 2}


# --------------------------------------------------------------------------- #
# docs/plugins/builtin/zizmor.md
# --------------------------------------------------------------------------- #


def test_zizmor_is_on_by_default_and_its_options_default_as_the_page_shows():
    assert_on_page(
        ZIZMOR_PAGE,
        "zizmor is a builtin scanner, enabled by default: a default scan runs it.",
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        ZizmorScannerConfig,
        ZizmorScannerConfigOptions,
    )

    assert ZizmorScannerConfig.model_fields["enabled"].default is True
    options = ZizmorScannerConfigOptions()
    assert options.persona == "regular"
    assert options.config_file is None
    assert options.online_audits is False
    assert options.honor_inline_ignores is False
    assert options.tool_version == ">=1.29.0,<2.0.0"
    assert options.install_timeout == 300
    assert options.scan_timeout == 1800
    assert options.severity_threshold is None


def test_zizmor_runs_offline_without_tokens_and_without_the_repository_config():
    assert_on_page(
        ZIZMOR_PAGE,
        "ASH always runs `zizmor --offline` unless `online_audits: true`.",
    )
    assert_on_page(
        ZIZMOR_PAGE,
        "While offline, ASH removes those three variables from zizmor's environment.",
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        zizmor_scanner,
    )

    assert zizmor_scanner.GITHUB_TOKEN_ENV_VARS == (
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ZIZMOR_GITHUB_TOKEN",
    )
    assert set(zizmor_scanner.ZIZMOR_BEHAVIOR_ENV_VARS) >= {
        "ZIZMOR_CONFIG",
        "ZIZMOR_OFFLINE",
        "ZIZMOR_NO_ONLINE_AUDITS",
    }
    source = (SCANNERS / "zizmor_scanner.py").read_text(encoding="utf-8")
    for flag in ("--offline", "--no-config", "--no-ignores"):
        assert flag in source, flag


def test_the_zizmor_severity_table_is_the_mapping_the_scanner_applies():
    assert_on_page(
        ZIZMOR_PAGE,
        "zizmor's scale stops at High, so no zizmor finding is CRITICAL.",
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        map_zizmor_severity,
    )

    rows = _table_rows(ZIZMOR_PAGE, "| zizmor severity")
    assert len(rows) == 4, rows
    for severity, confident, low_confidence in rows:
        assert map_zizmor_severity(severity, "High", None) == confident, severity
        assert map_zizmor_severity(severity, "Medium", None) == confident, severity
        assert map_zizmor_severity(severity, "Low", None) == low_confidence, severity
        assert "CRITICAL" not in (confident, low_confidence)


def test_both_deduplication_switches_are_off_by_default_and_independent():
    assert_on_page(
        "how-to/deduplicate-findings.md",
        "Both are off by default, and they are independent: `fold` does not need "
        "`annotate`.",
    )
    from automated_security_helper.config.ash_config import AshDeduplicationConfig

    default = AshDeduplicationConfig()
    assert (default.annotate, default.fold) == (False, False)
    assert AshDeduplicationConfig(fold=True).annotate is False
    assert AshDeduplicationConfig(annotate=True).fold is False
