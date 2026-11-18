# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Claims of the six docs pages that no claims test, runnable block or inventory held.

A coverage audit found these pages with none of the three: how-to/deploy-on-aws.md,
integrations.md, reference/configuration.md, and developer-guide/interface-design.md,
interface-review.md and high-end-design-review.md. Each test here follows the pattern of
test_page_claims.py, in two halves: ``assert_on_page`` checks that the sentence is still
on its page, and the test then probes the code, the committed deployment templates or the
assets that make it true. A test goes red when either half moves.

What each page now has pinned, and where a claim on it is not pinned:

- how-to/deploy-on-aws.md: the five targets and the template and module each names, the
  ``AshVersion`` default and the Terraform ``ash_version`` that has none, the ingress CIDR
  that rejects ``0.0.0.0/0``, the empty auth-header defaults, the sandbox backends the
  image lacks, ``ash mcp --stateless-http``, and the unpublished ``ASHScanStep``. Not
  pinned: the network defaults of the Terraform modules, and what a deployed stack does.
- integrations.md: what each pre-commit hook runs, the sixteen agent platforms and their
  directories, ``ash-mode`` of the reusable workflow, the three ways to name plugin
  modules, and the AWS reporters the page lists.
- reference/configuration.md: the order in which discovery looks for a config file, the
  names read only from the source directory, the ``[tool.ash]`` rule for pyproject.toml,
  and the bounds on an ``extends`` chain. The tables of keys are generated from the
  models and held fresh by scripts/generate_config_reference.py --check.
- developer-guide/interface-design.md: the palette of the three surfaces, the footer
  credit, the motion timings, the vendored Anime.js and the canonical editor workflow.
  The site stylesheet declares no critical color and no dark low color, although the
  page says the site stylesheet declares the palette's variables; that gap is recorded
  in ``SITE_STYLESHEET_LACKS`` and not asserted either way.
- developer-guide/interface-review.md: the files it names, the commands of its surface
  inventory and the nineteen reporters of its table.
- developer-guide/high-end-design-review.md: the nineteen shipped reporters it lists.
  Not pinned: its seven navigation groups (Start here, Scan & triage, ...), which are
  not the top-level entries of docs/content/.nav.yml (Who uses ASH, Getting started,
  How-to guides, Concepts, Reference, Plugins, Contributing, FAQ, Support).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
import yaml

from tests.snapshot.support.reporter_catalog import (
    AWS_REPORTER_NAMES,
    BUILTIN_REPORTER_NAMES,
)
from tests.unit.docs.test_page_claims import CONTENT, assert_on_page

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
DEPLOY_PAGE = "how-to/deploy-on-aws.md"
INTEGRATIONS_PAGE = "integrations.md"
CONFIGURATION_PAGE = "reference/configuration.md"
INTERFACE_DESIGN = "developer-guide/interface-design.md"
INTERFACE_REVIEW = "developer-guide/interface-review.md"
HIGH_END_REVIEW = "developer-guide/high-end-design-review.md"

CDK_TEMPLATES = REPO_ROOT / "deploy" / "cdk" / "templates"
TERRAFORM_MODULES = REPO_ROOT / "deploy" / "terraform" / "modules"
SITE_STYLESHEET = CONTENT / "assets" / "stylesheets" / "ash.css"
REPORT_STYLESHEET = (
    REPO_ROOT
    / "automated_security_helper"
    / "plugin_modules"
    / "ash_builtin"
    / "reporters"
    / "assets"
    / "ash-report.css"
)

#: Colors of the page's palette table that the site stylesheet does not carry: critical
#: and error (both themes) and the dark low-severity color. The page says the site and
#: offline report styles both declare the palette's variables; the offline report
#: stylesheet carries every color, the site stylesheet all but these three.
SITE_STYLESHEET_LACKS = frozenset({"#ff7a7a", "#db0000", "#f2cd54"})


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
    options = {opt for p in _click_commands().commands["mcp"].params for opt in p.opts}
    assert "--stateless-http" in options


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
# reference/configuration.md
# --------------------------------------------------------------------------- #


def _the_discovery_list_on_the_page() -> List[str]:
    lines = _page_lines(CONFIGURATION_PAGE)
    start = next(
        i for i, line in enumerate(lines) if line.startswith("## Where ASH finds")
    )
    listed = []
    for line in lines[start + 1 :]:
        if line.startswith("## "):
            break
        found = re.match(r"^\d+\. `([^`]+)`$", line)
        if found:
            listed.append(found.group(1))
    return listed


def _every_source(directory: Path) -> None:
    """Every file discovery looks for, present in ``directory``."""
    from automated_security_helper.core.constants import (
        ASH_CONFIG_FILE_NAMES,
        ASH_RC_FILE_NAMES,
    )

    for name in ASH_CONFIG_FILE_NAMES:
        (directory / ".ash").mkdir(exist_ok=True)
        (directory / name).write_text("project_name: a\n", encoding="utf-8")
        (directory / ".ash" / name).write_text("project_name: a\n", encoding="utf-8")
    for name in ASH_RC_FILE_NAMES:
        (directory / name).write_text("", encoding="utf-8")
    (directory / "pyproject.toml").write_text("[tool.ash]\n", encoding="utf-8")


def test_discovery_looks_for_a_config_file_in_the_order_the_page_lists(tmp_path):
    assert_on_page(
        CONFIGURATION_PAGE,
        "Otherwise ASH looks in the scan's source directory and uses the first of "
        "these it finds.",
    )
    from automated_security_helper.config.config_sources import discovery_candidates

    _every_source(tmp_path)
    found = [str(p.relative_to(tmp_path)) for p in discovery_candidates(tmp_path)]
    assert found == _the_discovery_list_on_the_page()
    assert len(found) == 21


def test_the_first_source_wins_and_the_others_are_ignored_with_a_warning(tmp_path):
    assert_on_page(
        CONFIGURATION_PAGE,
        "Sources are never merged: every other one that exists is ignored, with a "
        "warning naming it.",
    )
    from automated_security_helper.config.config_sources import (
        discover_config_source,
        discovery_warnings,
    )

    _every_source(tmp_path)
    discovery = discover_config_source(tmp_path)
    assert discovery.selected.path.name == ".ash.yml"
    assert len(discovery.ignored) == 20
    warnings = "\n".join(discovery_warnings(discovery))
    assert "ashrc.json" in warnings and ".ash.yaml" in warnings


def test_the_rc_names_and_pyproject_are_read_from_the_source_directory_only(tmp_path):
    assert_on_page(
        CONFIGURATION_PAGE,
        "These are read from the source directory only, never from `.ash/`: "
        "`.ashrc.toml`, `.ashrc.yaml`, `.ashrc.yml`, `.ashrc.json`, `ashrc.toml`, "
        "`ashrc.yaml`, `ashrc.yml`, `ashrc.json`, `pyproject.toml`.",
    )
    from automated_security_helper.config.config_sources import discover_config_source
    from automated_security_helper.core.constants import ASH_RC_FILE_NAMES

    (tmp_path / ".ash").mkdir()
    for name in (*ASH_RC_FILE_NAMES, "pyproject.toml"):
        (tmp_path / ".ash" / name).write_text("[tool.ash]\n", encoding="utf-8")
    assert discover_config_source(tmp_path).selected is None


def test_pyproject_is_a_source_only_with_a_tool_ash_table(tmp_path):
    assert_on_page(
        CONFIGURATION_PAGE,
        "`pyproject.toml` counts only when it has a `[tool.ash]` table; one without "
        "it is not a configuration source.",
    )
    from automated_security_helper.config.config_sources import discover_config_source

    (tmp_path / "pyproject.toml").write_text("[tool.other]\nx = 1\n", encoding="utf-8")
    assert discover_config_source(tmp_path).selected is None
    (tmp_path / "pyproject.toml").write_text("[tool.ash]\n", encoding="utf-8")
    selected = discover_config_source(tmp_path).selected
    assert selected is not None and selected.path == tmp_path / "pyproject.toml"


def test_an_extends_chain_is_bounded_as_the_page_says():
    assert_on_page(
        CONFIGURATION_PAGE,
        "A chain may be at most 10 levels deep and read at most 50 files.",
    )
    from automated_security_helper.core.constants import (
        ASH_CONFIG_EXTENDS_MAX_DEPTH,
        ASH_CONFIG_EXTENDS_MAX_FILES,
    )

    assert (ASH_CONFIG_EXTENDS_MAX_DEPTH, ASH_CONFIG_EXTENDS_MAX_FILES) == (10, 50)


# --------------------------------------------------------------------------- #
# developer-guide/interface-design.md, interface-review.md, high-end-design-review.md
# --------------------------------------------------------------------------- #

#: The page's palette roles, and the key of the terminal palette (ui_theme.COLORS).
PALETTE_KEYS = {
    "Background": "background",
    "Surface": "surface",
    "Text": "foreground",
    "Muted text": "muted",
    "Action and focus": "accent",
    "Critical and error": "critical",
    "High severity": "high",
    "Medium severity": "medium",
    "Low severity": "low",
    "Information": "info",
    "Success": "success",
}


def _palette() -> List[Tuple[str, str, str]]:
    """(role, dark, light) from the page's table."""
    return [
        (row[0], _code(row[1]), _code(row[2]))
        for row in _table_rows(INTERFACE_DESIGN, "| Role |")
    ]


def test_the_palette_table_is_the_terminal_palette_in_its_dark_column():
    assert_on_page(
        INTERFACE_DESIGN,
        "`automated_security_helper/utils/ui_theme.py` is the terminal palette and "
        "theme adapter.",
    )
    from automated_security_helper.utils.ui_theme import COLORS

    palette = _palette()
    assert [role for role, _d, _l in palette] == list(PALETTE_KEYS)
    for role, dark, _light in palette:
        assert COLORS[PALETTE_KEYS[role]] == dark, role


def test_the_report_stylesheet_carries_every_color_of_the_palette():
    assert_on_page(
        INTERFACE_DESIGN,
        "Check all three surfaces when changing a semantic color.",
    )
    css = REPORT_STYLESHEET.read_text(encoding="utf-8").lower()
    for role, dark, light in _palette():
        assert dark in css and light in css, role


def test_the_site_stylesheet_carries_the_palette_colors_it_uses():
    css = SITE_STYLESHEET.read_text(encoding="utf-8").lower()
    for role, dark, light in _palette():
        for color in (dark, light):
            if color not in SITE_STYLESHEET_LACKS:
                assert color in css, f"{role}: {color}"


def test_the_footer_credit_is_the_one_the_pages_give():
    from automated_security_helper.utils.ui_theme import FOOTER_CREDIT

    assert_on_page(INTERFACE_DESIGN, f"Footer: `{FOOTER_CREDIT}`.")
    assert_on_page(HIGH_END_REVIEW, f"`{FOOTER_CREDIT}` in human-facing footers.")


def test_the_motion_timings_are_the_ones_the_site_stylesheet_declares():
    assert_on_page(
        INTERFACE_DESIGN,
        "Use the shared custom easing curves and role-based timings: 160ms feedback, "
        "320ms menu entrance, 180ms exit, 40ms stagger, and 240ms section reveal.",
    )
    css = SITE_STYLESHEET.read_text(encoding="utf-8")
    for name, value in {
        "feedback": "160ms",
        "enter": "320ms",
        "exit": "180ms",
        "reveal": "240ms",
    }.items():
        assert re.search(rf"--ash-{name}:\s*{value};", css), name


def test_the_animation_library_is_vendored_at_the_version_the_page_names():
    assert_on_page(
        INTERFACE_DESIGN,
        "Light Phosphor icons and Anime.js 4.5.0 use MIT licenses.",
    )
    assert_on_page(
        INTERFACE_DESIGN,
        "Run `npm run vendor:motion` in `docs/ui-tests` to rebuild the module and its "
        "notice.",
    )
    tests_dir = REPO_ROOT / "docs" / "ui-tests"
    package = json.loads((tests_dir / "package.json").read_text(encoding="utf-8"))
    assert package["scripts"]["vendor:motion"] == "node vendor-motion.cjs"
    assert '"4.5.0"' in (tests_dir / "vendor-motion.cjs").read_text(encoding="utf-8")
    licenses = CONTENT / "assets" / "licenses"
    assert "Anime.js 4.5.0" in (licenses / "asset-provenance.txt").read_text(
        encoding="utf-8"
    )
    assert (licenses / "animejs-MIT.txt").is_file()
    assert (licenses / "phosphor-MIT.txt").is_file()


def test_the_human_report_outcome_comes_from_the_report_content_emitter():
    assert_on_page(
        INTERFACE_DESIGN,
        "`ReportContentEmitter.get_scan_summary()` supplies the factual outcome for "
        "human reports.",
    )
    from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
        ReportContentEmitter,
    )

    assert callable(getattr(ReportContentEmitter, "get_scan_summary", None))


def test_the_canonical_editor_workflow_lives_where_the_page_says():
    assert_on_page(
        INTERFACE_DESIGN,
        "Edit the canonical editor workflow under "
        "`ash-agent-plugins/agentic-coding/transpiler/_base/` and rebuild the "
        "integrations.",
    )
    base = REPO_ROOT / "ash-agent-plugins" / "agentic-coding" / "transpiler" / "_base"
    assert base.is_dir() and any(base.iterdir())


def test_the_files_the_interface_review_points_to_exist():
    assert_on_page(
        INTERFACE_REVIEW,
        "`scripts/preview_interfaces.py` and `docs/ui-tests/` make the human "
        "interfaces reproducible from repository fixtures.",
    )
    assert_on_page(
        INTERFACE_REVIEW,
        "Every shipped reporter is covered by the explicit reporter catalog in "
        "`tests/snapshot/support/reporter_catalog.py`.",
    )
    for path in (
        "scripts/preview_interfaces.py",
        "docs/ui-tests/README.md",
        "tests/snapshot/support/reporter_catalog.py",
    ):
        assert (REPO_ROOT / path).is_file(), path


def test_the_interface_review_reporter_table_lists_every_shipped_reporter():
    rows = _table_rows(INTERFACE_REVIEW, "| Reporter |")
    listed = [_code(row[0]) for row in rows]
    shipped = [*BUILTIN_REPORTER_NAMES, *AWS_REPORTER_NAMES]
    assert sorted(listed) == sorted(shipped)
    assert len(listed) == 19


def test_the_interface_review_surface_inventory_names_commands_that_exist():
    assert_on_page(
        INTERFACE_REVIEW,
        "| `plugin list` | Scanner/converter/reporter/event inventory,",
    )
    root = _click_commands()
    for name in ("scan", "build-image", "report", "merge", "get-genai-guide"):
        assert name in root.commands, name
    for group, subcommands in {
        "config": (
            "init",
            "get",
            "update",
            "wizard",
            "validate",
            "lint",
            "validate-plugin-dependencies",
        ),
        "dependencies": ("install",),
        "plugin": ("list",),
        "inspect": ("findings", "sarif-fields"),
    }.items():
        for subcommand in subcommands:
            assert subcommand in root.commands[group].commands, (group, subcommand)


def test_the_design_review_counts_the_reporters_there_are():
    assert_on_page(
        HIGH_END_REVIEW,
        "The final row includes **all nineteen shipped reporters**: HTML, Markdown, "
        "text, Bedrock summaries, CSV, flat JSON, SARIF, GitHub GHAS, GitLab SAST, "
        "CycloneDX, GitLab CycloneDX, SPDX, JUnit XML, OCSF, YAML, unused "
        "suppressions, Security Hub, CloudWatch Logs, and S3.",
    )
    assert len(BUILTIN_REPORTER_NAMES) + len(AWS_REPORTER_NAMES) == 19
