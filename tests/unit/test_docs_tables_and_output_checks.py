# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs checks hold tables, output samples and file names to the code.

The same contract as test_docs_checks_can_fail.py, for the rules that compare what a
page states with what the code does rather than with what the code is called: each
rule gets a synthetic page with one planted defect, which it must report, and a clean
page using every form the rule allows, which must pass.

- Output samples: an ``output`` marker binds a text block to the run block above it,
  and the sample is compared with that block's output after normalization;
  ``config kind=ash-output model=<dotted>`` validates a results excerpt against the
  output model, reporting keys the model does not declare.
- Defaults: a column that states defaults is either compared or reported; the phrases
  that stand for a default are accepted only where the code's default is what the
  phrase says; enabled-by-default columns are compared with each plugin's enabled
  default; env-table defaults with the env-var generator's data; Terraform variable
  tables with the module's variables.
- Completeness: an options marker with ``complete`` reports every key the table omits.
- File names: ``ash.<name>`` and ``reports/<name>`` spans name a file ASH writes.
- Scanner names in tables are scanners ASH ships.
- Plugin names next to a third-party module are still checked.
- Reasons, config paths and environment-variable families are checked as strictly as
  their forms allow.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CHECKS_PATH = REPO_ROOT / "scripts" / "docs_checks.py"
FENCE = "```"


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


dc = _load("_ash_docs_checks", CHECKS_PATH)


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _git_root(root: Path) -> Path:
    """Make root a git repository, so a check can list the files under it
    (dc.listed_files lists them as untracked)."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True, capture_output=True)
    return root


def _messages(findings) -> list[str]:
    return [str(f) for f in findings]


def _assert_reports(findings, expected: str, line: int | None = None) -> None:
    hits = [f for f in findings if expected in f.message]
    assert hits, (
        f"expected a finding containing {expected!r}, got: {_messages(findings)}"
    )
    if line is not None:
        assert any(f.line == line for f in hits), (
            f"expected line {line}: {_messages(hits)}"
        )


def _table(of: str, header: str, *rows: str) -> str:
    divider = "|" + "---|" * (header.count("|") - 1)
    lines = [f"<!-- doctest: options {of} -->", header, divider, *rows]
    return "\n".join(lines) + "\n"


@pytest.fixture
def fixture_root(tmp_path):
    """A docs root with the default fixture project the marker check looks up."""
    (tmp_path / dc.DOC_FIXTURES_DIR / dc.DEFAULT_FIXTURE).mkdir(parents=True)
    return tmp_path


# ---------------------------------------------------------------------------
# Output samples: normalization and comparison
# ---------------------------------------------------------------------------

CLEAN_OUTPUT_MARKERS = f"""# Output samples

{FENCE}bash
echo hello
{FENCE}

Prose may sit between a block and its sample.

<!-- doctest: output -->
{FENCE}text
hello
{FENCE}

<!-- doctest: run expect-exit=2 -->
{FENCE}console
$ echo failed; exit 2
{FENCE}

<!-- doctest: output -->
{FENCE}text
failed
{FENCE}

{FENCE}python
print("from python")
{FENCE}

<!-- doctest: output -->
{FENCE}text
from python
{FENCE}

An unmarked text block after a block that does not run is not an output sample.

<!-- doctest: illustrative reason="needs Docker" -->
{FENCE}bash
docker ps
{FENCE}

{FENCE}text
CONTAINER ID   IMAGE
{FENCE}
"""

FOLLOWS_NO_RUN_BLOCK = "marked output but follows no run block"
_OUTPUT_SAMPLE = f"<!-- doctest: output -->\n{FENCE}text\nash scan --offline\n{FENCE}\n"

#: (case, page, line of the output marker the check must report)
OUTPUT_MARKER_DEFECTS = [
    ("the first block on the page", f"# Page\n\nProse.\n\n{_OUTPUT_SAMPLE}", 5),
    (
        "after an illustrative block",
        (
            f'# Page\n\n<!-- doctest: illustrative reason="needs Docker" -->\n'
            f"{FENCE}bash\ndocker ps\n{FENCE}\n\n{_OUTPUT_SAMPLE}"
        ),
        8,
    ),
    (
        "after a zsh block, which the runner does not run",
        (
            f'# Page\n\n<!-- doctest: illustrative reason="shows zsh setup" -->\n'
            f"{FENCE}zsh\nsetopt nomatch\n{FENCE}\n\n{_OUTPUT_SAMPLE}"
        ),
        8,
    ),
    (
        "after a config block",
        (
            f"# Page\n\n<!-- doctest: config kind=ash -->\n{FENCE}yaml\n"
            f"project_name: demo\n{FENCE}\n\n{_OUTPUT_SAMPLE}"
        ),
        8,
    ),
    (
        "after a block that is only saved",
        (
            f"# Page\n\n<!-- doctest: save-as=app.py -->\n{FENCE}python\n"
            f"print('saved, not run')\n{FENCE}\n\n{_OUTPUT_SAMPLE}"
        ),
        8,
    ),
    (
        "after another output sample",
        (
            f"# Page\n\n{FENCE}bash\necho one\n{FENCE}\n\n"
            f"<!-- doctest: output -->\n{FENCE}text\none\n{FENCE}\n\n{_OUTPUT_SAMPLE}"
        ),
        12,
    ),
    (
        "after an unmarked text block",
        f"# Page\n\n{FENCE}text\nnot a command\n{FENCE}\n\n{_OUTPUT_SAMPLE}",
        7,
    ),
]


def test_output_markers_pass_every_valid_form(fixture_root):
    page = _write(fixture_root, "docs/page.md", CLEAN_OUTPUT_MARKERS)
    assert dc.check_markers([page], fixture_root) == []


@pytest.mark.parametrize(
    "case,text,line",
    OUTPUT_MARKER_DEFECTS,
    ids=[case for case, _text, _line in OUTPUT_MARKER_DEFECTS],
)
def test_an_output_marker_that_follows_no_run_block_is_reported(
    fixture_root, case, text, line
):
    """An output marker turns off the CLI check for the block's ash lines, so it counts
    only where the runner compares the block with real output: directly after a block
    it runs. Anywhere else the marker would hide a command from the CLI check."""
    page = _write(fixture_root, "docs/page.md", text)
    findings = dc.check_markers([page], fixture_root)
    _assert_reports(findings, FOLLOWS_NO_RUN_BLOCK, line)
    assert len([f for f in findings if FOLLOWS_NO_RUN_BLOCK in f.message]) == 1


def test_an_output_sample_is_compared_exactly_where_the_cli_check_skips_it(
    fixture_root,
):
    """One rule decides both: the samples the runner compares are the blocks the CLI
    check reads as output, and every other output marker is reported."""
    text = CLEAN_OUTPUT_MARKERS + "\n".join(t for _c, t, _l in OUTPUT_MARKER_DEFECTS)
    page = dc.parse_page(_write(fixture_root, "docs/page.md", text), fixture_root)
    samples = dc.output_samples(page)
    marked = [
        block
        for block in page.blocks
        if block.marker is not None and block.marker.mode == dc.OUTPUT_MODE
    ]
    reported = {
        f.line
        for f in dc.check_markers([page.path], fixture_root)
        if FOLLOWS_NO_RUN_BLOCK in f.message
    }
    # Three in the clean page, plus the first sample of the "another sample" case.
    assert len(samples) == 4
    assert all(dc.runner_runs(source) for source in samples.values())
    for block in marked:
        assert (id(block) in samples) != (block.marker.line in reported), block


def test_output_normalization_strips_color_box_lines_timings_and_paths():
    """What the comparison ignores: ANSI, Rich's box drawing, durations, the session's
    paths, and runs of whitespace. Nothing else is rewritten."""
    replacements = (("/work/session/project", "."), ("/work/session/home", "~"))
    output = (
        "\x1b[1;32mPASSED\x1b[0m  bandit   took 1.23s\n"
        "┃ Scanner ┃ Time ┃\n"
        "│ bandit  │ 46ms │\n"
        "wrote /work/session/project/.ash/ash_output/reports/ash.sarif\n"
        "config in /work/session/home/.config/ash at 2026-10-11T12:00:01Z, 0:00:03 elapsed\n"
    )
    assert dc.normalize_output(output, replacements) == [
        "PASSED bandit took <time>",
        "Scanner Time",
        "bandit <time>",
        "wrote .ash/ash_output/reports/ash.sarif",
        "config in ~/.config/ash at <time>, <time> elapsed",
    ]


OUTPUT_TEXT = "Scanning . with 1 scanner\n│ detect-secrets │ 0 │ 2 │ PASSED │\nResults written to .ash/ash_output\nExit code: 0"


@pytest.mark.parametrize(
    "sample",
    [
        "Scanning . with 1 scanner\nResults written to .ash/ash_output",
        "Scanning . with 1 scanner\n...\nExit code: 0",
        "│ detect-secrets │ 0 │ 2 │ PASSED │",
        "detect-secrets ... PASSED",
        "\n\nExit code: 0\n",
    ],
)
def test_an_output_sample_matches_when_every_line_is_in_the_output(sample):
    assert dc.output_sample_problem(sample, OUTPUT_TEXT, ()) is None


@pytest.mark.parametrize(
    "sample,missing",
    [
        ("Scanning . with 2 scanners", "Scanning . with 2 scanners"),
        ("Exit code: 0\nScanning . with 1 scanner", "Scanning . with 1 scanner"),
        ("detect-secrets ... FAILED", "detect-secrets ... FAILED"),
        ("2 actionable", "2 actionable"),
    ],
    ids=["changed line", "lines out of order", "wildcard line", "invented line"],
)
def test_an_output_sample_fails_on_a_line_the_output_lacks(sample, missing):
    problem = dc.output_sample_problem(sample, OUTPUT_TEXT, ())
    assert problem is not None
    _offset, line = problem
    assert line == missing


def test_a_changed_count_in_the_reporter_tutorials_sample_is_caught():
    """The count changed to `2 actionable` in the sample of the reporter tutorial's
    "Scan with it" step, where the reporter writes the count of actionable findings on
    its first line."""
    output = "1 actionable\nbandit B602 app.py:7"
    assert dc.output_sample_problem("1 actionable", output, ()) is None
    assert dc.output_sample_problem("2 actionable", output, ()) == (0, "2 actionable")


# ---------------------------------------------------------------------------
# Output samples: config kind=ash-output model=<dotted>
# ---------------------------------------------------------------------------

STATUS_MODEL = (
    "automated_security_helper.models.asharp_model.AshAggregatedResults.scanner_results"
)
RESULT_MODEL = "automated_security_helper.schemas.sarif_schema_model.Result"

#: A scanner_results row with fields every ASH this runs against declares.
STATUS_ROW = {
    "status": "MISSING",
    "dependencies_satisfied": True,
    "excluded": False,
    "finding_count": 0,
    "actionable_finding_count": 0,
    "suppressed_finding_count": 0,
    "exit_code": 0,
    "duration": 0.0,
}


def _ash_output(model: str, document) -> str:
    return (
        f"<!-- doctest: config kind=ash-output model={model} -->\n"
        f"{FENCE}json\n{json.dumps(document, indent=2)}\n{FENCE}\n"
    )


CLEAN_ASH_OUTPUT = "\n".join(
    [
        _ash_output(STATUS_MODEL, {"gitleaks": STATUS_ROW}),
        _ash_output(
            RESULT_MODEL,
            {
                "ruleId": "B602",
                "level": "error",
                "message": {"text": "subprocess call with shell=True"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "app.py"},
                            "region": {"startLine": 7},
                        }
                    }
                ],
                # A SARIF property bag is open by the spec: its keys are not checked.
                "properties": {"tags": ["bandit"], "scanner_name": "bandit"},
            },
        ),
    ]
)

ASH_OUTPUT_DEFECTS = [
    (
        "a field the model lacks, as missing_reasons in a scanner row",
        _ash_output(
            STATUS_MODEL,
            {"gitleaks": {**STATUS_ROW, "missing_reasons": "found only in the tree"}},
        ),
        "gitleaks.missing_reasons is not a field of ScannerTargetStatusInfo",
    ),
    (
        "a nested field the model lacks",
        _ash_output(
            STATUS_MODEL,
            {"gitleaks": {**STATUS_ROW, "severity_counts": {"critcal": 0}}},
        ),
        "gitleaks.severity_counts.critcal is not a field of ScannerSeverityCount",
    ),
    (
        "a value of the wrong type",
        _ash_output(
            STATUS_MODEL, {"gitleaks": {**STATUS_ROW, "finding_count": "lots"}}
        ),
        "finding_count",
    ),
    (
        "a status ASH does not have",
        _ash_output(STATUS_MODEL, {"gitleaks": {**STATUS_ROW, "status": "BROKEN"}}),
        "status",
    ),
    (
        "a SARIF key the spec lacks",
        _ash_output(
            RESULT_MODEL,
            {"ruleId": "B602", "message": {"text": "x"}, "rule_id": "B602"},
        ),
        "rule_id",
    ),
    (
        "no model",
        f"<!-- doctest: config kind=ash-output -->\n{FENCE}json\n{{}}\n{FENCE}\n",
        "config kind=ash-output needs model=",
    ),
    (
        "a model that does not exist",
        _ash_output("automated_security_helper.models.asharp_model.NoSuchModel", {}),
        "asharp_model has no NoSuchModel",
    ),
    (
        "a module that does not exist",
        _ash_output("automated_security_helper.no_such_module.Model", {}),
        "automated_security_helper has no no_such_module",
    ),
    (
        "not a pydantic model",
        _ash_output("automated_security_helper.core.enums.ScannerToolType", {}),
        "automated_security_helper.core.enums.ScannerToolType is not a pydantic model",
    ),
    (
        "a model outside ASH",
        _ash_output("json.JSONDecoder", {}),
        "model=json.JSONDecoder names no class in automated_security_helper",
    ),
    (
        "a field the model does not have",
        _ash_output(
            "automated_security_helper.models.asharp_model.AshAggregatedResults.scanner_rows",
            {},
        ),
        "AshAggregatedResults has no field scanner_rows",
    ),
]


def test_ash_output_blocks_pass_every_valid_form(fixture_root):
    page = _write(fixture_root, "docs/page.md", CLEAN_ASH_OUTPUT)
    assert dc.check_markers([page], fixture_root) == []
    assert dc.check_config_blocks([page], fixture_root) == []


@pytest.mark.parametrize(
    "case,text,expected", ASH_OUTPUT_DEFECTS, ids=[c[0] for c in ASH_OUTPUT_DEFECTS]
)
def test_ash_output_check_can_fail(fixture_root, case, text, expected):
    page = _write(fixture_root, "docs/page.md", text)
    findings = dc.check_markers([page], fixture_root) + dc.check_config_blocks(
        [page], fixture_root
    )
    _assert_reports(findings, expected)


def test_the_status_models_allow_extras_so_pydantic_alone_misses_a_renamed_key():
    """Why the keys are compared explicitly: pydantic keeps an undeclared key here."""
    from automated_security_helper.models.asharp_model import ScannerTargetStatusInfo

    assert ScannerTargetStatusInfo.model_config.get("extra") == "allow"
    ScannerTargetStatusInfo.model_validate({**STATUS_ROW, "missing_reasons": "x"})


def test_open_output_models_are_the_sarif_property_bag():
    """OPEN_OUTPUT_MODELS exempts these from the key comparison; pin why."""
    from automated_security_helper.schemas import sarif_schema_model

    assert dc.OPEN_OUTPUT_MODELS == frozenset({"PropertyBag"})
    bag = sarif_schema_model.PropertyBag
    assert bag.model_config.get("extra") == "allow"
    assert (
        dc._model_of(sarif_schema_model.Result.model_fields["properties"].annotation)[1]
        is bag
    )


# ---------------------------------------------------------------------------
# Defaults: columns, phrases, enabled-by-default, env tables, Terraform
# ---------------------------------------------------------------------------

CLEAN_DEFAULTS = """# Defaults

<!-- doctest: options of=scanners.bandit -->
| Option | Default |
|---|---|
| `confidence_level` | `all` |

<!-- doctest: options of=scanners.* -->
| Key | Default |
|---|---|
| `name` | the plugin's own name |
| `options` | the plugin's defaults |
| `enabled` | `true` |

<!-- doctest: options of=reporters -->
| Key | Enabled by default |
|---|---|
| `sarif` | yes |
| `spdx` | no |
| `yaml` | no |
| `s3` | yes |

<!-- doctest: options of=scanners -->
| Scanner | Enabled by default |
|---|---|
| [`bandit`](#bandit) | yes on Linux and macOS; yes on Windows |
| `ferret-scan` | yes |
"""

DEFAULT_DEFECTS = [
    (
        "a marked table's renamed Default column",
        _table(
            "of=scanners.bandit",
            "| Option | Type | Default when unset | Description |",
            "| `confidence_level` | string | `high` | x |",
        ),
        "column 'Default when unset' states defaults, but it is not compared",
        1,
    ),
    (
        "an unmarked table with a renamed Default column",
        "| Name | Default when unset |\n|---|---|\n| `confidence_level` | `high` |\n",
        "documents options or keys but names no section",
        1,
    ),
    (
        "an unmarked On by default column",
        "| Scanner | On by default |\n|---|---|\n| `bandit` | yes |\n",
        "documents options or keys but names no section",
        1,
    ),
    (
        "computed at run time for a static default",
        _table(
            "of=scanners.bandit",
            "| Option | Default |",
            "| `confidence_level` | computed at run time |",
        ),
        "'confidence_level' default says computed at run time, but the default is `\"all\"`",
        4,
    ),
    (
        "depends on the platform for a static default",
        _table(
            "of=scanners.bandit",
            "| Option | Default |",
            "| `confidence_level` | depends on the platform |",
        ),
        "'confidence_level' default says depends on the platform",
        4,
    ),
    (
        "the plugin's own name for a key that is not name",
        _table(
            "of=scanners.*",
            "| Key | Default |",
            "| `enabled` | the plugin's own name |",
        ),
        "'enabled' default says the plugin's own name, but the default is `true`",
        4,
    ),
    (
        "the plugin's defaults for a key that is not options",
        _table(
            "of=scanners.bandit",
            "| Option | Default |",
            "| `ignore_nosec` | the plugin's defaults |",
        ),
        "'ignore_nosec' default says the plugin's defaults",
        4,
    ),
    (
        "a reporter said to be enabled that is not",
        _table("of=reporters", "| Key | Enabled by default |", "| `spdx` | yes |"),
        "'spdx' enabled by default says yes, but its enabled default is `false`",
        4,
    ),
    (
        "a scanner said to be disabled that is not",
        _table("of=scanners", "| Scanner | Enabled by default |", "| `bandit` | no |"),
        "'bandit' enabled by default says no, but its enabled default is `true`",
        4,
    ),
    (
        "an enabled column for keys that are not plugins",
        _table("of=global_settings", "| Key | Enabled by default |", "| `mcp` | yes |"),
        "states whether each plugin is enabled, but of=global_settings names no plugin section",
        1,
    ),
]


def test_default_columns_pass_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_DEFAULTS)
    assert dc.check_option_tables([page], tmp_path) == []


@pytest.mark.parametrize(
    "case,text,expected,line", DEFAULT_DEFECTS, ids=[c[0] for c in DEFAULT_DEFECTS]
)
def test_default_columns_can_fail(tmp_path, case, text, expected, line):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_option_tables([page], tmp_path), expected, line)


def test_default_phrases_not_compared_are_pinned():
    """Four phrases stand for a default; each is one the reference generators write,
    and each is accepted only where the code's default is what it says."""
    assert dc.DEFAULT_PHRASES_NOT_COMPARED == frozenset(
        {
            "computed at run time",
            "depends on the platform",
            "the plugin's own name",
            "the plugin's defaults",
        }
    )
    generators = "".join(
        (REPO_ROOT / "scripts" / name).read_text(encoding="utf-8")
        for name in ("generate_config_reference.py", "generate_cli_docs.py")
    )
    for phrase in dc.DEFAULT_PHRASES_NOT_COMPARED:
        assert f'"{phrase}"' in generators, phrase


class _PlatformModel:
    """Built lazily: a model whose defaults are computed, for the phrase rules."""

    @staticmethod
    def build():
        import os
        import platform

        from pydantic import BaseModel, Field, field_validator

        class Computed(BaseModel):
            workers: int = Field(default_factory=lambda: os.cpu_count() or 1)
            enabled: bool = platform.system().lower() != "windows"
            label: str = Field(default="x", validate_default=True)
            static: str = "fixed"

            @field_validator("label")
            @classmethod
            def _label(cls, value):
                return value.upper()

        return Computed


def test_a_phrase_is_accepted_only_where_the_code_computes_the_default():
    keys = dc._model_keys(_PlatformModel.build())
    assert dc.default_problem("computed at run time", keys["workers"]) is None
    assert dc.default_problem("computed at run time", keys["label"]) is None
    assert dc.default_problem("depends on the platform", keys["enabled"]) is None
    for phrase in ("computed at run time", "depends on the platform"):
        assert dc.default_problem(phrase, keys["static"]) is not None, phrase
    assert dc.default_problem("depends on the platform", keys["workers"]) is not None


# -- env tables ---------------------------------------------------------------


def _read_set(**defaults):
    read = dc.EnvReadSet(
        names={"ASH_FAKE_DIR", "ASH_FAKE_MODE", "ASH_FAKE_FLAG"},
        dynamic=[],
        source="test",
    )
    read.build_args, read.test_only = {}, {}
    read.defaults = defaults
    return read


ENV_DEFAULTS = {
    "ASH_FAKE_DIR": ["`~/.cache/ash`"],
    "ASH_FAKE_MODE": ["`local`", "`container`"],
    "ASH_FAKE_FLAG": [],
}

CLEAN_ENV_TABLE = """# Variables

| Variable | Default | Purpose |
|---|---|---|
| `ASH_FAKE_DIR` | `~/.cache/ash` | x |
| `ASH_FAKE_MODE` | `container` | x |
| `ASH_FAKE_FLAG` | not set | x |
| `ASH_FAKE_FLAG` | | x |

| Variable | Default |
|---|---|
| `ASH_FAKE_MODE` | `local`<br>`container` |
"""


def test_env_table_defaults_pass_when_the_code_gives_them(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_ENV_TABLE)
    assert dc.check_env_vars([page], tmp_path, read=_read_set(**ENV_DEFAULTS)) == []


@pytest.mark.parametrize(
    "row,expected",
    [
        (
            "| `ASH_FAKE_DIR` | `~/.ash` |",
            "ASH_FAKE_DIR's default says `~/.ash`, but the code gives `~/.cache/ash`",
        ),
        (
            "| `ASH_FAKE_FLAG` | `1` |",
            "ASH_FAKE_FLAG's default says `1`, but the code gives no default",
        ),
        (
            "| `ASH_FAKE_DIR` | not set |",
            "ASH_FAKE_DIR's default says not set, but the code gives `~/.cache/ash`",
        ),
    ],
    ids=["wrong value", "a default the code does not give", "not set for a default"],
)
def test_env_table_defaults_can_fail(tmp_path, row, expected):
    page = _write(
        tmp_path, "docs/page.md", f"| Variable | Default |\n|---|---|\n{row}\n"
    )
    _assert_reports(
        dc.check_env_vars([page], tmp_path, read=_read_set(**ENV_DEFAULTS)), expected, 3
    )


def test_the_generator_gives_each_variables_default_entries():
    """The check's defaults are the generator's: what its Default column renders."""
    generator = dc._load_by_path(
        "_ash_env_var_reference", REPO_ROOT / dc.ENV_VAR_GENERATOR
    )
    entries = generator.default_entries(REPO_ROOT, with_cli=False)
    assert entries, "the generator gave no defaults at all"
    assert all(isinstance(v, list) for v in entries.values())
    page_text, _stats = generator.generate(REPO_ROOT, with_cli=False)
    for name, values in entries.items():
        if values:
            assert f"| `{name}` | {'<br>'.join(values)} |" in page_text, name


# -- Terraform ---------------------------------------------------------------

TERRAFORM_VARIABLES = """variable "name_prefix" {
  description = "Prefix."
  type        = string
  default     = "ash-mcp"

  validation {
    condition     = length(var.name_prefix) < 26
    error_message = "too long"
  }
}

variable "vpc_id" {
  description = <<-EOT
    The VPC. A default = "x" in this text is not the default.
  EOT
  type        = string
}

variable "internal" {
  type    = bool
  default = true
}

variable "container_command" {
  type    = list(string)
  default = ["/usr/local/bin/ash-mcp-serve"]
}

variable "tags" {
  type    = map(string)
  default = {}
}

variable "listener_port" {
  type    = number
  default = null
}
"""


@pytest.fixture
def terraform_code(tmp_path):
    code = _git_root(tmp_path / "code")
    _write(code, "deploy/terraform/modules/svc/variables.tf", TERRAFORM_VARIABLES)
    _write(code, "deploy/terraform/modules/svc/main.tf", 'resource "x" "y" {}\n')
    return code


CLEAN_TERRAFORM = _table(
    "of=terraform:deploy/terraform/modules/svc complete",
    "| Variable | Contract | Type | Default | Notes |",
    '| `name_prefix` | — | `string` | `"ash-mcp"` | x |',
    "| `vpc_id` | — | `string` | *required* | |",
    "| `internal` | — | `bool` | `true` | |",
    '| `container_command` | — | `list(string)` | `["/usr/local/bin/ash-mcp-serve"]` | |',
    "| `tags` | — | `map(string)` | `{}` | |",
    "| `listener_port` | — | `number` | `null` | |",
)

TERRAFORM_DEFECTS = [
    (
        "unmarked Terraform variables table",
        (
            "| Variable | Contract | Type | Default | Notes |\n|---|---|---|---|---|\n"
            '| `name_prefix` | — | `string` | `"ash-mcp"` | x |\n'
        ),
        "documents options or keys but names no section",
        1,
    ),
    (
        "wrong default",
        _table(
            "of=terraform:deploy/terraform/modules/svc",
            "| Variable | Default |",
            "| `internal` | `false` |",
        ),
        "'internal' default says `false`, but the default is `true`",
        4,
    ),
    (
        "prose default",
        _table(
            "of=terraform:deploy/terraform/modules/svc",
            "| Variable | Default |",
            "| `container_command` | MCP launcher |",
        ),
        "'container_command' default says MCP launcher",
        4,
    ),
    (
        "a variable the module lacks",
        _table(
            "of=terraform:deploy/terraform/modules/svc",
            "| Variable | Default |",
            "| `subnet_ids` | `[]` |",
        ),
        "'subnet_ids' is not a key of of=terraform:deploy/terraform/modules/svc",
        4,
    ),
    (
        "a required variable given a default",
        _table(
            "of=terraform:deploy/terraform/modules/svc",
            "| Variable | Default |",
            '| `vpc_id` | `"x"` |',
        ),
        "but the key is required",
        4,
    ),
    (
        "a directory with no variables",
        _table("of=terraform:deploy", "| Variable | Default |", "| `x` | `1` |"),
        "holds no Terraform variable blocks",
        1,
    ),
]


def test_terraform_tables_pass_every_valid_form(tmp_path, terraform_code):
    page = _write(tmp_path, "docs/page.md", CLEAN_TERRAFORM)
    assert dc.check_option_tables([page], tmp_path, terraform_code) == []
    assert dc.check_env_vars([page], tmp_path, read=_read_set()) == []


@pytest.mark.parametrize(
    "case,text,expected,line", TERRAFORM_DEFECTS, ids=[c[0] for c in TERRAFORM_DEFECTS]
)
def test_terraform_tables_can_fail(
    tmp_path, terraform_code, case, text, expected, line
):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(
        dc.check_option_tables([page], tmp_path, terraform_code), expected, line
    )


# ---------------------------------------------------------------------------
# Completeness: options marker with complete
# ---------------------------------------------------------------------------

WORKFLOW = """name: scan
on:
  workflow_call:
    inputs:
      ash-version: {type: string, default: main}
      fail-on-findings: {type: boolean, default: true}
      config: {type: string, default: ""}
jobs: {}
"""


@pytest.fixture
def workflow_code(tmp_path):
    code = _git_root(tmp_path / "code")
    _write(code, ".github/workflows/scan.yml", WORKFLOW)
    return code


CLEAN_COMPLETE = _table(
    "of=github-inputs:.github/workflows/scan.yml complete",
    "| Input | Defaults to |",
    "| `ash-version` | `main` |",
    "| `fail-on-findings` | `true` |",
    "| `config` | empty |",
)


def _listed(section) -> list[str]:
    """One spelling of every key a complete table must name."""
    return sorted({spec.names[0] for spec in section.keys.values() if spec.listed})


def test_a_complete_table_passes_when_every_key_has_a_row(tmp_path, workflow_code):
    page = _write(tmp_path, "docs/page.md", CLEAN_COMPLETE)
    assert dc.check_option_tables([page], tmp_path, workflow_code) == []
    section, _problem = dc.cli_section("cli.mcp")
    cli = _write(
        tmp_path,
        "docs/cli.md",
        _table(
            "of=cli.mcp complete",
            "| Option |",
            *[f"| `{name}` |" for name in _listed(section)],
        ),
    )
    assert dc.check_option_tables([cli], tmp_path) == []
    assert "--help" not in _listed(section)


@pytest.mark.parametrize(
    "case,text,expected,line",
    [
        (
            "a removed github-actions input row",
            _table(
                "of=github-inputs:.github/workflows/scan.yml complete",
                "| Input | Defaults to |",
                "| `ash-version` | `main` |",
                "| `config` | empty |",
            ),
            (
                "'fail-on-findings' is a key of of=github-inputs:.github/workflows/scan.yml "
                "(the workflow's inputs) that no row names; the marker says the table is complete"
            ),
            1,
        ),
        (
            "an omitted scanner option",
            _table(
                "of=scanners.bandit complete",
                "| Option | Default |",
                "| `confidence_level` | `all` |",
            ),
            "'ignore_nosec' is a key of scanners.bandit",
            1,
        ),
        (
            "complete with a value",
            _table(
                "of=scanners.bandit complete=yes",
                "| Option | Default |",
                "| `confidence_level` | `all` |",
            ),
            "complete is a bare word",
            1,
        ),
        (
            "an unknown marker key",
            _table(
                "of=scanners.bandit total",
                "| Option | Default |",
                "| `confidence_level` | `all` |",
            ),
            "'total' is neither key=value nor a known bare word",
            1,
        ),
    ],
    ids=[
        "a removed github-actions input row",
        "an omitted scanner option",
        "complete with a value",
        "an unknown marker key",
    ],
)
def test_a_complete_table_reports_each_key_no_row_names(
    tmp_path, workflow_code, fixture_root, case, text, expected, line
):
    page = _write(tmp_path, "docs/page.md", text)
    findings = dc.check_option_tables(
        [page], tmp_path, workflow_code
    ) + dc.check_markers([page], tmp_path)
    _assert_reports(findings, expected, line)


def test_generic_and_help_keys_need_no_row_in_a_complete_table(tmp_path):
    """--help, and an option ASH reads from every scanner undeclared, are not the
    section's own."""
    section, _problem = dc.options_section("scanners.bandit", dc.load_config_models())
    listed = _listed(section)
    page = _write(
        tmp_path,
        "docs/page.md",
        _table(
            "of=scanners.bandit complete",
            "| Option |",
            *[f"| `{name}` |" for name in listed],
        ),
    )
    assert dc.check_option_tables([page], tmp_path) == []
    # offline is read from every scanner's options without being declared; a field
    # the options model declares (scan_timeout, on ScannerOptionsBase) is its own.
    assert "offline" not in listed
    assert "scan_timeout" in listed


# ---------------------------------------------------------------------------
# File names: ash.<name> and reports/<name>
# ---------------------------------------------------------------------------


@pytest.fixture
def file_code(tmp_path):
    """A code tree with output file-name constants and a tracked file named ash.*."""
    code = _git_root(tmp_path / "code")
    _write(
        code,
        "automated_security_helper/utils/output_files.py",
        'OUTPUT_LOG_FILES = ("ash.log", "ash.log.jsonl")\n'
        'SESSION_CONFIG_FILENAME = "ash.yaml"\n'
        'NOT_A_FILE_CONSTANT = "ash.unrelated"\n',
    )
    _write(code, "Formula/ash.rb", "class Ash; end\n")
    _write(code, "examples/plugin/my_plugins/__init__.py", "")
    _write(
        code,
        "examples/plugin/my_plugins/reporter.py",
        'class ExampleReporterConfig:\n    extension: str = "example.md"\n',
    )
    _write(code, "tests/test_data/reports/ash.findings.json", "{}\n")
    return code


CLEAN_FILES = f"""# Files

The SARIF report is `ash.sarif`, under `.ash/ash_output/reports/ash.sarif`, beside
`reports/ash.csv` and `ash.flat.json`. Logs are in `ash.log` and `ash.log.jsonl`; the
session config is `ash.yaml`. The formula is `Formula/ash.rb`. A reporter whose name is
a placeholder writes `reports/ash.<extension>`.

<!-- doctest: save-as=my_reporter.py -->
{FENCE}python
class FindingsConfig:
    extension: str = "findings.txt"
{FENCE}

This page's reporter writes `ash.findings.txt`.
"""

FILE_DEFECTS = [
    (
        "a misspelled report",
        "Open `ash.sarf`.\n",
        (
            "`ash.sarf` names ash.sarf, which no reporter ASH registers writes and no "
            "file-name constant in ASH names; did you mean ash.sarif?"
        ),
    ),
    (
        "a report under reports/ ASH does not write",
        "Open `.ash/ash_output/reports/ash.findings.json`.\n",
        "ash.findings.json",
    ),
    (
        "a constant that is not a file-name constant",
        "Open `ash.unrelated`.\n",
        "`ash.unrelated` names ash.unrelated",
    ),
    (
        "a file name that exists only in the test data",
        "Open `ash.findings.json`.\n",
        "`ash.findings.json` names ash.findings.json",
    ),
    (
        "another page's reporter",
        "This page's reporter writes `ash.findings.txt`.\n",
        "`ash.findings.txt` names ash.findings.txt",
    ),
    (
        "an example plugin's report on a page that does not document it",
        "Open `reports/ash.example.md`.\n",
        "ASH writes no reports/ash.example.md",
    ),
    (
        "a misspelled local copy of the S3 upload",
        "The S3 reporter keeps a copy in `reports/s3-report.jsn`.\n",
        "ASH writes no reports/s3-report.jsn",
    ),
]


def test_file_names_pass_every_valid_form(tmp_path, file_code):
    page = _write(tmp_path, "docs/page.md", CLEAN_FILES)
    assert dc.check_report_files([page], tmp_path, file_code) == []


def test_the_files_a_reporter_writes_are_read_from_its_code(tmp_path, file_code):
    """The S3 reporter keeps a local copy of what it uploads, named in its report()
    from the format it uploads in, with no companion_file_names to declare it."""
    page = _write(
        tmp_path,
        "docs/page.md",
        "The S3 reporter keeps `reports/s3-report.json`, or `reports/s3-report.yaml` "
        "for the yaml format. The unused-suppressions reporter also writes "
        "`reports/ash.unused-suppressions.md`.\n",
    )
    assert dc.check_report_files([page], tmp_path, file_code) == []


REPORTER_WRITES = """
from pathlib import Path


class FakeReporter(ReporterPluginBase):
    def report(self, model):
        file_extension = "json" if self.config.options.file_format == "json" else "yaml"
        local = Path(self.context.output_dir) / "reports" / f"s3-report.{file_extension}"
        reports_dir = Path(self.context.output_dir).joinpath("reports")
        (reports_dir / "ash.extra.md").write_text("x")
        Path(self.context.output_dir).joinpath("reports", "ash.joined.txt")
        (reports_dir / f"ash.{self.config.options.suffix}").write_text("unknown")
        (Path(self.context.output_dir) / "scanners" / "ash.not-a-report").write_text("x")
        return local
"""


def test_reporter_writes_name_only_files_the_code_spells_out():
    """A name built from a value the code does not spell out (an option) is not
    guessed; options' file defaults are read from the options model instead."""
    import ast

    assert dc.reporter_written_files(ast.parse(REPORTER_WRITES)) == {
        "s3-report.json",
        "s3-report.yaml",
        "ash.extra.md",
        "ash.joined.txt",
    }


def test_declared_companion_names_cover_every_choice_of_an_option():
    """A reporter that declares its companion file from an option with a fixed set
    of values (the S3 reporter's file_format) declares one name per value, not only
    the name its default writes."""
    from typing import Any, Literal

    from pydantic import BaseModel

    class FakeOptions(BaseModel):
        file_format: Literal["json", "yaml"] = "json"
        compress: bool = False

    class FakeConfig(BaseModel):
        options: FakeOptions = FakeOptions()

    class FakeReporter(BaseModel):
        context: Any = None
        config: FakeConfig | None = None

        def companion_file_names(self):
            options = (self.config or FakeConfig()).options
            extension = "json" if options.file_format == "json" else "yaml"
            return (f"local.{extension}" + (".gz" if options.compress else ""),)

    assert dc.declared_companion_names(FakeReporter, None) == {
        "local.json",
        "local.yaml",
        "local.json.gz",
    }


def test_an_example_plugins_report_passes_where_its_plugin_is_documented(
    tmp_path, file_code
):
    """The example plugin's reporter writes reports/ash.example.md. A page in its
    project, or one that names its package, documents it; any other page naming that
    file names a report ASH does not write."""
    text = "The example reporter writes `reports/ash.example.md`.\n"
    inside = _write(tmp_path, "examples/plugin/README.md", text)
    naming = _write(
        tmp_path,
        "docs/plugins.md",
        "Load the example with `ash_plugin_modules: [my_plugins]`.\n\n" + text,
    )
    elsewhere = _write(tmp_path, "docs/other.md", text)
    findings = dc.check_report_files([inside, naming, elsewhere], tmp_path, file_code)
    assert [(f.path, f.line) for f in findings] == [("docs/other.md", 1)], findings


@pytest.mark.parametrize(
    "case,text,expected", FILE_DEFECTS, ids=[c[0] for c in FILE_DEFECTS]
)
def test_report_file_check_can_fail(tmp_path, file_code, case, text, expected):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_report_files([page], tmp_path, file_code), expected, 1)


def test_renaming_a_reporters_extension_fails_the_pages_that_name_it(
    tmp_path, file_code
):
    """The SARIF reporter's extension renamed to sarif.json: a page that names
    reports/ash.sarif must fail."""
    from pydantic import create_model

    models = dc.load_config_models()
    sarif = models.plugin_configs["reporters"]["sarif"]
    renamed = create_model(
        "SARIFReporterConfig", __base__=sarif, extension=(str, "sarif.json")
    )
    planted = dc.ConfigModels(
        models.ash_config,
        models.segments,
        {
            **models.plugin_configs,
            "reporters": {**models.plugin_configs["reporters"], "sarif": renamed},
        },
        models.passthrough,
        models.generic_option_keys,
        models.workspace_policy,
        models.unloaded,
    )
    page = _write(
        tmp_path, "docs/page.md", "Upload `reports/ash.sarif` to code scanning.\n"
    )
    assert dc.check_report_files([page], tmp_path, file_code) == []
    _assert_reports(
        dc.check_report_files([page], tmp_path, file_code, models=planted),
        "ASH writes no reports/ash.sarif",
        1,
    )


def test_historical_docs_are_not_held_to_todays_file_names(tmp_path, file_code):
    page = _write(tmp_path, "CHANGELOG.md", "Removed `ash.sarf`.\n")
    assert dc.check_report_files([page], tmp_path, file_code) == []


# ---------------------------------------------------------------------------
# Scanner names in tables
# ---------------------------------------------------------------------------

CLEAN_SCANNER_TABLES = """# Scanners

| What your repository has | Built-in scanners | Community plugins |
|---|---|---|
| Python code | bandit, semgrep, opengrep | snyk-code |
| Secrets, in any file | detect-secrets | ferret-scan (sensitive data), trivy-repo |
| CDK apps | cfn-nag, checkov (on the templates `cdk synth` writes) | |

| Scanner | Type |
|---|---|
| [`bandit`](scanners.md#bandit) | SAST |
| `checkov` | IaC |
| grype | SCA |

| Scanners | What they both do |
|---|---|
| semgrep and opengrep | x |
"""

SCANNER_DEFECTS = [
    (
        "an invented scanner in a plain-text cell",
        (
            "| What | Built-in scanners | Community plugins |\n|---|---|---|\n"
            "| Secrets | detect-secrets, trufflehog | |\n"
        ),
        "'trufflehog' in the Built-in scanners column is not a scanner ASH ships",
    ),
    (
        "a misspelled scanner row",
        "| Scanner | Type |\n|---|---|\n| gitleakz | Secrets |\n",
        "'gitleakz' in the Scanner column is not a scanner ASH ships",
    ),
    (
        "a community plugin listed as built in",
        "| What | Built-in scanners |\n|---|---|\n| Secrets | ferret-scan |\n",
        "'ferret-scan' in the Built-in scanners column is a community plugin",
    ),
    (
        "a built-in scanner listed as a community plugin",
        "| What | Community plugins |\n|---|---|\n| Python | bandit |\n",
        "'bandit' in the Community plugins column is a built-in scanner",
    ),
    (
        "an invented scanner with a word after it",
        "| What | Built-in scanners |\n|---|---|\n| Secrets | trufflehog scanner |\n",
        "'trufflehog scanner' in the Built-in scanners column is not one scanner name",
    ),
    (
        "prose in a scanner column",
        "| What | Built-in scanners |\n|---|---|\n| CDK | the CloudFormation scanners |\n",
        "'the CloudFormation scanners' in the Built-in scanners column is not one",
    ),
]


def test_scanner_tables_pass_every_valid_form(tmp_path):
    page = _write(tmp_path, "docs/page.md", CLEAN_SCANNER_TABLES)
    assert dc.check_scanner_names([page], tmp_path) == []


def test_the_scanner_check_counts_what_it_examined(tmp_path):
    """A note with the count, so a check that stopped finding its columns or names
    shows it, beside the findings."""
    page = _write(tmp_path, "docs/page.md", CLEAN_SCANNER_TABLES)
    notes: list[str] = []
    assert dc.check_scanner_names([page], tmp_path, notes=notes) == []
    assert notes == [
        "examined 9 cells in 4 scanner columns: 14 scanner names, 0 other items"
    ]


@pytest.mark.parametrize(
    "case,text,expected", SCANNER_DEFECTS, ids=[c[0] for c in SCANNER_DEFECTS]
)
def test_scanner_name_check_can_fail(tmp_path, case, text, expected):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_scanner_names([page], tmp_path), expected, 3)


def test_a_scanner_inventory_table_is_checked_in_both_directions(tmp_path):
    """coverage.md's By scanner table, marked complete: a missing row fails too."""
    section, _problem = dc.options_section("scanners", dc.load_config_models())
    names = _listed(section)
    assert set(dc.load_config_models().plugin_configs["scanners"]) <= {
        name for spec in section.keys.values() for name in spec.names
    }
    rows = [f"| {name} | x |" for name in names]
    complete = _table("of=scanners complete", "| Scanner | Type |", *rows)
    page = _write(tmp_path, "docs/page.md", complete)
    assert dc.check_option_tables([page], tmp_path) == []
    assert dc.check_scanner_names([page], tmp_path) == []
    short = _write(
        tmp_path,
        "docs/short.md",
        _table("of=scanners complete", "| Scanner | Type |", *rows[1:]),
    )
    _assert_reports(
        dc.check_option_tables([short], tmp_path),
        f"'{names[0]}' is a key of",
        1,
    )


# ---------------------------------------------------------------------------
# Plugin names next to a module from outside ASH
# ---------------------------------------------------------------------------

PAGE_PLUGIN = f"""# A plugin

<!-- doctest: save-as=ash-plugins/acme_plugins/__init__.py -->
{FENCE}python
from typing import Literal

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase


class AcmeOptions(ScannerOptionsBase):
    select: str = "S"


class AcmeConfig(ScannerPluginConfigBase):
    name: Literal["acme-scan"] = "acme-scan"
    enabled: bool = True
    options: AcmeOptions = AcmeOptions()
{FENCE}

"""


def _with_config(config: str) -> str:
    return PAGE_PLUGIN + f"{FENCE}yaml\n{config}{FENCE}\n"


def test_a_page_plugin_config_validates_against_the_pages_module(tmp_path):
    page = _write(
        tmp_path,
        "docs/page.md",
        _with_config(
            "project_name: x\nash_plugin_modules: [acme_plugins]\n"
            "scanners:\n  acme-scan:\n    options:\n      select: S,B\n"
            "  bandit:\n    enabled: false\n"
        ),
    )
    assert dc.check_config_blocks([page], tmp_path) == []
    assert "acme_plugins" not in sys.modules, "the page's module was imported here"


@pytest.mark.parametrize(
    "case,config,expected",
    [
        (
            "an option the page's plugin lacks",
            (
                "ash_plugin_modules: [acme_plugins]\nscanners:\n  acme-scan:\n"
                "    options:\n      selct: S\n"
            ),
            "scanners.acme-scan.options.selct is not a field of AcmeOptions",
        ),
        (
            "a plugin neither ASH nor the page defines",
            (
                "ash_plugin_modules: [acme_plugins]\nscanners:\n  acme-scn:\n"
                "    enabled: true\n"
            ),
            (
                "neither ASH nor the modules this block loads (acme_plugins) define a "
                "scanner named 'acme-scn'"
            ),
        ),
        (
            "a misspelled built-in next to a module that is not installed",
            (
                "ash_plugin_modules: [not_installed_plugins]\nscanners:\n  banditt:\n"
                "    enabled: false\n"
            ),
            "ASH ships no scanner named 'banditt'; did you mean 'bandit'?",
        ),
    ],
    ids=[
        "an option the page's plugin lacks",
        "a plugin neither ASH nor the page defines",
        "a misspelled built-in next to a module that is not installed",
    ],
)
def test_plugin_names_next_to_an_outside_module_can_fail(
    tmp_path, case, config, expected
):
    page = _write(tmp_path, "docs/page.md", _with_config(config))
    _assert_reports(dc.check_config_blocks([page], tmp_path), expected)


def test_a_name_far_from_every_builtin_next_to_an_uninstalled_module_passes(tmp_path):
    """A third-party plugin the docs environment cannot import is not checked further."""
    page = _write(
        tmp_path,
        "docs/page.md",
        f"{FENCE}yaml\nash_plugin_modules: [not_installed_plugins]\n"
        f"scanners:\n  my-org-scanner:\n    enabled: true\n{FENCE}\n",
    )
    assert dc.check_config_blocks([page], tmp_path) == []


def test_plugin_configs_are_found_by_base_class():
    """RuffSecurityConfig does not end in ScannerConfig; it is still a scanner config."""
    import types

    from typing import Literal

    from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase

    class RuffSecurityConfig(ScannerPluginConfigBase):
        name: Literal["ruff-security"] = "ruff-security"

    module = types.ModuleType("fake_plugins")
    module.RuffSecurityConfig = RuffSecurityConfig
    module.ScannerPluginConfigBase = ScannerPluginConfigBase
    found = dc.plugin_config_classes(module)
    assert found["scanners"] == {"ruff-security": RuffSecurityConfig}


def test_the_package_configs_found_by_base_class_are_the_ones_found_by_suffix():
    models = dc.load_config_models()
    for section, suffix in (
        ("scanners", "ScannerConfig"),
        ("reporters", "ReporterConfig"),
        ("converters", "ConverterConfig"),
    ):
        by_suffix = {
            name
            for name, cls in models.plugin_configs[section].items()
            if cls.__name__.endswith(suffix)
        }
        assert by_suffix == set(models.plugin_configs[section]), section


# ---------------------------------------------------------------------------
# Reasons, config paths, env-var families and env tables
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "reason",
    [
        "example",
        "illustrative",
        "not runnable",
        "does not run",
        "output",
        "an example",
        "illustrative example only",
        "just an example snippet",
        "This is illustrative.",
        "not run",
    ],
)
def test_a_reason_that_names_no_cause_is_a_placeholder(fixture_root, reason):
    page = _write(
        fixture_root,
        "docs/page.md",
        f'<!-- doctest: illustrative reason="{reason}" -->\n{FENCE}bash\ntrue\n{FENCE}\n',
    )
    _assert_reports(dc.check_markers([page], fixture_root), "names no cause", 1)


@pytest.mark.parametrize(
    "reason",
    [
        "needs Docker",
        "writes to a real bucket",
        "an example that needs AWS credentials",
        "not runnable offline",
        "the output of a full scan, which needs every scanner installed",
    ],
)
def test_a_reason_that_names_a_cause_passes(fixture_root, reason):
    page = _write(
        fixture_root,
        "docs/page.md",
        f'<!-- doctest: illustrative reason="{reason}" -->\n{FENCE}bash\ntrue\n{FENCE}\n',
    )
    assert dc.check_markers([page], fixture_root) == []


def test_a_kind_other_reason_must_say_what_the_file_is(fixture_root):
    vague = _write(
        fixture_root,
        "docs/vague.md",
        f'<!-- doctest: config kind=other reason="an example config" -->\n'
        f"{FENCE}yaml\na: 1\n{FENCE}\n",
    )
    _assert_reports(dc.check_markers([vague], fixture_root), "names no cause", 1)
    for reason in ("a SARIF excerpt", "an IAM policy", "example MCP tool response"):
        fine = _write(
            fixture_root,
            "docs/fine.md",
            f'<!-- doctest: config kind=other reason="{reason}" -->\n'
            f"{FENCE}yaml\na: 1\n{FENCE}\n",
        )
        assert dc.check_markers([fine], fixture_root) == [], reason


@pytest.mark.parametrize(
    "span,expected",
    [
        (
            "scanner.bandit.enabled",
            "there is no top-level key 'scanner'; did you mean 'scanners'?",
        ),
        (
            "global_setting.severity_threshold: LOW",
            "there is no top-level key 'global_setting'; did you mean 'global_settings'?",
        ),
        ("reporters.xml: true", "this ASH ships no reporter named 'xml'"),
        ("scanners.sh = false", "this ASH ships no scanner named 'sh'"),
    ],
)
def test_config_paths_the_check_used_to_skip_are_checked(tmp_path, span, expected):
    page = _write(tmp_path, "docs/page.md", f"Set `{span}` to change it.\n")
    _assert_reports(dc.check_option_tables([page], tmp_path), expected, 1)


@pytest.mark.parametrize(
    "span",
    [
        "scanners.md",
        "reporters.csv",
        "reporters.html: true",
        "scanner.py",
        "config.yaml",
        "os.environ",
        "sandbox.md",
    ],
)
def test_file_names_and_other_dotted_words_are_not_config_paths(tmp_path, span):
    page = _write(tmp_path, "docs/page.md", f"See `{span}`.\n")
    assert dc.check_option_tables([page], tmp_path) == []


def _env_read_set():
    read = dc.EnvReadSet(
        names={"ASH_SANDBOX_MODE", "ASH_SANDBOX_NETWORK", "ASH_SCAN_ID", "AWS_REGION"},
        dynamic=[],
        source="test",
    )
    read.build_args, read.test_only, read.defaults = {}, {}, {}
    return read


@pytest.mark.parametrize(
    "text,expected",
    [
        (
            "Every `ASH_S*` variable is read at start-up.\n",
            "ASH_S* is not an environment variable ASH reads",
        ),
        (
            "Every `ASH_SANDBOX*` variable is read at start-up.\n",
            "a family name ends at an underscore",
        ),
        (
            "| Env var | Purpose |\n|---|---|\n| `UV_INVENTED` | x |\n",
            "UV_INVENTED (in an environment-variable table)",
        ),
        (
            "| Option | Environment variable |\n|---|---|\n| `--x` | `UV_INVENTED` |\n",
            "UV_INVENTED (in an environment-variable table)",
        ),
    ],
    ids=[
        "loose family",
        "family not at an underscore",
        "Env var table",
        "env column",
    ],
)
def test_env_families_and_env_tables_are_checked_strictly(tmp_path, text, expected):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(dc.check_env_vars([page], tmp_path, read=_env_read_set()), expected)


def test_env_families_and_tables_pass_their_valid_forms(tmp_path):
    page = _write(
        tmp_path,
        "docs/page.md",
        "Every `ASH_SANDBOX_*` variable, and `ASH_SANDBOX_` too, is read.\n\n"
        "| Env var | Purpose |\n|---|---|\n| `AWS_REGION` | x |\n",
    )
    assert dc.check_env_vars([page], tmp_path, read=_env_read_set()) == []


def test_reporter_classes_come_from_the_modules_not_the_managers_cache():
    """The plugin manager caches its reporter list on first use, which can be before
    the AWS plugin module is imported; the companion files must not depend on that."""
    from automated_security_helper.plugins import ash_plugin_manager

    dc.load_config_models()
    found = {cls.__name__ for cls in dc._reporter_plugin_classes()}
    assert {
        cls.__name__ for cls in ash_plugin_manager.plugin_modules("reporter")
    } <= found
    assert "S3Reporter" in found


def test_a_variable_table_is_an_env_table_when_most_rows_name_env_variables(tmp_path):
    """environment-variables.md lists http_proxy among upper-case names; a Terraform
    module's lower-case variables are not environment variables."""
    page = _write(
        tmp_path,
        "docs/page.md",
        "| Variable | Default |\n|---|---|\n| `HTTP_PROXY` | |\n| `HTTPS_PROXY` | |\n"
        "| `http_proxy` | |\n\n"
        "| Variable | Default |\n|---|---|\n| `name_prefix` | `x` |\n| `vpc_id` | required |\n",
    )
    env, terraform = dc.parse_page(page, tmp_path).tables
    keys = frozenset({"HTTP_PROXY", "name_prefix", "vpc_id"})
    assert dc._is_env_table(env) and not dc._is_options_table(env, keys)
    assert not dc._is_env_table(terraform) and dc._is_options_table(terraform, keys)


def test_expect_exit_any_needs_an_output_sample(fixture_root):
    """expect-exit=any passes on any exit code; only a compared sample checks the block."""
    unchecked = _write(
        fixture_root,
        "docs/unchecked.md",
        f"<!-- doctest: run expect-exit=any -->\n{FENCE}bash\nash --version\n{FENCE}\n\n"
        f"{FENCE}text\nash 3.0\n{FENCE}\n",
    )
    _assert_reports(
        dc.check_markers([unchecked], fixture_root),
        "expect-exit=any checks nothing about the block",
        1,
    )
    checked = _write(
        fixture_root,
        "docs/checked.md",
        f"<!-- doctest: run expect-exit=any -->\n{FENCE}bash\nash --version\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\nash\n{FENCE}\n\n"
        f"<!-- doctest: run expect-exit=nonzero -->\n{FENCE}bash\nfalse\n{FENCE}\n",
    )
    assert dc.check_markers([checked], fixture_root) == []


def test_a_column_headed_environment_is_not_a_column_of_variables(tmp_path):
    page = _write(
        tmp_path,
        "docs/page.md",
        "| Environment | Notes |\n|---|---|\n| AWS CodeBuild | x |\n",
    )
    assert dc.check_env_vars([page], tmp_path, read=_env_read_set()) == []


def test_an_env_default_cell_saying_none_passes_when_the_code_gives_none_too(tmp_path):
    read = _read_set(ASH_FAKE_DIR=["`.ash/.ash.yaml`", "not set"])
    page = _write(
        tmp_path,
        "docs/page.md",
        "| Variable | Default |\n|---|---|\n| `ASH_FAKE_DIR` | not set |\n",
    )
    assert dc.check_env_vars([page], tmp_path, read=read) == []


def _typo_config() -> str:
    return (
        f"{FENCE}yaml\nash_plugin_modules: [acme_plugins]\nscanners:\n  acme-scan:\n"
        f"    options:\n      selct: S\n{FENCE}\n"
    )


def test_a_plugin_module_saved_at_the_project_root_is_imported(tmp_path):
    page = _write(
        tmp_path,
        "docs/page.md",
        PAGE_PLUGIN.replace(
            "save-as=ash-plugins/acme_plugins/__init__.py", "save-as=acme_plugins.py"
        )
        + _typo_config(),
    )
    _assert_reports(
        dc.check_config_blocks([page], tmp_path),
        "scanners.acme-scan.options.selct is not a field of AcmeOptions",
    )


def test_the_page_module_runs_without_the_callers_credentials(tmp_path, monkeypatch):
    """The saved module refuses to import when it can see AWS_PROFILE. The typo is
    reported only when the module imported, so the report shows the variable stayed
    out of the child process."""
    monkeypatch.setenv("AWS_PROFILE", "docs-check-test")
    guarded = PAGE_PLUGIN.replace(
        "from typing import Literal\n",
        'import os\nfrom typing import Literal\n\nassert "AWS_PROFILE" not in os.environ\n',
    )
    page = _write(tmp_path, "docs/page.md", guarded + _typo_config())
    _assert_reports(
        dc.check_config_blocks([page], tmp_path),
        "scanners.acme-scan.options.selct is not a field of AcmeOptions",
    )


def test_expect_exit_any_needs_a_sample_with_something_to_compare(fixture_root):
    page = _write(
        fixture_root,
        "docs/page.md",
        f"<!-- doctest: run expect-exit=any -->\n{FENCE}bash\nash --version\n{FENCE}\n\n"
        f"<!-- doctest: output -->\n{FENCE}text\n...\n\n{FENCE}\n",
    )
    _assert_reports(
        dc.check_markers([page], fixture_root),
        "expect-exit=any checks nothing about the block",
        1,
    )


def test_a_sample_word_matches_only_a_whole_word_of_the_output():
    assert dc.output_sample_problem("OK", "BROKEN", ()) == (0, "OK")
    assert dc.output_sample_problem("OK", "status: OK.", ()) is None
    assert dc.output_sample_problem("--offline", "ran with --offline set", ()) is None
    # Beside an ellipsis a piece may stop or start mid-word, as a truncated cell does.
    assert (
        dc.output_sample_problem(
            "FindingsListRe\u2026 acme", "FindingsListReporter acme", ()
        )
        is None
    )
    assert dc.output_sample_problem("...Reporter", "FindingsListReporter", ()) is None
    assert dc.output_sample_problem("Findings...", "MyFindingsList", ()) is not None


def test_terraform_variables_read_one_line_blocks_comments_and_trailing_commas():
    text = (
        'variable "a" {}\nvariable "b" { default = 1 }\n'
        'variable "c" { # note\n  default = "x" # trailing\n}\n'
        '/* variable "hidden" { */\n'
        'variable "d" {\n  default = [\n    "one",\n    "two",\n  ]\n}\n'
    )
    assert dict(dc.terraform_variables(text)) == {
        "a": dc.REQUIRED,
        "b": 1,
        "c": "x",
        "d": ["one", "two"],
    }


def test_urls_and_calls_are_not_file_names(tmp_path, file_code):
    page = _write(
        tmp_path,
        "docs/page.md",
        "Upload to `s3://my-bucket/reports/2024-01-01.json` with `ash.run_ash_scan()`.\n",
    )
    assert dc.check_report_files([page], tmp_path, file_code) == []


def test_a_capitalized_invented_scanner_is_checked(tmp_path):
    page = _write(
        tmp_path, "docs/page.md", "| Scanner | Type |\n|---|---|\n| Gitleakz | x |\n"
    )
    _assert_reports(
        dc.check_scanner_names([page], tmp_path), "'gitleakz' in the Scanner column", 3
    )


# ---------------------------------------------------------------------------
# Unmarked tables: a marker is required where the rows name keys
# ---------------------------------------------------------------------------

NAMES_NO_SECTION = "documents options or keys but names no section"

#: Tables headed like an options table, or with a column of defaults, whose rows name
#: no key of anything a marker can name: none needs a marker.
NOT_KEY_TABLES = [
    (
        "a table of defenses, each on or off",
        (
            "| Defense | What it does | On by default |\n|---|---|---|\n"
            "| Scanner sandbox | Limits reads | No |\n"
            "| [Trust tiers](trust-model.md) | Refuses grants | Yes |\n"
        ),
    ),
    (
        "options in the sense of choices",
        (
            "| Option | When to use it |\n|---|---|\n"
            "| Rebase the branch | history matters |\n| Merge main | it does not |\n"
        ),
    ),
    (
        "defaults of things that are not keys",
        "| Machine | Default memory |\n|---|---|\n| Laptop | 8 GB |\n| CI runner | 7 GB |\n",
    ),
    (
        "code spans that name no key",
        (
            "| Setting | Default |\n|---|---|\n"
            "| `make lint` | runs ruff |\n| `make docs` | builds the site |\n"
        ),
    ),
]

#: Unmarked tables whose rows name keys: each needs a marker naming its section.
KEY_TABLES = [
    (
        "ASH config keys under a Name header",
        (
            "| Name | Default |\n|---|---|\n"
            "| `severity_threshold` | `MEDIUM` |\n| `fail_on_findings` | `true` |\n"
        ),
    ),
    (
        "plugin names with their defaults",
        (
            "| Reporter | Operator-only options | Defaults |\n|---|---|---|\n"
            "| `s3` | `bucket_name` | `ASH_S3_BUCKET_NAME` |\n"
            "| `cloudwatch-logs` | `log_group_name` | `ASHScanResults` |\n"
        ),
    ),
    (
        "dotted config paths",
        "| Key | Default |\n|---|---|\n| `scanners.bandit.enabled` | `true` |\n",
    ),
    (
        "ash command options",
        (
            "| Option | Default |\n|---|---|\n"
            "| `--offline` | off |\n| `--output-dir` | `.ash/ash_output` |\n"
        ),
    ),
    (
        "MCP tool parameters",
        "| Parameter | Default |\n|---|---|\n| `scan_id` | required |\n",
    ),
    (
        "a misspelled key, which still names one",
        "| Option | Default |\n|---|---|\n| `severity_treshold` | `MEDIUM` |\n",
    ),
    (
        "keys with one invented row",
        (
            "| Option | Default |\n|---|---|\n| `severity_threshold` | x |\n"
            "| `fail_on_findings` | y |\n| `no_such_thing_anywhere` | z |\n"
        ),
    ),
]


@pytest.mark.parametrize(
    "case,text", NOT_KEY_TABLES, ids=[case for case, _text in NOT_KEY_TABLES]
)
def test_a_table_whose_rows_name_no_keys_needs_no_marker(tmp_path, case, text):
    """No exemption marker: a table that states defaults of things no section holds
    is simply not a table of keys, so nothing asks it to name one."""
    page = _write(tmp_path, "docs/page.md", text)
    assert dc.check_option_tables([page], tmp_path, REPO_ROOT) == []


@pytest.mark.parametrize(
    "case,text", KEY_TABLES, ids=[case for case, _text in KEY_TABLES]
)
def test_a_table_whose_rows_name_keys_needs_a_marker(tmp_path, case, text):
    page = _write(tmp_path, "docs/page.md", text)
    _assert_reports(
        dc.check_option_tables([page], tmp_path, REPO_ROOT), NAMES_NO_SECTION, 1
    )


def test_the_keys_a_row_may_name_come_from_every_section_kind(tmp_path):
    """One key from each kind of section an options marker can name, in a code tree
    that has one of each."""
    code = _git_root(tmp_path / "code")
    _write(code, "deploy/terraform/modules/m/variables.tf", 'variable "tf_only" {}\n')
    _write(
        code,
        "action.yml",
        "inputs:\n  action-only:\n    default: x\nruns:\n  using: composite\n  steps: []\n",
    )
    _write(
        code,
        ".github/workflows/reusable.yml",
        "on:\n  workflow_call:\n    inputs:\n      workflow-only:\n        type: string\n"
        "jobs: {}\n",
    )
    _write(code, "Dockerfile", "ARG DOCKER_ONLY=1\nFROM scratch\n")
    _write(
        code,
        "deploy/cfn/stack.yaml",
        "AWSTemplateFormatVersion: '2010-09-09'\nParameters:\n  CfnOnly:\n"
        "    Type: String\nResources: {}\n",
    )
    _write(
        code,
        "deploy/cdk/lib/props.ts",
        "export interface StepProps {\n  readonly tsOnly?: number;\n}\n",
    )
    _write(code, "pkg/api.py", "def scan(python_only=3):\n    pass\n")
    names = dc.documented_key_names(dc.load_config_models(), code)
    for name in (
        "severity_threshold",  # the ASH config model
        "bandit",  # a plugin name under scanners
        "confidence_level",  # a plugin's option
        "--offline",  # an ash command's option
        "scan_id",  # an MCP tool's parameter
        "tf_only",
        "action-only",
        "workflow-only",
        "DOCKER_ONLY",
        "CfnOnly",
        "tsOnly",
        "python_only",
    ):
        assert name in names, name
    assert "Laptop" not in names
