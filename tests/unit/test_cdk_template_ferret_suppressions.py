"""Pin the ferret-scan suppressions on the synthesized CDK templates.

.ash/.ash_community_plugins.yaml suppresses ferret-scan's API_KEY_OR_SECRET on each
committed CloudFormation template as a whole file, because CDK's hashed logical ids
read as high-entropy secrets and `cdk synth` moves them between lines. That is only
safe while two things hold, and these tests hold them:

* the suppression names each template that exists, file by file, so a new stack's
  template is scanned until somebody adds an entry for it after looking at it, and
  nothing else under deploy/cdk is suppressed for that rule -- the TypeScript
  sources and cdk.json, where any literal in a template would have to come from,
  stay scanned;
* the drift workflow still re-synthesizes the stacks and fails when a committed
  template differs, so a template cannot carry content the sources do not produce.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
TEMPLATES = REPO / "deploy" / "cdk" / "templates"
CONFIG = REPO / ".ash" / ".ash_community_plugins.yaml"
DRIFT_WORKFLOW = REPO / ".github" / "workflows" / "ash-iac-drift.yml"
RULE = "API_KEY_OR_SECRET"


def _rule_entries() -> list[dict]:
    config = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    return [
        entry
        for entry in config["global_settings"]["suppressions"]
        if entry.get("rule_id") == RULE
    ]


def test_templates_exist() -> None:
    # Guards the comparison below against an empty glob passing vacuously.
    assert sorted(TEMPLATES.glob("*.template.json")), TEMPLATES


def test_every_template_has_exactly_one_whole_file_entry() -> None:
    templates = sorted(
        path.relative_to(REPO).as_posix() for path in TEMPLATES.glob("*.template.json")
    )
    entries = [
        entry
        for entry in _rule_entries()
        if entry["path"].startswith("deploy/cdk/templates/")
    ]
    assert sorted(entry["path"] for entry in entries) == templates
    for entry in entries:
        # Whole-file on purpose: a line range would drift on the next synth.
        assert "line_start" not in entry and "line_end" not in entry, entry
        assert "*" not in entry["path"], entry
        assert entry.get("reason", "").strip(), entry


def test_nothing_else_under_deploy_cdk_is_suppressed_for_the_rule() -> None:
    others = [
        entry["path"]
        for entry in _rule_entries()
        if entry["path"].startswith("deploy/cdk")
        and not entry["path"].startswith("deploy/cdk/templates/")
    ]
    assert others == []


def test_the_drift_workflow_still_compares_the_committed_templates() -> None:
    text = DRIFT_WORKFLOW.read_text(encoding="utf-8")
    assert "npx cdk synth --all" in text
    assert "GEN_DIR=deploy/cdk/templates" in text
    assert 'git status --porcelain --untracked-files=all -- "$GEN_DIR"' in text
