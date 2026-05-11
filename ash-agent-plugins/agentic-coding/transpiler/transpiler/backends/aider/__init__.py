"""Aider backend.

Aider has no MCP support — this backend ships per-project conventions via
a committed `.aider.conf.yml` (with `read: CONVENTIONS.md`) and a
`CONVENTIONS.md` that auto-loads as read-only context every session.

Smoke test: invoke `aider --help` to confirm the CLI is on PATH, then
parse the YAML config to confirm it loads. Aider doesn't have a "validate
config" mode, so the YAML structural check + the existing AGENTS.md-pointer
check is the highest-fidelity smoke test we can run without a paid LLM key.
"""
from __future__ import annotations

import shutil
import subprocess

import yaml

from ...core import BaseBackend, BuildContext, ConfigFile, InstructionFile
from ...registry import register_backend


@register_backend
class AiderBackend(BaseBackend):
    NAME = "aider"
    OUTPUT_DIR = "aider"

    INSTRUCTION_FILE = InstructionFile(
        path="CONVENTIONS.md",
        template="aider/CONVENTIONS.md.j2",
        include_skill_body=True,
        include_references="appended",
    )

    CONFIG_FILE = ConfigFile(
        path=".aider.conf.yml",
        template="aider/aider_conf.yml.j2",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate the generated .aider.conf.yml parses + references CONVENTIONS.md.

        If `aider` is on PATH, also verify `aider --help` exits 0 (proves the
        binary is installable in this CI environment). Skipped silently when
        aider isn't installed — Aider requires a paid LLM key to run anything
        beyond --help, so we can't go further in CI without leaking secrets."""
        conf_path = ctx.out / ".aider.conf.yml"
        conventions = ctx.out / "CONVENTIONS.md"

        if not conf_path.exists():
            return {"ok": False, "reason": ".aider.conf.yml missing"}
        if not conventions.exists():
            return {"ok": False, "reason": "CONVENTIONS.md missing"}

        try:
            conf = yaml.safe_load(conf_path.read_text())
        except yaml.YAMLError as e:
            return {"ok": False, "reason": f".aider.conf.yml YAML invalid: {e}"}

        read_field = conf.get("read") if isinstance(conf, dict) else None
        if not read_field or "CONVENTIONS.md" not in (
            read_field if isinstance(read_field, list) else [read_field]
        ):
            return {
                "ok": False,
                "reason": ".aider.conf.yml is missing `read: CONVENTIONS.md`",
            }

        # `aider --exit --yes-always --config <path>` runs the full startup
        # config-load path then exits before the chat loop — the de facto
        # validation idiom per aider/main.py (configargparse parses YAML
        # before argparse short-circuits help/version). Per
        # aider.chat/docs/config/aider_conf.html, malformed configs fail
        # before any chat starts. No LLM call. No provider key required.
        pins = self._load_cli_pins(ctx.base_dir)
        if "aider" in pins:
            ver = self._assert_version_pin("aider", ["aider", "--version"], pins["aider"])
            if ver and ver.get("ok") is False:
                return ver
        return self._invoke_validator(
            ["aider", "--exit", "--yes-always", "--config", str(conf_path.resolve())],
        )
