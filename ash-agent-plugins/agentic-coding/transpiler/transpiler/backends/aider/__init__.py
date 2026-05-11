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

        if shutil.which("aider") is not None:
            try:
                subprocess.run(
                    ["aider", "--help"],
                    check=True,
                    capture_output=True,
                    timeout=15,
                )
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                return {"ok": False, "reason": f"aider --help failed: {e}"}
            return {"ok": True, "detail": "aider --help OK; config + conventions valid"}
        return {"ok": True, "detail": "config + conventions valid (aider not installed; CLI invocation skipped)"}
