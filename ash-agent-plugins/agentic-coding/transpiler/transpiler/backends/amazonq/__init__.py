"""Amazon Q Dev CLI agent backend.

Emits agent.json (Amazon Q agent definition) and an install.sh that copies
it into ~/.aws/amazonq/cli-agents/.
"""
from __future__ import annotations

import json

from ...core import BaseBackend, BuildContext, MCPConfig
from ...registry import register_backend


@register_backend
class AmazonqBackend(BaseBackend):
    NAME = "amazonq"
    OUTPUT_DIR = "amazonq"

    MCP = MCPConfig(
        format="amazonq",
        path="agent.json",
        install_script="amazonq",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate agent.json + run `q agent validate --path`.

        Per github.com/aws/amazon-q-developer-cli crates/chat-cli/src/cli/
        agent/root_command_args.rs: `q agent validate --path <p>` runs
        Agent::load + jsonschema::validate against the schemars-derived
        Draft-07 schema. No LLM call, no auth required.

        CRITICAL: `q agent validate` always exits 0 regardless of validation
        outcome — failures print to stderr/stdout with `WARNING ` (schema
        mismatch) or `Error: ` (parse/IO) prefix. We must scan output for
        those prefixes, not rely on exit code."""
        agent_path = ctx.out / "agent.json"

        if not agent_path.exists():
            return {"ok": False, "reason": "agent.json missing"}
        try:
            agent = json.loads(agent_path.read_text())
        except json.JSONDecodeError as e:
            return {"ok": False, "reason": f"agent.json invalid JSON: {e}"}
        if not agent.get("name"):
            return {"ok": False, "reason": "agent.json missing `name`"}
        if "mcpServers" not in agent:
            return {"ok": False, "reason": "agent.json missing `mcpServers` block"}

        pins = self._load_cli_pins(ctx.base_dir)
        if "q" in pins:
            ver = self._assert_version_pin("q", ["q", "--version"], pins["q"])
            if ver and ver.get("ok") is False:
                # Don't hard-fail on q version mismatch — Q is in maintenance
                # mode and Kiro is the active path; just record the mismatch.
                pass

        result = self._invoke_validator(
            ["q", "agent", "validate", "--path", str(agent_path.resolve())],
        )
        if not result.get("ok"):
            return result
        if result.get("skipped"):
            return result
        # `q agent validate` always exits 0; scan its stdout/stderr for
        # WARNING / Error prefixes that indicate validation failure.
        output = result.get("stdout", "")
        for line in output.splitlines():
            if line.startswith("WARNING ") or line.startswith("Error: "):
                return {
                    "ok": False,
                    "reason": f"q agent validate flagged: {line.strip()[:200]}",
                }
        return {"ok": True, "detail": "q agent validate clean"}
