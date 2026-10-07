"""Amazon Q Dev CLI agent backend.

Emits agent.json (Amazon Q agent definition) and an install.sh that copies
it into ~/.aws/amazonq/cli-agents/.
"""

from __future__ import annotations

import json
import re

from ...core import BaseBackend, BuildContext, MCPConfig
from ...formats import AMAZONQ_AGENT
from ...cli_tools import CLI_Q, CLI_KIRO_CLI
from ...registry import register_backend

# The binary `kiro-cli agent ...` and `q agent ...` dispatch to. Unlike those two
# wrappers it runs `agent validate` without a login.
_VALIDATOR = "kiro-cli-chat"
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


@register_backend
class AmazonqBackend(BaseBackend):
    NAME = "amazonq"
    OUTPUT_DIR = "amazonq"
    FORMAT = AMAZONQ_AGENT
    CLI_TOOLS = (CLI_Q, CLI_KIRO_CLI)

    MCP = MCPConfig(
        format="amazonq",
        path="agent.json",
        install_script="amazonq",
    )

    def smoke_test(self, ctx: BuildContext) -> dict | None:
        """Validate agent.json with kiro-cli's own agent loader, offline.

        Amazon Q Developer CLI was renamed Kiro CLI, and `q` is now a script
        that runs kiro-cli. `q agent validate` and `kiro-cli agent validate`
        both refuse to run without a login ("You are not logged in"), on q
        1.19.7 and on kiro-cli 2.28.0, so neither can run in CI. Both wrappers
        dispatch `agent` to kiro-cli-chat (its usage line reads
        `kiro-cli-chat agent validate`), which ships in the same pinned archive
        and validates with no login. This runs that.

        What is checked without credentials: the generated file is JSON with
        a name and an mcpServers block; kiro-cli-chat runs and reports the
        version cli_versions.json pins for kiro-cli; and kiro-cli-chat loads
        the file against kiro-cli's agent definition without an error. What is
        NOT checked: anything `kiro-cli agent validate` does after its login
        gate. That needs an authenticated kiro-cli.

        kiro-cli-chat exits 0 whatever the outcome, and reports a failure on
        stderr as `Error: ...`, colored even with NO_COLOR set. q 1.x reported
        schema mismatches as `WARNING ...`. So both streams are scanned for
        both prefixes with ANSI codes stripped, and the exit code is not
        trusted.
        """
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

        # q and kiro-cli share kiro-cli's pin (CLI_Q.pin_key == "kiro-cli").
        pins = self._load_cli_pins(ctx.base_dir)
        pin_key = CLI_KIRO_CLI.resolved_pin_key()
        if pin_key in pins:
            ver = self._assert_version_pin(
                _VALIDATOR, [_VALIDATOR, "--version"], pins[pin_key]
            )
            if ver is not None and ver.get("ok") is False:
                return ver

        result = self._invoke_validator(
            [_VALIDATOR, "agent", "validate", "--path", str(agent_path.resolve())],
        )
        if not result.get("ok"):
            return result
        if result.get("skipped"):
            return result
        output = _ANSI_ESCAPE.sub(
            "", result.get("stdout", "") + "\n" + result.get("stderr", "")
        )
        for line in output.splitlines():
            if line.lstrip().startswith(("WARNING ", "Error:")):
                return {
                    "ok": False,
                    "reason": f"{_VALIDATOR} agent validate flagged: {line.strip()[:200]}",
                }
        return {
            "ok": True,
            "detail": (
                f"{_VALIDATOR} agent validate clean (offline; the full "
                "`kiro-cli agent validate` needs a login and was not run)"
            ),
        }
