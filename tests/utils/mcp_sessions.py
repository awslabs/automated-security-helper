# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One setup for the MCP cells that need a real session sandbox with a bound profile.

The sandbox contract is the same in every cell: a workspace root the server
reads from ``ASH_MCP_WORKSPACE_ROOT``, a source directory under the session's
own workspace, a delivered config the sandbox classifies as the client's, and
a profile in the session's config directory that is bound through
``profile_registry.bind_session_config``. The cells differ in the profile's
text, the extra environment they set, and whether the source directory is also
named in the allowed roots, so those are parameters.
"""

from pathlib import Path
from typing import Mapping, Optional, Tuple

from automated_security_helper.cli.mcp import profile_registry
from automated_security_helper.cli.mcp.scan_target import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.config.ash_config import AshConfig


def a_session_with_a_bound_profile(
    ws: Path,
    monkeypatch,
    session_id: str,
    *,
    profile_text: str = "project_name: a-held-profile\n",
    base_text: Optional[str] = None,
    profile_name: str = "held",
    allowed_roots: bool = True,
    clear_config_env: bool = True,
    env: Optional[Mapping[str, str]] = None,
) -> Tuple[Path, Path, Path, Path]:
    """A real session sandbox with a delivered config and a bound profile.

    Returns ``(target, delivered, profile, config_dir)``: the source directory,
    the delivered (client's) config inside it, the session's bound profile, and
    the session's config directory.

    *allowed_roots* names the source directory in the allowed-roots variable;
    *clear_config_env* removes ``ASH_CONFIG``; *env* sets further variables
    through *monkeypatch*; *base_text* writes a ``base.ash.yaml`` beside the
    profile.
    """
    from automated_security_helper.cli.mcp.sandbox import config_is_client_supplied

    target = ws / session_id / "source" / "repo"
    target.mkdir(parents=True)
    config_dir = ws / session_id / "config"
    config_dir.mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(ws))
    if allowed_roots:
        monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(target))
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)
    if clear_config_env:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
    delivered = target / "client.ash.yaml"
    delivered.write_text("project_name: delivered\n", encoding="utf-8")
    profile = config_dir / "ash.yaml"
    profile.write_text(profile_text, encoding="utf-8")
    if base_text is not None:
        (config_dir / "base.ash.yaml").write_text(base_text, encoding="utf-8")
    assert config_is_client_supplied(delivered)
    assert not config_is_client_supplied(profile)
    profile_registry.bind_session_config(
        session_id,
        config=AshConfig(),
        profile_name=profile_name,
        config_path=str(profile),
    )
    assert profile_registry.resolve_session_config_path(session_id) == str(profile)
    return target, delivered, profile, config_dir
