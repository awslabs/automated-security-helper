"""OS-level sandboxing for scanner subprocesses. See docs/content/docs/scanner-sandbox.md."""

from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.sandbox.policy import (
    SandboxPolicy,
    SandboxRequirements,
)
from automated_security_helper.utils.sandbox.scope import (
    SandboxScope,
    SandboxUnavailable,
    active_scope,
    clear_backend_cache,
    prepare_spawn,
    resolve_backend,
    sandbox_scope,
    scanner_sandbox_scope,
)

__all__ = [
    "SandboxPolicy",
    "SandboxRequirements",
    "SandboxScope",
    "SandboxUnavailable",
    "SpawnPlan",
    "active_scope",
    "clear_backend_cache",
    "prepare_spawn",
    "resolve_backend",
    "sandbox_scope",
    "scanner_sandbox_scope",
]
