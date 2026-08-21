"""Importing this package triggers @register_backend on every backend module,
populating BackendRegistry. The CLI imports `transpiler.backends` once at
startup, then iterates `BackendRegistry.all()`.

The order of imports below determines the order backends appear in
`BackendRegistry.all()` — kept in the same order as the original
configs.yaml so generated output ordering is stable across the refactor.
"""
from . import claude  # noqa: F401
from . import codex  # noqa: F401
from . import kiro  # noqa: F401
from . import copilot  # noqa: F401
from . import opencode  # noqa: F401
from . import cursor  # noqa: F401
from . import windsurf  # noqa: F401
from . import cline  # noqa: F401
from . import roo  # noqa: F401
from . import continue_dev  # noqa: F401  -- 'continue' is a Python keyword
from . import gemini  # noqa: F401
from . import goose  # noqa: F401
from . import amazonq  # noqa: F401
from . import aider  # noqa: F401
from . import mcpb  # noqa: F401
from . import generic_skill  # noqa: F401  -- format-only release of agentskills
