"""Click CLI: `agentic-plugins {setup,build,release,check}`.

Each command takes an optional backend name; without one, the command runs
across all registered backends. The four-phase shape (setup, build, release,
check) maps to BaseBackend lifecycle methods + the orchestrator.
"""
from __future__ import annotations

import sys
from pathlib import Path

import click

from . import backends as _backends_pkg  # noqa: F401  triggers registration
from . import orchestrator
from .core import BuildContext
from .registry import BackendRegistry


def _all_or_one(name: str | None) -> list[str]:
    if name is None:
        return BackendRegistry.names()
    if name not in BackendRegistry.names():
        click.echo(
            f"Unknown backend: {name}. Available: {', '.join(BackendRegistry.names())}",
            err=True,
        )
        sys.exit(2)
    return [name]


@click.group()
def cli() -> None:
    """Build plugin packages for AI coding agents."""


# ---------------------------------------------------------------------------
# setup
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("name", required=False)
def setup(name: str | None) -> None:
    """Run setup-stage phases (refresh-time work like schema fetches).

    Most backends have no setup work; the command is a no-op unless a backend
    declares PHASES with `stage="setup"`."""
    m = orchestrator._load_manifest()
    out_root = orchestrator.OUTPUT_ROOT
    for backend_name in _all_or_one(name):
        BackendCls = BackendRegistry.get(backend_name)
        backend = BackendCls()
        ctx = BuildContext(
            manifest=m,
            out=out_root / BackendCls.OUTPUT_DIR,
            plugins_root=out_root,
            base_dir=orchestrator.BASE_DIR,
            schemas_dir=orchestrator.SCHEMAS_DIR,
        )
        backend.setup(ctx)
    click.echo(f"setup complete for {len(_all_or_one(name))} backend(s)")


# ---------------------------------------------------------------------------
# build
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("name", required=False)
def build(name: str | None) -> None:
    """Build platform plugin packages from _base/ + backend class vars.

    With no NAME, builds all backends + the universal AGENTS.md.
    With a NAME, builds just that backend (AGENTS.md is not regenerated)."""
    if name is None:
        orchestrator.build_all()
        click.echo(
            f"Transpiled _base/ -> AGENTS.md + {len(BackendRegistry.names())} "
            f"platforms: {', '.join(BackendRegistry.names())}"
        )
    else:
        names = _all_or_one(name)
        for n in names:
            orchestrator.build_one(n)
        click.echo(f"built: {', '.join(names)}")


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------


@cli.command()
@click.argument("name", required=False)
@click.option(
    "--dist",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("agentic-coding/dist"),
    help="Directory to write release artifacts into.",
)
def release(name: str | None, dist: Path) -> None:
    """Run release-stage phases — package artifacts for distribution.

    Most backends have nothing to release (their output is the directory
    itself). MCPB releases its .mcpb archive into the dist directory."""
    if name is None:
        orchestrator.release_all(dist)
    else:
        orchestrator.release_one(name, dist)
    click.echo(f"release artifacts written to {dist}")


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--drift-only", is_flag=True, help="Skip schema validation; check drift only.")
@click.option("--validate-only", is_flag=True, help="Skip drift; run validation only.")
def check(drift_only: bool, validate_only: bool) -> None:
    """Run drift detection + output validation.

    The canonical CI gate. Without flags: runs both passes, returns 1 on any
    failure. --drift-only and --validate-only let local development iterate
    without paying for the full check."""
    rc = 0
    if not validate_only:
        rc = orchestrator.check_drift()
    if rc == 0 and not drift_only:
        # Lazy import — pulls jsonschema only when actually needed
        from validate import validate_all
        m = orchestrator._load_manifest()
        errors = validate_all(
            plugins_root=orchestrator.OUTPUT_ROOT,
            schemas_dir=orchestrator.SCHEMAS_DIR,
            configs={
                # Compatibility shim: validate.py expects a dict[str, PlatformConfig]
                # but the new architecture has BaseBackend subclasses. We pass the
                # equivalent via the registry. validate.py uses cfg.output_dir and
                # the section configs (cfg.mcp.path, cfg.skill.path, etc.).
                # The registry's class vars line up with PlatformConfig fields, so
                # we wrap classes in a thin adapter.
                name: _backend_to_platform_config(BackendRegistry.get(name))
                for name in BackendRegistry.names()
            },
            plugin_name=m.name,
            skill_name=m.skill_name,
        )
        if errors:
            click.echo(f"ERROR: {len(errors)} validation issue(s):", err=True)
            for path, msg, hint in errors:
                click.echo(f"  [{path}] {msg}", err=True)
                if hint:
                    click.echo(f"    hint: {hint}", err=True)
            rc = 1
        else:
            click.echo(
                f"OK: validation passed for {len(BackendRegistry.names())} platforms + AGENTS.md."
            )
    sys.exit(rc)


# ---------------------------------------------------------------------------
# Compatibility shim for validate.py
# ---------------------------------------------------------------------------


def _backend_to_platform_config(BackendCls):
    """Build a PlatformConfig-shaped object from a BaseBackend subclass.

    validate.py predates the class-per-backend refactor and expects a Pydantic
    PlatformConfig model. The class vars on BaseBackend are structurally the
    same — we wrap them in a SimpleNamespace-equivalent that exposes the same
    attribute path."""
    from types import SimpleNamespace
    return SimpleNamespace(
        output_dir=BackendCls.OUTPUT_DIR,
        plugin_manifest=BackendCls.PLUGIN_MANIFEST,
        extension_manifest=BackendCls.EXTENSION_MANIFEST,
        marketplace=BackendCls.MARKETPLACE,
        mcp=BackendCls.MCP,
        skill=BackendCls.SKILL,
        commands=BackendCls.COMMANDS,
        agents=BackendCls.AGENTS,
        instruction_file=BackendCls.INSTRUCTION_FILE,
        rules_dir=BackendCls.RULES_DIR,
        custom_modes=BackendCls.CUSTOM_MODES,
        config_file=BackendCls.CONFIG_FILE,
        mcpb_bundle=BackendCls.MCPB_BUNDLE,
    )


# ---------------------------------------------------------------------------
# Backward-compatible entry point
# ---------------------------------------------------------------------------


def transpile_compat() -> None:
    """The original `transpile` entry point. Maps to `agentic-plugins build`
    when called bare, or `agentic-plugins check` when called with --check.

    Exists so existing pre-commit hooks and CI invocations don't break during
    the transition. Both names are wired in pyproject.toml."""
    args = sys.argv[1:]
    if args == ["--check"]:
        sys.argv = [sys.argv[0]]
        check.callback(drift_only=False, validate_only=False)
        return
    if args == ["--drift-only"]:
        sys.argv = [sys.argv[0]]
        check.callback(drift_only=True, validate_only=False)
        return
    if args == ["--validate-only"]:
        sys.argv = [sys.argv[0]]
        check.callback(drift_only=False, validate_only=True)
        return
    if not args:
        orchestrator.build_all()
        click.echo(
            f"Transpiled _base/ -> AGENTS.md + {len(BackendRegistry.names())} "
            f"platforms: {', '.join(BackendRegistry.names())}"
        )
        return
    click.echo(
        f"Unsupported transpile args: {args}. Use `agentic-plugins` instead.",
        err=True,
    )
    sys.exit(2)


def main() -> None:
    cli()
