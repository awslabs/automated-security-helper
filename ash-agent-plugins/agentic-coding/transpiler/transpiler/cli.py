"""Click CLI: `agentic-plugins {setup,build,release,check,smoke-test}`.

The four-phase shape (setup, build, release, check) maps to BaseBackend
lifecycle methods + the orchestrator. Each command takes an optional backend
NAME; without one, the command runs across all registered backends.

Backends can contribute additional subcommands by defining a class-level
`CLI_GROUP: ClassVar[click.Group | None]`. Such a group is mounted under
`agentic-plugins <backend-name>` so the backend can offer custom commands
beyond the four lifecycle phases (e.g. `agentic-plugins mcpb verify-archive`).
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
    targets = _all_or_one(name)
    for backend_name in targets:
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
    click.echo(f"setup complete for {len(targets)} backend(s)")


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
# check (drift + validation, both run unconditionally; failures accumulate)
# ---------------------------------------------------------------------------


@cli.command()
@click.option("--drift-only", is_flag=True, help="Skip schema validation; check drift only.")
@click.option("--validate-only", is_flag=True, help="Skip drift; run validation only.")
def check(drift_only: bool, validate_only: bool) -> None:
    """Run drift detection + output validation.

    The canonical CI gate. Both passes run unconditionally so a single CI run
    surfaces every problem; the exit code is non-zero if either fails. Use
    --drift-only or --validate-only to scope local iteration."""
    failed = False

    if not validate_only:
        if orchestrator.check_drift() != 0:
            failed = True

    if not drift_only:
        # Lazy import keeps jsonschema and frontmatter out of the build hot path
        from validate import validate_all
        m = orchestrator._load_manifest()
        errors = validate_all(
            plugins_root=orchestrator.OUTPUT_ROOT,
            schemas_dir=orchestrator.SCHEMAS_DIR,
            configs={
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
            failed = True
        else:
            click.echo(
                f"OK: validation passed for {len(BackendRegistry.names())} platforms + AGENTS.md."
            )

    sys.exit(1 if failed else 0)


# ---------------------------------------------------------------------------
# smoke-test (CI-time check that platform tooling can actually load each plugin)
# ---------------------------------------------------------------------------


def _label(backend_name: str, BackendCls) -> str:
    """Format the smoke-test display name as 'name (format)' when a
    backend declares FORMAT, else just the name. Surfaces shared formats
    (e.g., 'claude (claude-marketplace)' and 'codex (claude-marketplace)')
    so the cross-agent relationship is visible in CI logs."""
    fmt = getattr(BackendCls, "FORMAT", None)
    if fmt is None:
        return backend_name
    return f"{backend_name} ({fmt.name})"


@cli.command(name="smoke-test")
@click.argument("name", required=False)
def smoke_test(name: str | None) -> None:
    """Verify each generated plugin package loads correctly under its target CLI.

    Where a platform CLI is installable, run a load-only smoke test (e.g.
    `claude /plugins`, `codex plugin list`, `gemini extensions install --dry-run`).
    Backends that don't have a CLI smoke path (or the CLI isn't installed in
    CI) are skipped with a clear message rather than failing.

    Each backend that supports smoke testing implements a `smoke_test(ctx)`
    method on its class; backends without one print 'skipped'."""
    m = orchestrator._load_manifest()
    out_root = orchestrator.OUTPUT_ROOT
    targets = _all_or_one(name)

    failed: list[str] = []
    skipped: list[str] = []
    passed: list[str] = []

    for backend_name in targets:
        BackendCls = BackendRegistry.get(backend_name)
        backend = BackendCls()
        ctx = BuildContext(
            manifest=m,
            out=out_root / BackendCls.OUTPUT_DIR,
            plugins_root=out_root,
            base_dir=orchestrator.BASE_DIR,
            schemas_dir=orchestrator.SCHEMAS_DIR,
        )
        try:
            result = backend.smoke_test(ctx)  # type: ignore[attr-defined]
        except NotImplementedError:
            skipped.append(backend_name)
            click.echo(f"  [skip]   {backend_name}: no smoke test implemented")
            continue
        except Exception as e:  # noqa: BLE001 — surface anything as failure
            failed.append(backend_name)
            click.echo(f"  [FAIL]   {backend_name}: {e}", err=True)
            continue

        if result is None:
            skipped.append(backend_name)
            click.echo(f"  [skip]   {backend_name}: backend returned None")
        elif result.get("ok") is False:
            failed.append(backend_name)
            click.echo(
                f"  [FAIL]   {backend_name}: {result.get('reason', 'unknown')}",
                err=True,
            )
        elif result.get("skipped") is True:
            # _invoke_validator and _probe_cli_present return ok=True alongside
            # skipped=True when the CLI was unreachable. Surface this as a
            # distinct state so CI logs distinguish "12 passed, 3 skipped"
            # from "15 passed" — silently passing skipped backends would hide
            # the fact that the strongest validator was bypassed.
            skipped.append(backend_name)
            click.echo(f"  [skip]   {_label(backend_name, BackendCls)}: {result.get('detail', 'OK')}")
        else:
            passed.append(backend_name)
            click.echo(f"  [pass]   {_label(backend_name, BackendCls)}: {result.get('detail', 'OK')}")

    click.echo()
    click.echo(
        f"smoke-test summary: {len(passed)} passed, "
        f"{len(skipped)} skipped, {len(failed)} failed"
    )
    sys.exit(1 if failed else 0)


# ---------------------------------------------------------------------------


@cli.command(name="formats")
def formats_cmd() -> None:
    """List the output formats that backends produce.

    Surfaces the format → agents relationship: which backends emit
    'claude-marketplace' (Claude + Codex), 'amazonq-agent' (Amazon Q +
    kiro-cli), etc. Useful for understanding which artifacts can be
    cross-consumed and which are single-agent. Also shows which agents
    natively consume the standalone generic-skill release.
    """
    from collections import defaultdict
    from .formats import ALL_FORMATS
    from .registry import BackendRegistry

    fmt_to_backends = defaultdict(list)
    no_format = []
    generic_skill_consumers = []
    for backend_name, BackendCls in BackendRegistry.all().items():
        fmt = getattr(BackendCls, "FORMAT", None)
        if fmt is None:
            no_format.append(backend_name)
        else:
            fmt_to_backends[fmt.name].append(backend_name)
        if getattr(BackendCls, "SUPPORTS_GENERIC_SKILL", False):
            generic_skill_consumers.append(backend_name)

    click.echo("Output formats:")
    for fmt in ALL_FORMATS:
        agents = fmt_to_backends.get(fmt.name, [])
        agents_str = ", ".join(sorted(agents)) if agents else "(no backend points at this format)"
        click.echo(f"  {fmt.name}")
        click.echo(f"    consumed by: {agents_str}")
        if fmt.is_format_only_release:
            click.echo(f"    format-only release: yes (standalone artifact at agentic-coding/plugins/{fmt.name.replace('agentskills', 'generic-skill')}/)")
            click.echo(f"    natively consumed by: {', '.join(sorted(generic_skill_consumers)) or '(none)'}")
        if fmt.spec_url:
            click.echo(f"    spec: {fmt.spec_url}")
        if fmt.schema_url:
            click.echo(f"    schema: {fmt.schema_url}")

    if no_format:
        click.echo()
        click.echo("Backends without a Format (legacy or bespoke shape):")
        for b in sorted(no_format):
            click.echo(f"  {b}")


@cli.command(name="cli-tools")
def cli_tools_cmd() -> None:
    """List CLI tools each backend uses for installation and validation.

    Surfaces the (backend, cli) matrix: which CLIs install or validate
    each backend's output. Drives the matrix CI workflow — each
    (backend, validator) pair becomes its own CI job. Multi-CLI backends
    (e.g., codex declares both `codex` and `claude` since the artifact
    sits at .claude-plugin/plugin.json) yield multiple jobs.
    """
    from .registry import BackendRegistry

    click.echo("Backend → CLI tools:")
    for backend_name, BackendCls in sorted(BackendRegistry.all().items()):
        clis = getattr(BackendCls, "CLI_TOOLS", ())
        if not clis:
            click.echo(f"  {backend_name}: (no CLI tools declared)")
            continue
        cli_names = [t.name for t in clis]
        click.echo(f"  {backend_name}: {', '.join(cli_names)}")
        for tool in clis:
            roles = tool.role
            headless_marker = "" if tool.headless else " (GUI-only — non-headless)"
            click.echo(f"    {tool.name} [{roles}]{headless_marker}")
            if tool.install_cmd:
                click.echo(f"      install: {tool.install_cmd}")
            if tool.validate_argv_template:
                click.echo(f"      validate: {' '.join(tool.validate_argv_template)}")


@cli.command(name="matrix")
@click.option("--validators-only", is_flag=True,
              help="Emit only (backend, validator-CLI) pairs (skip installer-only tools).")
def matrix_cmd(validators_only: bool) -> None:
    """Print a JSON matrix for CI consumption.

    Each entry is {backend, cli, install_cmd, headless} suitable for
    GitHub Actions' strategy.matrix. Backends with multiple CLIs
    yield multiple matrix entries (e.g., codex declares both codex
    and claude validators). Use this to generate a parallel-jobs
    workflow: one CI job per (backend, validator) pair, each
    installing only the CLIs that backend needs.
    """
    import json
    from .registry import BackendRegistry

    matrix = []
    for backend_name, BackendCls in sorted(BackendRegistry.all().items()):
        clis = getattr(BackendCls, "CLI_TOOLS", ())
        for tool in clis:
            if validators_only and tool.role == "installer":
                continue
            matrix.append({
                "backend": backend_name,
                "cli": tool.name,
                "role": tool.role,
                "install_cmd": tool.install_cmd,
                "headless": tool.headless,
                "format": getattr(BackendCls, "FORMAT", None).name if getattr(BackendCls, "FORMAT", None) else None,
            })
    click.echo(json.dumps({"include": matrix}, indent=2))


# Per-backend subcommand registration
# ---------------------------------------------------------------------------


def _register_backend_groups() -> None:
    """Mount each backend's CLI_GROUP under `agentic-plugins <backend-name>`.

    Backends opt in by defining a module-level Click group and assigning it
    to a CLI_GROUP class var on their class. Most backends don't, so the
    namespace stays tidy."""
    for backend_name in BackendRegistry.names():
        BackendCls = BackendRegistry.get(backend_name)
        group = getattr(BackendCls, "CLI_GROUP", None)
        if group is None:
            continue
        # Click's add_command mounts the group as a subcommand
        cli.add_command(group, name=backend_name)


_register_backend_groups()


# ---------------------------------------------------------------------------
# Compatibility shim for the old validate.py expecting PlatformConfig
# ---------------------------------------------------------------------------


def _backend_to_platform_config(BackendCls):
    """Wrap a BaseBackend's class vars in a SimpleNamespace whose attribute
    paths match what validate.py's old PlatformConfig consumer expects."""
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


def main() -> None:
    cli()
