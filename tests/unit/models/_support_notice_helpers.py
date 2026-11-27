"""Support notices as a writer builds them from the support register's rows.

Three rows stand for the three levels a notice can have: the processor below polars'
default runtime (unsupported, raised at the start of a run, with paths on this machine
and elsewhere), a Landlock kernel below ABI 6 (degraded, raised at a decision) and the
sandbox GuardDog runs in instead of its own (polyfilled, raised at a decision). The
tests of the model, of the workspace root and of ``ash merge`` share them, so each
states only what it is about.
"""

from __future__ import annotations

from typing import Any

from automated_security_helper.models.asharp_model import (
    SupportNotice,
    UpgradePathNotice,
)

DOCS_PAGE = "how-to/supported-configurations.md"

CPU_ID = "host.cpu.below-polars-runtime"
SANDBOX_ID = "host.sandbox.landlock-below-6"
POLYFILL_ID = "scanner.guarddog.sandbox-replaced"

#: The path kinds that change this machine; every other kind moves the scan elsewhere.
_THIS_MACHINE = ("same-os", "container", "wsl")

#: What both hosts of ``cpu_notice_of_two_hosts`` read, and nothing else.
AGREED_CPU_FACTS = {"arch": "amd64", "polars_runtime": "runtime-32"}


def upgrade_path(
    path_id: str, kind: str, summary: str, **changes: Any
) -> UpgradePathNotice:
    """One upgrade path, in the group its kind belongs to, with ``changes`` applied."""
    fields: dict[str, Any] = {
        "id": path_id,
        "group": "this-machine" if kind in _THIS_MACHINE else "elsewhere",
        "kind": kind,
        "summary": summary,
        "docs": f"{DOCS_PAGE}#{path_id}",
    }
    fields.update(changes)
    return UpgradePathNotice(**fields)


def cpu_notice(**changes: Any) -> SupportNotice:
    """An unsupported row raised at the start: the processor lacks what polars needs."""
    fields: dict[str, Any] = {
        "id": CPU_ID,
        "scope": "ash",
        "dimension": "cpu",
        "level": "unsupported",
        "behavior": "continues",
        "message": (
            "This x86-64 processor lacks instructions the installed polars runtime "
            "is built for, and polars warns that running on it will likely crash."
        ),
        "found": "avx2, bmi2 and fma are missing (polars-runtime-32 1.44.2).",
        "facts": {
            "arch": "amd64",
            "cpu_level": "compat-only",
            "polars_runtime": "runtime-32",
        },
        "raised": "start",
        "docs": f"{DOCS_PAGE}#host-cpu-below-polars-runtime",
        "paths": [
            upgrade_path(
                "polars-compat-runtime",
                "same-os",
                "Add polars' compatibility runtime (its rtcompat extra) to ASH's "
                "environment, at the polars version ASH uses.",
            ),
            upgrade_path(
                "x86-host-with-features",
                "other-host",
                "Run ASH on an x86-64 processor with the instruction set polars is "
                "built for (AVX2 and its companions).",
            ),
            upgrade_path(
                "arm64-host",
                "other-host",
                "Run ASH on an arm64 machine: Linux on arm64 or a Mac with Apple "
                "silicon.",
            ),
            upgrade_path(
                "ci-runner",
                "ci-runner",
                "Run the scan in CI on a hosted runner; ASH's reusable GitHub "
                "workflow runs on ubuntu-latest by default.",
            ),
        ],
    }
    fields.update(changes)
    return SupportNotice(**fields)


def cpu_notice_of_two_hosts() -> tuple[SupportNotice, SupportNotice]:
    """The processor row as two hosts met it: one row, a different read on each.

    Both processors lack what polars is built for, but the second is further below it.
    Each notice records the flags its own host lacked and the level its own processor
    is at, so ``found`` differs and so does one fact. The architecture and the runtime
    are what both read (``AGREED_CPU_FACTS``).
    """
    near = cpu_notice(
        found="avx2, bmi2 and fma are missing (polars-runtime-32 1.44.2).",
        facts={
            "arch": "amd64",
            "cpu_level": "compat-only",
            "polars_runtime": "runtime-32",
        },
    )
    far = cpu_notice(
        found="avx, avx2, bmi2, fma and sse4.2 are missing (polars-runtime-32 1.44.2).",
        facts={
            "arch": "amd64",
            "cpu_level": "below-compat",
            "polars_runtime": "runtime-32",
        },
    )
    return near, far


def sandbox_notice(**changes: Any) -> SupportNotice:
    """A degraded row raised at a decision: the kernel's Landlock ABI is below 6."""
    fields: dict[str, Any] = {
        "id": SANDBOX_ID,
        "scope": "ash",
        "dimension": "sandbox",
        "level": "degraded",
        "behavior": "continues",
        "message": (
            "Abstract Unix sockets and signals to processes outside the sandbox are "
            "not restricted, because the kernel's Landlock ABI is below 6."
        ),
        "found": "Landlock ABI 5.",
        "facts": {
            "sandbox_mode": "auto",
            "sandbox_backend": "landlock",
            "sandbox_loss": "landlock-below-6",
        },
        "raised": "decision",
        "docs": f"{DOCS_PAGE}#host-sandbox-landlock-below-6",
        "paths": [
            upgrade_path(
                "newer-kernel-landlock",
                "same-os",
                "Use a Linux kernel whose Landlock ABI is 6 or later, or the bwrap "
                "backend.",
            ),
            upgrade_path(
                "install-bubblewrap",
                "same-os",
                "Install bubblewrap and allow unprivileged user namespaces, or use "
                "the firejail or landlock backend.",
            ),
        ],
    }
    fields.update(changes)
    return SupportNotice(**fields)


def polyfill_notice(**changes: Any) -> SupportNotice:
    """A polyfilled row raised at a decision: GuardDog runs in ASH's sandbox."""
    fields: dict[str, Any] = {
        "id": POLYFILL_ID,
        "scope": "guarddog",
        "dimension": "tool sandbox",
        "level": "polyfilled",
        "behavior": "continues",
        "message": (
            "GuardDog runs inside ASH's sandbox-exec confinement instead of its own "
            "kernel sandbox."
        ),
        "polyfill": "guarddog-ash-sandbox",
        "facts": {"tool_sandbox": "replaced"},
        "raised": "decision",
        "docs": f"{DOCS_PAGE}#scanner-guarddog-sandbox-replaced",
    }
    fields.update(changes)
    return SupportNotice(**fields)


def notice_of_row(row: Any) -> SupportNotice:
    """The notice a writer builds from a support register row, as the row declares it.

    The notice is raised when the row says it is, so a row that is never a notice (a
    matrix-only one, which has no moment) is not built here.

    The register is imported here, not at the top, so a test that does not read it
    does not build it.
    """
    from automated_security_helper.base.support_register import REGISTER

    return SupportNotice(
        id=row.id,
        scope=row.scope,
        dimension=row.dimension,
        level=row.level.value,
        behavior=row.behavior.value,
        message=row.reason,
        polyfill=row.polyfill,
        facts={name: tokens[0] for name, tokens in row.match.constraints()},
        raised=row.notify.value,
        docs=row.docs,
        paths=[
            UpgradePathNotice(
                id=path.id,
                group="this-machine" if path.kind.here else "elsewhere",
                kind=path.kind.value,
                summary=path.summary,
                docs=path.docs,
            )
            for path in (REGISTER.path(path_id) for path_id in row.paths)
        ],
    )
