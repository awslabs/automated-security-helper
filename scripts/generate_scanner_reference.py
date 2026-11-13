#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate docs/content/reference/scanners.md from the scanner plugins ASH ships.

Usage:
    uv run python scripts/generate_scanner_reference.py           # rewrite the page
    uv run python scripts/generate_scanner_reference.py --check   # exit 1 with a diff if stale

Every scanner class declared by a package under ``plugin_modules/`` is listed (see
``scripts/_plugin_reference.py`` for how they are found). For each one the page
gives, from the code:

* its config name, whether it is enabled by default, and which package provides
  it (``ash_builtin`` is always loaded; the community modules are loaded through
  ``ash_plugin_modules``);
* a link to its own page in the docs tree, when that tree has one (see
  :func:`scanner_page`);
* its tool type (``ScannerToolType``), the command it runs, how ASH installs that
  command, whether ``--python-only`` keeps it, and its offline strategy;
* what it needs from the sandbox: network, and the environment prefixes it is
  given;
* every key of its ``options`` model, with type, default and description.

What it does not say: what each scanner finds. The scanners' class docstrings were
measured and several contradict the scanner's own ``tool_type`` (grype's,
npm-audit's and syft's say "IaC"), so they are not published. A scanner that sets a
``description`` of itself has it shown.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _reference_docs import (
    add_docs_root_argument,
    banner,
    code,
    generated_note,
    md_prose,
    options_marker,
    prepare_environment,
    reference_dir,
    refuse_check_to_stdout,
    write_or_check,
)

GENERATOR = "scripts/generate_scanner_reference.py"
PAGE = "scanners.md"
#: Where a docs tree keeps one page per scanner, relative to its root.
BUILTIN_PAGES = Path("docs/content/docs/plugins/builtin")
COMMUNITY_PAGES = Path("docs/content/docs/plugins/community")


def scanner_page(plugin, docs_root: Path) -> Optional[Path]:
    """The docs tree's own page for ``plugin``, if it has one.

    A built-in scanner's page is ``BUILTIN_PAGES/<name>.md``, or a page that covers
    several scanners and names them in its file name joined by ``-and-``
    (``cfn-lint-and-cfn-guard.md``). A community scanner's page is
    ``COMMUNITY_PAGES/<name>-plugin.md``, or ``<module>-plugin.md`` after the
    module name's ``ash_`` and ``_plugins`` (``ash_snyk_plugins`` is
    ``snyk-plugin.md``). Read from the files present, so a link appears in the
    same change that adds the page.
    """
    from _plugin_reference import module_name

    if plugin.builtin:
        folder = Path(docs_root) / BUILTIN_PAGES
        candidates = [folder / f"{plugin.name}.md"]
        candidates += sorted(
            page
            for page in folder.glob("*-and-*.md")
            if plugin.name in page.stem.split("-and-")
        )
    else:
        folder = Path(docs_root) / COMMUNITY_PAGES
        module = module_name(plugin).removeprefix("ash_").removesuffix("_plugins")
        candidates = [
            folder / f"{plugin.name}-plugin.md",
            folder / f"{module.replace('_', '-')}-plugin.md",
        ]
    return next((page for page in candidates if page.is_file()), None)


def _value(instance, attr: str):
    value = getattr(instance, attr, None)
    return getattr(value, "value", value)


def _sandbox(plugin) -> tuple[str, str, str]:
    """(network, environment passed in, environment set) from the sandbox requirements."""
    requirements = getattr(plugin.instance, "sandbox_requirements", None)
    if requirements is None:
        requirements = plugin.cls.__dict__.get("sandbox_requirements")
    if requirements is None or isinstance(requirements, property):
        return "not declared", "not declared", "none"
    if not requirements.network:
        network = "no"
    elif getattr(requirements, "network_requires_grant", False):
        network = "no; yes when `sandbox.network_scanners` names this scanner"
    else:
        network = "yes, unless the scan is offline"
    passed = [f"{p}*" for p in requirements.env_prefixes] + list(requirements.env_names)
    set_under = [
        f"{k}={v}" for k, v in getattr(requirements, "sandbox_exec_env", ()) or ()
    ]
    return (
        network,
        ", ".join(code(n) for n in passed) if passed else "none beyond the baseline",
        ", ".join(code(n) for n in set_under) if set_under else "none",
    )


def _baseline_environment() -> list[str]:
    """The environment every sandboxed scanner gets, from utils/sandbox/policy.py."""
    from automated_security_helper.utils.sandbox import policy

    # The certificate names are in BASE_ENV_NAMES but follow `sandbox.environment`,
    # so they are not among the names every scanner gets.
    certificates = list(policy.CA_BUNDLE_ENV_NAMES)
    names = sorted(policy.BASE_ENV_NAMES - set(certificates))
    prefixes = list(policy.BASE_ENV_PREFIXES)
    markers = list(policy.CREDENTIAL_MARKERS)
    proxies = sorted(policy.PROXY_ENV_NAMES)
    return [
        "## Environment in the sandbox",
        "",
        "When `sandbox.mode` confines scanners, a scanner process receives only an "
        "allowlist of the environment ASH was started with. Every sandboxed scanner "
        "gets these names: "
        + ", ".join(code(n) for n in names)
        + "; and names starting with "
        + ", ".join(code(p) for p in prefixes)
        + ". The proxy variables "
        + ", ".join(code(n) for n in proxies)
        + " and the certificate variables "
        + ", ".join(code(n) for n in certificates)
        + " are the default of `sandbox.environment`, a docker-compose style list "
        "that replaces them when it is set. A proxy variable is passed only to a "
        "scanner that has a network. A scanner's own prefixes and names, listed with "
        "each scanner below, are added to all of that. A name containing "
        + ", ".join(code(m) for m in markers)
        + " is dropped even under an allowed prefix, unless the scanner names it "
        "exactly. The lists are in "
        "`automated_security_helper/utils/sandbox/policy.py`.",
        "",
        (
            "The network entry of each scanner below is its default. "
            "`sandbox.network_scanners`, when it is set, replaces every scanner's "
            "declared need: only the scanners it names get a network. A config file "
            "inside a git checkout or the scanned directory can only take network "
            "away, and an offline scan gives no scanner a network."
        ),
        "",
    ]


def generate(docs_root: Path) -> tuple[str, dict]:
    from _plugin_reference import (
        ENV_NOTE_SLOT,
        discover,
        install_text,
        instantiate,
        options_table,
        package_note,
        package_short,
        place_env_note,
        yes_no,
    )

    plugins = discover("scanner")
    instantiate(plugins)
    missing: list[str] = []

    lines = banner(
        GENERATOR,
        "the scanner plugins declared under automated_security_helper/plugin_modules",
        extra=[
            "",
            "Anchors: each scanner's heading id is its config name (#bandit, #cdk-nag);",
            "each option has <a id> scanners.<name>.options.<option>.",
        ],
    )
    lines += [
        "# Scanners reference",
        "",
        generated_note(GENERATOR, "the scanner plugins in the ASH source code"),
        "",
        (
            f"ASH ships {len(plugins)} scanners. The built-in ones are loaded on every "
            "scan. The others are community scanners, each in a plugin module that "
            "`ash scan` loads only when the configuration's `ash_plugin_modules` (or "
            "`--ash-plugin-modules`) names the module; for the MCP server, see "
            "[What a plugin can do](../plugins/index.md#what-a-plugin-can-do)."
        ),
        "",
        options_marker("scanners"),
        "| Scanner | Tool type | Enabled by default | Provided by | Command | Runs with `--python-only` |",
        "|---------|-----------|--------------------|-------------|---------|---------------------------|",
    ]
    for p in plugins:
        inst = p.instance
        python_only = None
        if inst is not None:
            try:
                python_only = bool(inst.is_python_only())
            except Exception:
                python_only = None
        command = _value(inst, "command") if inst is not None else None
        lines.append(
            f"| [{code(p.name)}](#{p.name}) | {_value(inst, 'tool_type') or 'not determined'} | "
            f"{yes_no(p.enabled)} | {package_short(p)} | "
            f"{code(command) if command else 'not determined'} | {yes_no(python_only)} |"
        )
    lines += [
        "",
        (
            "Tool type is the scanner's own `ScannerToolType`. `--python-only` keeps a "
            "scanner when its `is_python_only()` is true: the scanner class's own "
            "`python_only` when it states one; otherwise only when the scanner runs its "
            "tool through uv, declares no install commands, and has only pip "
            "dependencies. A scanner it does not keep is SKIPPED."
        ),
        "",
        ENV_NOTE_SLOT,
        "",
        *_baseline_environment(),
    ]

    for p in plugins:
        inst = p.instance
        lines += [f"## {code(p.name)}", ""]
        description = getattr(inst, "description", None) or getattr(
            inst, "tool_description", None
        )
        if description:
            lines += [md_prose(description), ""]
        network, env, env_set = _sandbox(p)
        facts = []
        page = scanner_page(p, docs_root)
        if page is not None:
            link = Path(os.path.relpath(page, reference_dir(docs_root))).as_posix()
            facts.append(("Scanner page", f"[{code(p.name)} scanner page]({link})"))
        facts += [
            ("Class", code(f"{p.cls.__module__}.{p.cls.__name__}")),
            ("Provided by", package_note(p)),
            ("Enabled by default", yes_no(p.enabled)),
            ("Tool type", str(_value(inst, "tool_type") or "not determined")),
            (
                "Command",
                code(_value(inst, "command"))
                if _value(inst, "command")
                else "not determined",
            ),
            ("Install", install_text(inst)),
            (
                "Offline strategy",
                code(_value(p.cls, "offline_strategy"))
                if _value(p.cls, "offline_strategy")
                else "not declared",
            ),
            ("Network in the sandbox, by default", network),
            ("Environment passed into the sandbox", env),
            ("Environment set under sandbox-exec", env_set),
        ]
        if p.instance_error:
            facts.append(
                ("Could not be built for inspection", md_prose(p.instance_error))
            )
        lines += [f"- {label}: {value}" for label, value in facts]
        lines.append("")
        lines += options_table(p, "scanners", missing)

    while lines and lines[-1] == "":
        lines.pop()
    stats = {"plugins": len(plugins), "missing": missing}
    return "\n".join(place_env_note(lines)) + "\n", stats


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="Exit 1 with a diff if stale."
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output path, or '-' for stdout. Default: <docs root>/docs/content/reference/{PAGE}",
    )
    parser.add_argument(
        "--missing-descriptions",
        default=None,
        help="Also write the options that have no description to this path.",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args()
    refuse_check_to_stdout(parser, args)

    docs_root = Path(args.docs_root).resolve()
    prepare_environment(docs_root)
    output = Path(args.output) if args.output else reference_dir(docs_root) / PAGE
    content, stats = generate(docs_root)
    summary = (
        f"{stats['plugins']} scanners, {len(stats['missing'])} options with no "
        "description in the model."
    )
    if args.missing_descriptions:
        Path(args.missing_descriptions).write_text(
            "\n".join(stats["missing"]) + "\n", encoding="utf-8"
        )
    if args.output == "-":
        sys.stdout.write(content)
        print(summary, file=sys.stderr)
        return 0
    return write_or_check(output, content, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
