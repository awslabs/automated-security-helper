#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate the plugin data the docs site's graphics read from the plugin registry.

Usage:
    uv run python scripts/generate_plugin_data_partial.py           # rewrite the partial
    uv run python scripts/generate_plugin_data_partial.py --check   # exit 1 with a diff if stale

Why this exists
---------------
The reference pages (``scanners.md``, ``reporters.md``, ``converters.md``) are written
from the plugin registry. The graphics on the home page were not: the scanner grid,
the scan example and the snippet builder named scanners, report formats and
converters by hand, so a renamed or removed plugin left them describing a set ASH no
longer ships, and nothing failed.

What it writes
--------------
``docs/overrides/partials/generated/plugin-data.html``, one Jinja template that sets
one variable, ``plugin_data``. A theme template reads it with::

    {% from "partials/generated/plugin-data.html" import plugin_data %}

``import`` is the form that works. A ``{% set %}`` in an included template is not
visible to the template that included it (``include`` renders in its own scope),
whereas the top-level ``{% set %}`` of an imported template is exported by the
import, the same way ``partials/ash-icons.html`` exports its macros.

What is derived and what is curated
-----------------------------------
From the registry: which scanners, reporters and converters exist; each scanner's
tool type (and with it its category and type tag); the converters' commands; each
reporter's file extension; the tools ``ash dependencies install`` manages (the
built-in scanners that declare install commands); the built-in scanner count.

The managed-tool set must not depend on the machine that regenerates it, so every
built-in scanner has to be accounted for: it declares install commands, or it is in
``MANAGED_TOOL_EXTRAS`` (managed although its commands are declared only where a
prerequisite exists), or in ``NOT_MANAGED`` (installed some other way). A scanner whose
instance cannot be built, or that fits none of the three, stops the generator instead of
dropping out of the CI snippets.

Curated here, keyed by plugin name, because nothing in the code says it:
``SCANNER_DOCS`` (display name, icon, tagline, language coverage), ``TRACKS`` (the
example files, findings and severities of the scan example), ``SCAN_FORMATS`` (which
report formats the example links), ``CONVERTER_DOCS`` (what each converter does, in a
sentence). This is the pattern ``REPORTER_DOCS`` in
``generate_reporter_docs.py`` already uses. The check is a completeness one: an entry
that names a plugin the registry lacks, a built-in scanner that is neither featured
nor named in ``HOME_GRID_OMITTED``, or an engine whose tool type puts it in another
category than its track, is an error, so a plugin cannot be removed or added without
the graphics being looked at.

Links go to ``reference/scanners.md`` and ``reference/reporters.md``, whose heading
ids are the plugins' config names.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _reference_docs import (  # noqa: E402
    add_docs_root_argument,
    prepare_environment,
    refuse_check_to_stdout,
    write_or_check,
)

GENERATOR = "scripts/generate_plugin_data_partial.py"
#: The partial, relative to ``--docs-root``, which is the checkout root (the default),
#: not its ``docs`` directory.
PARTIAL = Path("docs/overrides/partials/generated/plugin-data.html")
#: Pages the links point to, relative to the site root (as the templates' ``url`` filter wants them).
SCANNERS_URL = "reference/scanners/"
REPORTERS_URL = "reference/reporters/"

#: Scanner category by ``ScannerToolType`` value, as the home page's filter names it.
TOOL_TYPE_CATEGORY = {
    "SAST": "code",
    "IAC": "infrastructure",
    "SECRETS": "secrets",  # pragma: allowlist secret - a category name, not a secret
    "SCA": "dependencies",
    "SBOM": "dependencies",
}
#: The type tag on a scanner card, by ``ScannerToolType`` value.
TOOL_TYPE_TAG = {
    "SAST": "SAST",
    "IAC": "IaC",
    "SECRETS": "Secrets",  # pragma: allowlist secret - a type tag, not a secret
    "SCA": "SCA",
    "SBOM": "SBOM",
}
#: The filter buttons of the scanner grid, in order: category -> button label.
CATEGORY_LABELS = (
    ("code", "Code"),
    ("infrastructure", "Infrastructure"),
    ("secrets", "Secrets"),
    ("dependencies", "Dependencies"),
)

#: The scanners the home page's grid features, in the order it shows them, with the
#: words only a person can write. ``strip`` is how the one-line strip above the
#: workflow section shows the scanner: "icon" with its icon, "plain" as text, absent
#: when it is not in the strip.
SCANNER_DOCS: dict[str, dict[str, str]] = {
    "bandit": {
        "display": "Bandit",
        "icon": "language-python",
        "tagline": "Python security checks",
        "covers": "Python",
        "strip": "plain",
    },
    "semgrep": {
        "display": "Semgrep",
        "icon": "code-braces",
        "tagline": "Pattern-based code checks",
        "covers": "Multiple languages",
        "strip": "plain",
    },
    "opengrep": {
        "display": "Opengrep",
        "icon": "code-tags-check",
        "tagline": "Pattern-based code checks",
        "covers": "Multiple languages",
    },
    "checkov": {
        "display": "Checkov",
        "icon": "check-decagram-outline",
        "tagline": "Infrastructure policy checks",
        "covers": "Terraform, Kubernetes, CloudFormation",
        "strip": "icon",
    },
    "cdk-nag": {
        "display": "CDK-Nag",
        "icon": "cloud-check-outline",
        "tagline": "NagPack policy checks",
        "covers": "CloudFormation",
    },
    "cfn-nag": {
        "display": "CFN-Nag",
        "icon": "cloud-outline",
        "tagline": "Template security checks",
        "covers": "CloudFormation",
    },
    "detect-secrets": {
        "display": "detect-secrets",
        "icon": "fingerprint",
        "tagline": "Secret detection",
        "covers": "Text files",
        "strip": "icon",
    },
    "grype": {
        "display": "Grype",
        "icon": "cube-scan",
        "tagline": "Vulnerability matching",
        "covers": "Packages and container images",
        "strip": "icon",
    },
    "npm-audit": {
        "display": "npm audit",
        "icon": "package-variant-closed",
        "tagline": "Dependency vulnerability checks",
        "covers": "Node.js",
    },
    "syft": {
        "display": "Syft",
        "icon": "layers-outline",
        "tagline": "Software inventory",
        "covers": "SBOM generation",
        "strip": "icon",
    },
}
#: Built-in scanners the grid deliberately does not feature. Every built-in scanner
#: is in ``SCANNER_DOCS`` or here, so adding one forces the choice.
HOME_GRID_OMITTED = (
    "actionlint",
    "cfn-guard",
    "cfn-lint",
    "gitleaks",
    "trivy",
    "zizmor",
)

#: Built-in scanners whose tool ``ash dependencies install`` installs although the
#: scanner declares no install commands on every machine. cfn-nag is a Ruby gem: its
#: install commands exist only where RubyGems is on PATH (the instance logs "cannot
#: be installed here" otherwise), so the registry cannot be asked, and the install
#: step of the CI snippets must name it all the same.
MANAGED_TOOL_EXTRAS = ("cfn-nag",)
#: Built-in scanners that declare no install commands because ASH installs their
#: tool another way (``uv tool install`` on first use, a Python dependency of ASH, the
#: Node.js on the machine), so ``ash dependencies install --tool`` is not how the CI
#: snippets get them. A scanner here that starts declaring install commands is an
#: error, so the snippets are not left without a tool that is now managed.
NOT_MANAGED = (
    "bandit",
    "cdk-nag",
    "cfn-lint",
    "checkov",
    "detect-secrets",
    "npm-audit",
    "semgrep",
    "zizmor",
)

#: What each converter does, for the sentence under the scan example. ``{command}`` is
#: filled from the converter's own command. An unknown or missing converter fails
#: ``--check``.
CONVERTER_DOCS: dict[str, str] = {
    "archive": "extracts the scannable members of zip and tar archives",
    "jupyter": "turns each notebook into a Python script with {command}",
}

#: The scan example's rows: the category it filters on, the file it shows, and the
#: scanners it says run on it. ``engines`` is a list of groups; a group of several
#: scanners shows as "A + B". The finding and severity are an example, not output.
TRACKS: tuple[dict[str, Any], ...] = (
    {
        "category": "code",
        "label": "Code",
        "file": "app.py",
        "icon": "code-braces",
        "engines": (("bandit",), ("semgrep",)),
        "finding": "Shell command",
        "severity": "High",
    },
    {
        "category": "infrastructure",
        "label": "Infrastructure",
        "file": "template.yaml",
        "icon": "cloud-outline",
        "engines": (("checkov",), ("cfn-nag",)),
        "finding": "Public ingress",
        "severity": "High",
    },
    {
        "category": "secrets",
        "label": "Secrets",
        "file": ".env",
        "icon": "key-outline",
        "engines": (("detect-secrets",),),
        "finding": "Embedded credential",
        "severity": "High",
    },
    {
        "category": "dependencies",
        "label": "Dependencies",
        "file": "package-lock.json",
        "icon": "package-variant-closed",
        "engines": (("npm-audit",), ("syft", "grype")),
        "finding": "Package vulnerability",
        "severity": "Medium",
    },
    {
        # A notebook is converted to Python first, so a code scanner reads it.
        "category": "notebooks",
        "label": "Notebook",
        "file": "analysis.ipynb",
        "icon": "file-document-outline",
        "engines": (("bandit",),),
        "finding": "Hardcoded password",
        "severity": "High",
        "scanner_category": "code",
    },
)

#: The report formats the scan example links: reporter name, the chip's label, and
#: the key ``ash-scan.js`` animates it by.
SCAN_FORMATS = (
    ("html", "HTML", "html"),
    ("sarif", "SARIF", "sarif"),
    ("markdown", "Markdown", "markdown"),
    ("flat-json", "JSON", "json"),
)


def editorial_problems(
    scanners: dict[str, str | None],
    builtin: set[str],
    reporters: set[str],
) -> list[str]:
    """What is wrong with the curated maps against the registry; empty when complete.

    ``scanners`` maps every registered scanner name to its tool type value (None when
    it could not be determined), ``builtin`` is the built-in subset, ``reporters``
    the registered reporter names. Pure, so a test can feed it any registry.
    """
    problems: list[str] = []
    for name in SCANNER_DOCS:
        if name not in scanners:
            problems.append(f"SCANNER_DOCS names {name!r}, which no scanner registers")
    for name in HOME_GRID_OMITTED:
        if name not in scanners:
            problems.append(
                f"HOME_GRID_OMITTED names {name!r}, which no scanner registers"
            )
        if name in SCANNER_DOCS:
            problems.append(f"{name!r} is both featured and in HOME_GRID_OMITTED")
    for name in sorted(builtin):
        if name not in SCANNER_DOCS and name not in HOME_GRID_OMITTED:
            problems.append(
                f"built-in scanner {name!r} is neither in SCANNER_DOCS nor in "
                "HOME_GRID_OMITTED; feature it or omit it on purpose"
            )
    for name, docs in SCANNER_DOCS.items():
        for key in ("display", "icon", "tagline", "covers"):
            if not docs.get(key):
                problems.append(f"SCANNER_DOCS[{name!r}] has no {key}")
        if docs.get("strip", "icon") not in ("icon", "plain"):
            problems.append(f"SCANNER_DOCS[{name!r}] strip must be 'icon' or 'plain'")
        tool_type = scanners.get(name)
        if name in scanners and tool_type not in TOOL_TYPE_CATEGORY:
            problems.append(
                f"scanner {name!r} has tool type {tool_type!r}, which no home page "
                "category covers; add it to TOOL_TYPE_CATEGORY and TOOL_TYPE_TAG"
            )
    categories = {slug for slug, _ in CATEGORY_LABELS}
    for track in TRACKS:
        scanner_category = track.get("scanner_category", track["category"])
        if scanner_category not in categories:
            problems.append(
                f"track {track['category']!r} has no category {scanner_category!r}"
            )
        for group in track["engines"]:
            for name in group:
                if name not in SCANNER_DOCS:
                    problems.append(
                        f"track {track['category']!r} names {name!r}, which is not "
                        "in SCANNER_DOCS (it needs a display name)"
                    )
                    continue
                derived = TOOL_TYPE_CATEGORY.get(scanners.get(name) or "")
                if name in scanners and derived != scanner_category:
                    problems.append(
                        f"track {track['category']!r} puts {name!r} under "
                        f"{scanner_category!r}, but its tool type "
                        f"{scanners.get(name)!r} is category {derived!r}"
                    )
    for reporter, _label, _key in SCAN_FORMATS:
        if reporter not in reporters:
            problems.append(
                f"SCAN_FORMATS names {reporter!r}, which no reporter registers"
            )
    return problems


def managed_problems(declares: dict[str, bool | None]) -> list[str]:
    """What makes the managed-tool set depend on the machine, or on a stale list.

    ``declares`` maps every built-in scanner to whether its instance declares install
    commands, or None when no instance could be built. Each built-in must be
    accountable: declaring install commands, or named in ``MANAGED_TOOL_EXTRAS`` or
    ``NOT_MANAGED``. Pure, so a test can feed it any registry.
    """
    problems: list[str] = []
    for name in (*MANAGED_TOOL_EXTRAS, *NOT_MANAGED):
        if name not in declares:
            problems.append(
                f"{name!r} is named in MANAGED_TOOL_EXTRAS or NOT_MANAGED but is not "
                "a built-in scanner"
            )
    for name in MANAGED_TOOL_EXTRAS:
        if name in NOT_MANAGED:
            problems.append(f"{name!r} is in both MANAGED_TOOL_EXTRAS and NOT_MANAGED")
    for name, declared in sorted(declares.items()):
        if declared is None:
            problems.append(
                f"built-in scanner {name!r} could not be built, so whether it is a "
                "managed tool is unknown on this machine; the partial would differ "
                "from one built elsewhere"
            )
        elif declared and name in NOT_MANAGED:
            problems.append(
                f"{name!r} declares install commands but is in NOT_MANAGED; move it "
                "out so the CI snippets install it"
            )
        elif (
            not declared and name not in MANAGED_TOOL_EXTRAS and name not in NOT_MANAGED
        ):
            problems.append(
                f"built-in scanner {name!r} declares no install commands and is in "
                "neither MANAGED_TOOL_EXTRAS nor NOT_MANAGED; say which it is"
            )
    return problems


def converter_problems(commands: dict[str, str | None]) -> list[str]:
    """What is wrong with ``CONVERTER_DOCS`` against the registered converters.

    ``commands`` maps each registered converter to its command (None when it runs in
    the ASH process).
    """
    problems: list[str] = []
    for name in CONVERTER_DOCS:
        if name not in commands:
            problems.append(
                f"CONVERTER_DOCS names {name!r}, which no converter registers"
            )
    for name, command in sorted(commands.items()):
        text = CONVERTER_DOCS.get(name)
        if text is None:
            problems.append(f"converter {name!r} has no entry in CONVERTER_DOCS")
        elif "{command}" in text and not command:
            problems.append(
                f"CONVERTER_DOCS[{name!r}] uses {{command}}, but the converter has none"
            )
    return problems


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _literal(value: Any, depth: int = 0) -> str:
    """``value`` as a Jinja expression: JSON, with ``none`` for null.

    Scalars and short scalar lists stay on one line; anything else is indented, so
    the diff of a change reads as the change.
    """
    pad = "  " * depth
    inner = "  " * (depth + 1)
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        text = json.dumps(value)  # ASCII only: non-ASCII becomes \uXXXX
        for opener in ("{{", "{%", "{#"):
            if opener in text:
                raise ValueError(f"{value!r} would be read as Jinja ({opener})")
        return text
    if isinstance(value, (list, tuple)):
        if not value:
            return "[]"
        items = [_literal(v, depth + 1) for v in value]
        one_line = "[" + ", ".join(items) + "]"
        if all(not isinstance(v, (list, tuple, dict)) for v in value) and len(
            one_line
        ) <= 78 - len(pad):
            return one_line
        return "[\n" + ",\n".join(inner + i for i in items) + "\n" + pad + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        rows = [
            f"{inner}{json.dumps(k)}: {_literal(v, depth + 1)}"
            for k, v in value.items()
        ]
        return "{\n" + ",\n".join(rows) + "\n" + pad + "}"
    raise TypeError(f"cannot render {type(value).__name__} as a Jinja literal")


def render(data: dict[str, Any]) -> str:
    """The partial's text for ``data``."""
    command = f"uv run python {GENERATOR}"
    return (
        "{#-\n"
        f"  Generated by {GENERATOR} from the plugin registry\n"
        "  (the ASH_SCANNERS, ASH_REPORTERS and ASH_CONVERTERS lists of the packages\n"
        "  under automated_security_helper/plugin_modules) and the curated maps in the\n"
        "  generator.\n"
        "  Do not edit this file by hand: change the code or the generator, then run\n"
        f"    {command}\n"
        "  tests/unit/test_generated_docs_freshness.py (integration tier) runs\n"
        f"  `{command} --check` and fails when this file is stale.\n"
        "\n"
        "  Read it from a theme template with\n"
        '    {% from "partials/generated/plugin-data.html" import plugin_data %}\n'
        "  not with include: an include's {% set %} does not reach the including template.\n"
        "-#}\n"
        f"{{% set plugin_data = {_literal(data)} %}}\n"
    )


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _declares_install(instance: Any) -> bool:
    """Whether the scanner declares commands for ``ash dependencies install`` to run."""
    table = getattr(instance, "custom_install_commands", None) or {}
    return any(
        commands for per_arch in table.values() for commands in per_arch.values()
    )


def collect() -> tuple[dict[str, Any], list[str]]:
    """The data and the problems with the curated maps, from the live registry."""
    from _plugin_reference import discover, instantiate

    import generate_reporter_docs as reporter_docs

    scanner_plugins = discover("scanner")
    reporter_plugins = discover("reporter")
    converter_plugins = discover("converter")
    instantiate(scanner_plugins)
    instantiate(converter_plugins)

    tool_types: dict[str, str | None] = {}
    for plugin in scanner_plugins:
        value = _enum_value(getattr(plugin.instance, "tool_type", None))
        tool_types[plugin.name] = str(value) if value else None
    builtin = {p.name for p in scanner_plugins if p.builtin}
    reporter_names = {p.name for p in reporter_plugins}
    problems = editorial_problems(tool_types, builtin, reporter_names)

    extensions: dict[str, str | None] = {}
    for plugin in reporter_plugins:
        if plugin.config_cls is not None:
            extensions[plugin.name] = reporter_docs.config_defaults(plugin.config_cls)[
                "extension"
            ]

    home = []
    for name, docs in SCANNER_DOCS.items():
        tool_type = tool_types.get(name) or ""
        entry: dict[str, Any] = {
            "name": name,
            "display": docs["display"],
            "category": TOOL_TYPE_CATEGORY.get(tool_type),
            "icon": docs["icon"],
            "tagline": docs["tagline"],
            "covers": docs["covers"],
            "tag": TOOL_TYPE_TAG.get(tool_type),
            "strip": docs.get("strip"),
            "href": f"{SCANNERS_URL}#{name}",
        }
        home.append(entry)

    tracks = []
    for track in TRACKS:
        tracks.append(
            {
                "category": track["category"],
                "label": track["label"],
                "file": track["file"],
                "icon": track["icon"],
                "engines": [
                    " + ".join(SCANNER_DOCS.get(n, {}).get("display", n) for n in group)
                    for group in track["engines"]
                ],
                "finding": track["finding"],
                "severity": track["severity"],
            }
        )

    formats = []
    for reporter, label, key in SCAN_FORMATS:
        formats.append(
            {
                "name": reporter,
                "label": label,
                "key": key,
                "extension": extensions.get(reporter),
                "href": f"{REPORTERS_URL}#{reporter}",
            }
        )

    commands = {
        plugin.name: getattr(plugin.instance, "command", None) or None
        for plugin in converter_plugins
    }
    problems += converter_problems(commands)
    converters = []
    for name, command in sorted(commands.items()):
        text = CONVERTER_DOCS.get(name, "")
        converters.append(
            {
                "name": name,
                "command": command,
                "description": text.replace("{command}", command or ""),
            }
        )

    declares: dict[str, bool | None] = {
        plugin.name: (
            None if plugin.instance is None else _declares_install(plugin.instance)
        )
        for plugin in scanner_plugins
        if plugin.builtin
    }
    problems += managed_problems(declares)
    managed = sorted(
        {name for name, declared in declares.items() if declared}
        | set(MANAGED_TOOL_EXTRAS)
    )

    data = {
        "scanners": {
            "all": sorted(p.name for p in scanner_plugins),
            "builtin": sorted(builtin),
            "builtin_count": len(builtin),
            "home": home,
            "home_count": len(home),
            "categories": [
                {"slug": slug, "label": label} for slug, label in CATEGORY_LABELS
            ],
            "reference_href": SCANNERS_URL,
        },
        "tracks": tracks,
        "formats": formats,
        "converters": converters,
        "managed_tools": managed,
    }
    return data, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check", action="store_true", help="Exit 1 with a diff if stale."
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output path, or '-' for stdout. Default: <docs root>/{PARTIAL.as_posix()}",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args()
    refuse_check_to_stdout(parser, args)

    docs_root = Path(args.docs_root).resolve()
    if args.output is None and not (docs_root / PARTIAL.parent.parent).is_dir():
        parser.error(
            f"--docs-root {docs_root} has no {PARTIAL.parent.parent.as_posix()}; "
            "name the checkout root (the default), not its docs directory"
        )
    prepare_environment(docs_root)
    output = Path(args.output) if args.output else docs_root / PARTIAL
    data, problems = collect()
    if problems:
        print(
            f"{GENERATOR}: the curated maps do not match the plugin registry:",
            file=sys.stderr,
        )
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    content = render(data)
    summary = (
        f"{data['scanners']['builtin_count']} built-in scanners, "
        f"{data['scanners']['home_count']} on the home grid, "
        f"{len(data['formats'])} report formats, {len(data['converters'])} converters, "
        f"{len(data['managed_tools'])} managed tools."
    )
    if args.output == "-":
        sys.stdout.write(content)
        print(summary, file=sys.stderr)
        return 0
    return write_or_check(output, content, args.check, GENERATOR, summary)


if __name__ == "__main__":
    sys.exit(main())
