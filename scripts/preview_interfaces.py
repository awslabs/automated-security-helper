# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate local review artifacts without running scanners or posting comments.

Run from the repository root:
    uv run --group dev python scripts/preview_interfaces.py
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import html
import json
import re
from pathlib import Path

import markdown
import pytest

from automated_security_helper.cli.inspect.inspect_findings_app import (
    FindingsExplorerApp,
    extract_findings,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.ui_theme import FOOTER_CREDIT
from automated_security_helper.plugin_modules.ash_builtin.reporters.html_reporter import (
    HtmlReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    MarkdownReporter,
    MarkdownReporterConfig,
    MarkdownReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.text_reporter import (
    TextReporter,
)
from tests.snapshot.support.fixture_model import (
    CLOCK,
    REPORT_TIME,
    build_fixture_model,
    build_fixture_workspace_model,
    finalize_fixture_model,
    fixture_plugin_context,
    pin_clock,
    workspace_reporter_context,
)


COMMENT_CSS = """
*{box-sizing:border-box}body{margin:0;padding:3rem 1rem;background:#0d1117;color:#e6edf3;font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:920px;margin:auto}h1{font-size:26px;border-bottom:1px solid #30363d;padding-bottom:.4em}h2{font-size:21px;border-bottom:1px solid #30363d;padding-bottom:.3em}h3{font-size:17px}a{color:#79c0ff}
article{padding:24px;border:1px solid #30363d;border-radius:8px;background:#161b22;overflow-wrap:anywhere}
.preview-note{color:#919da9;margin:0 0 1rem}.table-scroll{overflow:auto}table{border-collapse:collapse;font-size:13px;white-space:nowrap}th,td{border:1px solid #30363d;padding:7px 12px}th{font-weight:600}tr:nth-child(2n){background:#1c222a}
blockquote{margin:1rem 0;padding:.1rem 1rem;border-left:3px solid #d29922;background:#211f19;border-radius:0 5px 5px 0}
summary{cursor:pointer;padding:7px 0;font-weight:500}details{margin:10px 0}details[open]{padding-bottom:5px}code,pre{font:12px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace}code{background:#242c35;padding:2px 4px;border-radius:4px}pre{overflow:auto;padding:16px;background:#0d1117;border-radius:6px}pre code{padding:0;background:none}
hr{border:0;border-top:1px solid #30363d;margin:1.8rem 0}:focus-visible{outline:2px solid #79c0ff;outline-offset:3px}
@media(max-width:600px){body{padding:1rem .6rem}article{padding:15px}h1{font-size:23px}}
@media(prefers-color-scheme:light){body{background:#f6f8fa;color:#1f2328}article{background:#fff;border-color:#d0d7de}h1,h2,hr{border-color:#d0d7de}th,td{border-color:#d0d7de}tr:nth-child(2n){background:#f6f8fa}blockquote{background:#fff8df}pre{background:#f6f8fa}code{background:#eff1f3}a{color:#0969da}.preview-note{color:#59636e}}
"""

PREVIEW_CSS = """
*{box-sizing:border-box}body{margin:0;background:#0f141a;color:#dedee3;font:16px/1.5 "Open Sans",Helvetica,Arial,sans-serif}
main{max-width:1040px;padding:32px 24px;margin:auto}h1{font-size:24px;line-height:30px}p,footer{color:#b4b4bb}
a{color:#42b4ff}ul{padding:0;display:grid;gap:8px;list-style:none}li a{display:block;padding:12px 16px;border:1px solid #424650;border-radius:8px;background:#161d26;text-decoration:none}
li a:hover{border-color:#42b4ff;background:#001129}:focus-visible{outline:2px solid #42b4ff;outline-offset:4px}
footer{margin-top:32px;padding-top:16px;border-top:1px solid #424650;font-size:12px}
@media(prefers-color-scheme:light){body{background:#f9f9fa;color:#0f141a}p,footer{color:#424650}a{color:#006ce0}li a{background:#fff;border-color:#c6c6cd}li a:hover{background:#f0fbff;border-color:#006ce0}footer{border-color:#c6c6cd}}
"""


def render_comment(document: str) -> str:
    body = markdown.markdown(
        document.replace("<details>", '<details markdown="1">'),
        extensions=["tables", "fenced_code", "md_in_html"],
    )
    # GitHub recognizes these alert markers; the offline preview displays the
    # same outcome in a blockquote using only local styles.
    for marker in ("WARNING", "CAUTION", "TIP"):
        body = body.replace(f"[!{marker}]", marker.title())
    body = body.replace(
        "<table>",
        '<div class="table-scroll" role="region" aria-label="Report table" tabindex="0"><table>',
    ).replace("</table>", "</table></div>")
    return (
        '<!DOCTYPE html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>ASH · GitHub comment preview</title><style>{COMMENT_CSS}</style>"
        '<main><p class="preview-note">GitHub comment preview · Fixture data</p>'
        f"<article>{body}</article></main></html>"
    )


async def render_tui(findings: list, destination: Path) -> None:
    def save(app: FindingsExplorerApp, filename: str) -> None:
        # Rich's SVG export declares remote fonts. Keep fixture previews offline.
        document = re.sub(
            r"@font-face\s*\{[^}]*\}", "", app.export_screenshot()
        ).replace("font-family: Fira Code, monospace;", "font-family: monospace;")
        destination.joinpath(filename).write_text(document, encoding="utf-8")

    for width, height in ((60, 24), (80, 24), (120, 36)):
        app = FindingsExplorerApp(
            findings, config_path=destination / "preview.ash.yaml"
        )
        async with app.run_test(size=(width, height)) as pilot:
            await pilot.pause()
            save(app, f"tui-{width}.svg")
            if width == 80:
                for key, name in (("f", "filters"), ("f", None), ("/", "search")):
                    await pilot.press(key)
                    await pilot.pause()
                    if name:
                        save(app, f"tui-{width}-{name}.svg")
                await pilot.press("escape", "v")
                await pilot.pause()
                save(app, f"tui-{width}-detail.svg")
                await pilot.press("escape", "x")
                await pilot.pause()
                save(app, f"tui-{width}-suppression.svg")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/ui-tests/.previews"))
    parser.add_argument("--skip-tui", action="store_true")
    arguments = parser.parse_args()
    destination = arguments.output.resolve()
    destination.mkdir(parents=True, exist_ok=True)
    with pytest.MonkeyPatch.context() as monkeypatch:
        pin_clock(monkeypatch)
        context = fixture_plugin_context(destination)
        single = finalize_fixture_model(build_fixture_model(destination, context))
        single.ash_config.project_name = "example-service"
        single.metadata.project_name = "example-service"
        workspace = build_fixture_workspace_model(
            destination / "workspace", monkeypatch, with_skipped_project=True
        )
        CLOCK.set(REPORT_TIME)
        examples = {
            "review": (single, context),
            "empty": (AshAggregatedResults(), context),
            "workspace": (
                workspace,
                workspace_reporter_context(workspace, destination / "workspace"),
            ),
        }
        manifest = {}
        for name, (model, report_context) in examples.items():
            documents = {
                "report.html": HtmlReporter(context=report_context).report(model),
                "comment.md": MarkdownReporter(context=report_context).report(model),
                "summary.txt": TextReporter(context=report_context).report(model),
                "comment-compact.md": MarkdownReporter(
                    context=report_context,
                    config=MarkdownReporterConfig(
                        options=MarkdownReporterConfigOptions(compact=True)
                    ),
                ).report(model),
            }
            documents["comment.html"] = render_comment(documents["comment.md"])
            manifest[name] = {}
            for suffix, document in documents.items():
                filename = f"{name}-{suffix}"
                destination.joinpath(filename).write_text(document, encoding="utf-8")
                manifest[name][suffix] = filename
        if not arguments.skip_tui:
            asyncio.run(render_tui(extract_findings(single), destination))
        destination.joinpath("manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        links = "".join(
            f'<li><a href="{html.escape(filename)}">{html.escape(name)} · {html.escape(suffix)}</a></li>'
            for name, documents in manifest.items()
            for suffix, filename in documents.items()
        )
        links += "".join(
            f'<li><a href="{html.escape(preview.name)}">{html.escape(preview.stem)}</a></li>'
            for preview in sorted(destination.glob("tui-*.svg"))
        )
        fonts = Path(__file__).resolve().parents[1] / "docs/content/assets/fonts"
        font_data = base64.b64encode(
            fonts.joinpath("open-sans.woff2").read_bytes()
        ).decode("ascii")
        font_license = fonts.joinpath("open-sans-OFL.txt").read_text(encoding="utf-8")
        font_css = (
            f"/* {font_license} */"
            '@font-face{font-family:"Open Sans";font-style:normal;font-weight:300 800;'
            'font-display:swap;src:url("data:font/woff2;base64,'
            f'{font_data}") format("woff2")}}'
        )
        destination.joinpath("index.html").write_text(
            '<!DOCTYPE html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>ASH interface previews</title><style>{font_css}{PREVIEW_CSS}</style>"
            "<main><h1>ASH interface previews</h1><p>Fixture reports and terminal screens.</p>"
            f'<p><a href="gallery.html">Image gallery and scan playback</a></p><ul>{links}</ul>'
            f"<footer>{html.escape(FOOTER_CREDIT)}</footer></main></html>",
            encoding="utf-8",
        )
    print(f"Interface previews: {destination / 'index.html'}")


if __name__ == "__main__":
    main()
