# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/validate_url_history.py: planted bad mappings fail, the real map passes.

Each planted fixture is a miniature checkout carrying exactly one defect the
validator exists to catch - a mapped target no page serves, a redirect chain, a
loop, a historical URL nothing covers, a map entry docs/redirects.yml does not
materialize or contradicts, a redirect shadowing a live page, and a built site
whose stub points nowhere. A validator change that stops flagging any of them
fails here before it can wave a broken mapping through CI. The last tests run
the validator over this checkout itself, so the committed ledger, map and
docs/redirects.yml cannot drift apart without failing the unit suite either.

The file is also runnable directly (``python -I -B`` on it) as a plain
assertion driver, for environments that check the predicates without pytest.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

try:
    import pytest
except ImportError:  # the direct-run driver at the bottom needs no pytest
    pytest = None  # type: ignore[assignment]
    pytestmark = None
else:
    pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]

#: Rows the committed fixtures hold today; the counts only ever grow, so a
#: shrink means the ledger or the map lost rows it should have kept.
HISTORY_FLOOR = 149
MAPPED_FLOOR = 70

PAGE = "# A page\n"
REAL_HTML = "<!doctype html><html><body><p>a real page</p></body></html>\n"


def _load() -> ModuleType:
    """Load the script under test by path, the way conftest.load_script does."""
    name = "_ash_script_validate_url_history"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "scripts" / "validate_url_history.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def plant(
    tmp_path: Path,
    *,
    redirects: dict[str, str] | None = None,
    tombstones: list[str] | None = None,
    yml: dict[str, str] | None = None,
    history: list[str] | None = None,
    pages: tuple[str, ...] = ("how-to/install.md",),
    renames: list[tuple[str, str]] | None = None,
    counts: dict[str, int] | None = None,
) -> Path:
    """A miniature checkout with the three inputs the validator reads."""
    root = tmp_path / "repo"
    docs = root / "docs" / "content"
    for page in pages:
        path = docs / page
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(PAGE, encoding="utf-8")
    docs.mkdir(parents=True, exist_ok=True)
    history_dir = root / "docs" / "url-history"
    history_dir.mkdir(parents=True, exist_ok=True)
    document: dict = {"redirects": redirects or {}, "tombstones": tombstones or []}
    if counts is not None:
        document["counts"] = counts
    (history_dir / "url-redirect-map.json").write_text(
        json.dumps(document), encoding="utf-8"
    )
    lines = ["redirects:"] + [f"  {old}: {new}" for old, new in (yml or {}).items()]
    (root / "docs" / "redirects.yml").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    rows = ["tag-range\tkind\told-url\tnew-url-or-empty"]
    rows += [f"v1..v2\tD\t{url}" for url in history or []]
    rows += [f"v1..v2\tR\t{old}\t{new}" for old, new in renames or []]
    (history_dir / "historical-urls.tsv").write_text(
        "\n".join(rows) + "\n", encoding="utf-8"
    )
    return root


def stub_html(rel_target: str) -> str:
    """A redirect page of the shape docs/hooks/redirects.py writes."""
    return (
        "<!doctype html><html><head>"
        f'<meta http-equiv="refresh" content="0; url={rel_target}">'
        "</head><body></body></html>\n"
    )


def put_site_page(site: Path, url: str, text: str) -> None:
    page = site / url.strip("/") / "index.html"
    page.parent.mkdir(parents=True, exist_ok=True)
    page.write_text(text, encoding="utf-8")


def test_planted_missing_target_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        redirects={"/gone/": "/nowhere/"},
        yml={"gone.md": "nowhere.md"},
        history=["gone/"],
    )
    findings, _summary = vuh.run(root)
    assert any("maps to /nowhere/" in f for f in findings), findings


def test_planted_chain_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        yml={"a.md": "b.md", "b.md": "c.md"},
        pages=("c.md",),
        history=["a/", "b/"],
    )
    findings, _summary = vuh.run(root)
    assert any("redirect chain: /a/ -> /b/" in f for f in findings), findings


def test_planted_loop_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(tmp_path, yml={"a.md": "b.md", "b.md": "a.md"}, pages=())
    findings, _summary = vuh.run(root)
    assert any("redirect loop" in f for f in findings), findings


def test_planted_uncovered_history_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(tmp_path, history=["vanished/"])
    findings, _summary = vuh.run(root)
    assert any(
        "historical URL /vanished/ is dead and uncovered" in f for f in findings
    ), findings


def test_tombstone_covers_a_dead_url(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(tmp_path, history=["vanished/"], tombstones=["/vanished/"])
    findings, _summary = vuh.run(root)
    assert findings == []


def test_planted_unmaterialized_map_entry_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(tmp_path, redirects={"/gone/": "/how-to/install/"})
    findings, _summary = vuh.run(root)
    assert any("no docs/redirects.yml entry" in f for f in findings), findings


def test_planted_disagreeing_target_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        redirects={"/gone/": "/how-to/install/"},
        yml={"gone.md": "other.md"},
        pages=("how-to/install.md", "other.md"),
    )
    findings, _summary = vuh.run(root)
    assert any("make them agree" in f for f in findings), findings


def test_planted_shadowed_url_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        yml={"dup.md": "how-to/install.md"},
        pages=("how-to/install.md", "dup/index.md"),
    )
    findings, _summary = vuh.run(root)
    assert any("would overwrite it" in f for f in findings), findings


def test_planted_pair_of_old_pages_serving_one_url_fails(tmp_path: Path) -> None:
    vuh = _load()
    # ``x.md`` and ``x/index.md`` are one URL, ``/x/``; their redirect pages
    # would overwrite each other and the later entry would win unannounced.
    root = plant(
        tmp_path,
        yml={"x.md": "how-to/install.md", "x/index.md": "other.md"},
        pages=("how-to/install.md", "other.md"),
    )
    findings, _summary = vuh.run(root)
    matching = [f for f in findings if "already serves" in f]
    assert len(matching) == 1, findings
    assert "redirects.yml:3:" in matching[0] and "(line 2)" in matching[0], matching


def test_distinct_old_pages_serving_distinct_urls_pass(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        yml={"x.md": "how-to/install.md", "y/index.md": "how-to/install.md"},
    )
    findings, _summary = vuh.run(root)
    assert not [f for f in findings if "already serves" in f], findings


def test_planted_wrong_map_counts_fail(tmp_path: Path) -> None:
    vuh = _load()
    redirects = {"/a/": "/how-to/install/", "/b/": "/how-to/install/"}
    yml = {"a.md": "how-to/install.md", "b.md": "how-to/install.md"}
    wrong = plant(
        tmp_path,
        redirects=redirects,
        yml=yml,
        counts={"dead": 2, "mapped": 3, "distinct_targets": 2},
    )
    findings, _summary = vuh.run(wrong)
    assert any("counts.mapped says 3" in f for f in findings), findings
    assert any("counts.distinct_targets says 2" in f for f in findings), findings
    assert not any("counts.dead" in f for f in findings), findings


def test_right_map_counts_and_unchecked_classification_keys_pass(
    tmp_path: Path,
) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        redirects={"/a/": "/how-to/install/", "/b/": "/how-to/install/"},
        yml={"a.md": "how-to/install.md", "b.md": "how-to/install.md"},
        counts={
            "dead": 2,
            "mapped": 2,
            "distinct_targets": 1,
            "tombstones": 0,
            "rename_chain": 99,  # classification only: never checked
            "fallbacks": 99,
        },
    )
    findings, _summary = vuh.run(root)
    assert findings == []


def test_planted_unresolvable_rename_target_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        renames=[("old-page/", "no-such-page/")],
        yml={"old-page.md": "how-to/install.md"},
    )
    findings, _summary = vuh.run(root)
    assert any(
        "historical-urls.tsv:2:" in f and "/no-such-page/" in f for f in findings
    ), findings


def test_planted_malformed_rename_target_fails(tmp_path: Path) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        renames=[("old-page/", "how-to/install/?x=1")],
        yml={"old-page.md": "how-to/install.md"},
    )
    findings, _summary = vuh.run(root)
    assert any("is not a /path/ page URL" in f for f in findings), findings


def test_rename_targets_a_page_a_redirect_or_a_mapped_url_serves_pass(
    tmp_path: Path,
) -> None:
    vuh = _load()
    root = plant(
        tmp_path,
        redirects={"/gone/": "/how-to/install/"},
        yml={
            "gone.md": "how-to/install.md",
            "moved.md": "how-to/install.md",
            "a.md": "how-to/install.md",
            "b.md": "how-to/install.md",
        },
        renames=[
            ("a/", "how-to/install/"),  # a served page
            ("b/", "moved/"),  # a redirect entry's old page
            ("c/", "gone/"),  # a mapped dead URL
        ],
        history=["c/"],
    )
    findings, _summary = vuh.run(root)
    assert not [f for f in findings if "historical-urls.tsv:" in f], findings


def test_planted_broken_site_stub_fails(tmp_path: Path) -> None:
    vuh = _load()
    site = tmp_path / "site"
    put_site_page(site, "/", REAL_HTML)
    put_site_page(site, "/gone/", stub_html("../missing/"))
    mapping = {"redirects": {"/gone/": "/missing/"}, "tombstones": set()}
    findings = vuh.check_built_site(site, [], mapping)
    assert any("/missing/ is not in the built site" in f for f in findings), findings


def test_planted_site_loop_fails(tmp_path: Path) -> None:
    vuh = _load()
    site = tmp_path / "site"
    put_site_page(site, "/", REAL_HTML)
    put_site_page(site, "/a/", stub_html("../b/"))
    put_site_page(site, "/b/", stub_html("../a/"))
    findings = vuh.check_built_site(
        site, ["/a/"], {"redirects": {}, "tombstones": set()}
    )
    assert any("redirect loop in the built site" in f for f in findings), findings


def test_resolving_site_stub_passes(tmp_path: Path) -> None:
    vuh = _load()
    site = tmp_path / "site"
    put_site_page(site, "/", REAL_HTML)
    put_site_page(site, "/how-to/install/", REAL_HTML)
    put_site_page(site, "/gone/", stub_html("../how-to/install/"))
    mapping = {"redirects": {"/gone/": "/how-to/install/"}, "tombstones": set()}
    findings = vuh.check_built_site(site, ["/gone/"], mapping)
    assert findings == []


def test_the_real_mapping_passes(tmp_path: Path) -> None:
    vuh = _load()
    findings, summary = vuh.run(REPO_ROOT)
    assert findings == [], summary


def test_the_committed_fixtures_keep_their_rows(tmp_path: Path) -> None:
    vuh = _load()
    history, findings = vuh.load_history(
        REPO_ROOT / "docs" / "url-history" / "historical-urls.tsv"
    )
    assert findings == []
    assert len(history) >= HISTORY_FLOOR
    mapping, map_findings = vuh.load_map(
        REPO_ROOT / "docs" / "url-history" / "url-redirect-map.json"
    )
    assert map_findings == []
    assert len(mapping["redirects"]) >= MAPPED_FLOOR


if __name__ == "__main__":
    # A plain assertion driver over the same tests, for running the predicates
    # directly (python -I -B on this file) where pytest is not wanted.
    import tempfile

    tests = sorted(
        (name, fn) for name, fn in globals().items() if name.startswith("test_")
    )
    failed = 0
    for name, fn in tests:
        with tempfile.TemporaryDirectory() as scratch:
            try:
                fn(Path(scratch))
            except AssertionError as error:
                failed += 1
                print(f"FAIL {name}: {error}")
            else:
                print(f"PASS {name}")
    print(f"{len(tests) - failed} of {len(tests)} passed, {failed} failed")
    sys.exit(1 if failed else 0)
