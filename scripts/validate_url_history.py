# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every URL the docs site ever served still lands on the right page.

docs/url-history/historical-urls.tsv is the ledger of every docs URL a release
tag renamed or deleted, and docs/url-history/url-redirect-map.json maps each URL
that stopped being served with no redirect to the page that owns its subject
today. The redirect mechanism materializes that map as docs/redirects.yml
entries, which docs/hooks/redirects.py turns into redirect pages (canonical
link, robots noindex, hash-preserving location.replace, meta-refresh fallback)
in every version the site builds, and scripts/docs_versions.py mirrors at the
site root for the default version. This script is the CI gate that holds the
three in agreement:

- every mapped target is a page of the site (in docs/content, and when
  --site-dir names a built site, a real non-redirect page of that build);
- every URL in the historical ledger is covered: still served, redirected by
  docs/redirects.yml, or deliberately tombstoned in the map;
- no redirect chains or loops: no redirect's target is itself redirected,
  in docs/redirects.yml, in the map, or between them;
- the map and docs/redirects.yml agree: every mapped dead URL has an entry
  whose old page serves exactly that URL and whose new page serves exactly the
  mapped target;
- no redirect shadows a live URL: an entry whose old URL another page still
  serves would overwrite that page's output;
- with --site-dir, every historical URL resolves inside the built tree: it is
  a page, or a redirect page whose refresh target reaches a real page within
  a bounded number of hops and without revisiting a URL.

Validating the tree this checkout builds, never the deployed gh-pages branch,
is what makes the check meaningful across releases: main is routinely ahead of
the deploy (a page can be in the nav before any deploy served it), and each
release tag's publish re-validates its own build, so a release cannot ship a
mapping that its own site contradicts. Only the standard library is used and
the checks are pure functions over paths, so the script runs as
``python -I -B scripts/validate_url_history.py`` anywhere, built site or not.

docs/redirects.yml is read with a parser for exactly the flat grammar the file
uses (one ``old: new`` pair per two-space-indented line under ``redirects:``);
anything else in the block is reported rather than guessed at. The full YAML
reading, anchor validation included, stays with scripts/docs_checks.py
check_nav in the lint job.

Known limits: the unversioned build has no version selector and no site-root
stub layer, so the root-level redirect-into-version hop that the deployed site
adds (dead URL at the root -> same path under the default version -> target) is
exercised by scripts/docs_versions.py check, not here; and the historical
ledger records whole pages, so anchor-level moves are out of scope.
"""

from __future__ import annotations

import argparse
import html
import json
import posixpath
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MAP_FILE = "docs/url-history/url-redirect-map.json"
HISTORY_FILE = "docs/url-history/historical-urls.tsv"
REDIRECTS_FILE = "docs/redirects.yml"
DOCS_DIR = "docs/content"

#: Hops a redirect page may take inside a built site before it must land on a
#: real page. The hook writes single-hop redirects, so anything deeper than the
#: one hop plus margin is a chain the source checks should already have caught.
MAX_HOPS = 5

#: The meta-refresh fallback docs/hooks/redirects.py writes; its URL is the
#: redirect's target relative to the redirect's own URL.
_REFRESH = re.compile(
    r'<meta http-equiv="refresh" content="0; url=([^"]+)"', re.IGNORECASE
)


def normalize_url(url: str) -> str:
    """A site-root-relative page URL, with leading and trailing slash."""
    url = url.strip()
    if not url.startswith("/"):
        url = "/" + url
    if not url.endswith("/"):
        url += "/"
    return url


def url_of_page(page: str) -> str:
    """The URL a docs page path is served at, under use_directory_urls."""
    path = page.partition("#")[0].removesuffix(".md")
    if posixpath.basename(path) in ("index", "README"):
        path = posixpath.dirname(path)
    return normalize_url(path) if path else "/"


def page_for_url(docs_dir: Path, url: str) -> Path | None:
    """The source page serving a URL, or None when nothing serves it."""
    rel = url.strip("/")
    if rel:
        candidates = (f"{rel}.md", f"{rel}/index.md", f"{rel}/README.md")
    else:
        candidates = ("index.md", "README.md")
    for candidate in candidates:
        path = docs_dir / candidate
        if path.is_file():
            return path
    return None


def load_history(path: Path) -> tuple[list[str], list[str]]:
    """The distinct historical old URLs, in ledger order, plus findings."""
    findings: list[str] = []
    urls: list[str] = []
    seen: set[str] = set()
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        fields = raw.split("\t")
        if fields[0] == "tag-range":
            continue
        if len(fields) < 3 or fields[1] not in ("R", "D") or not fields[2].strip():
            findings.append(
                f"{path.name}:{number}: not a 'tag-range<TAB>R|D<TAB>old-url"
                f"[<TAB>new-url]' row: {raw!r}"
            )
            continue
        url = normalize_url(fields[2])
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls, findings


def load_map(path: Path) -> tuple[dict, list[str]]:
    """The dead-URL map, plus findings about its own shape."""
    findings: list[str] = []
    document = json.loads(path.read_text(encoding="utf-8"))
    redirects = document.get("redirects")
    tombstones = document.get("tombstones")
    if not isinstance(redirects, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in redirects.items()
    ):
        return {}, [f"{path.name}: 'redirects' must map dead URLs to target URLs"]
    if not isinstance(tombstones, list) or not all(
        isinstance(t, str) for t in tombstones
    ):
        findings.append(f"{path.name}: 'tombstones' must be a list of URLs")
        tombstones = []
    for url in list(redirects) + list(tombstones):
        if normalize_url(url) != url:
            findings.append(
                f"{path.name}: {url} is not in the /path/ form every URL here uses"
            )
    for url in redirects:
        if url in tombstones:
            findings.append(f"{path.name}: {url} is both redirected and tombstoned")
    counts = document.get("counts") or {}
    for key, wanted in (("dead", len(redirects)), ("tombstones", len(tombstones))):
        if key in counts and counts[key] != wanted:
            findings.append(
                f"{path.name}: counts.{key} says {counts[key]}, "
                f"but the file holds {wanted}"
            )
    return {
        "redirects": {k: normalize_url(v) for k, v in redirects.items()},
        "tombstones": set(tombstones),
    }, findings


def load_redirects_yml(path: Path) -> tuple[dict[str, str], list[str]]:
    """docs/redirects.yml as old page -> new page, parsed by its flat grammar."""
    findings: list[str] = []
    entries: dict[str, str] = {}
    in_block = False
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line == "redirects:":
            in_block = True
            continue
        match = re.fullmatch(r"  ([^\s:]+): (\S+)", line)
        if not in_block or not match:
            findings.append(
                f"{path.name}:{number}: not the flat 'old.md: new.md' grammar this "
                f"validator reads (and check_nav validates in full): {line!r}"
            )
            continue
        old, new = match.group(1), match.group(2)
        if old in entries:
            findings.append(f"{path.name}:{number}: {old} is redirected twice")
        entries[old] = new
    return entries, findings


def check_map_targets(
    mapping: dict, docs_dir: Path, map_name: str = "url-redirect-map.json"
) -> list[str]:
    """(a) Every mapped target is a page of the docs tree."""
    findings: list[str] = []
    for old, target in mapping["redirects"].items():
        if page_for_url(docs_dir, target) is None:
            findings.append(
                f"{map_name}: {old} maps to {target}, which no page in "
                f"{docs_dir.name} serves"
            )
    return findings


def check_history_covered(
    history: list[str], mapping: dict, yml_urls: dict[str, str], docs_dir: Path
) -> list[str]:
    """(b) Every historical URL is served, redirected, or tombstoned."""
    findings: list[str] = []
    for url in history:
        if url in yml_urls or url in mapping["tombstones"]:
            continue
        if page_for_url(docs_dir, url) is not None:
            continue
        findings.append(
            f"historical URL {url} is dead and uncovered: add a docs/redirects.yml "
            "entry (and a url-redirect-map.json mapping), or tombstone it in the map"
        )
    return findings


def check_no_chains(merged: dict[str, str]) -> list[str]:
    """(c) No redirect's target is itself redirected; no loops."""
    findings: list[str] = []
    for source, target in sorted(merged.items()):
        if target not in merged:
            continue
        visited = [source]
        cursor: str | None = target
        while cursor in merged and cursor not in visited:
            visited.append(cursor)
            cursor = merged[cursor]
        if cursor in visited:
            findings.append(
                f"redirect loop: {' -> '.join(visited)} -> {cursor}; break the cycle"
            )
        else:
            findings.append(
                f"redirect chain: {source} -> {target}, and {target} is itself "
                "redirected; point every entry at its final page"
            )
    return findings


def check_map_materialized(mapping: dict, yml_urls: dict[str, str]) -> list[str]:
    """The map and docs/redirects.yml agree on every mapped dead URL."""
    findings: list[str] = []
    for old, target in mapping["redirects"].items():
        materialized = yml_urls.get(old)
        if materialized is None:
            findings.append(
                f"{old} is mapped to {target} but no docs/redirects.yml entry "
                "serves that URL, so no redirect page is built for it"
            )
        elif materialized != target:
            findings.append(
                f"{old}: url-redirect-map.json says {target}, docs/redirects.yml "
                f"says {materialized}; make them agree"
            )
    return findings


def check_no_shadowed_urls(yml_urls: dict[str, str], docs_dir: Path) -> list[str]:
    """No redirect is written at a URL a live page still serves."""
    findings: list[str] = []
    for url in yml_urls:
        page = page_for_url(docs_dir, url)
        if page is not None:
            findings.append(
                f"a docs/redirects.yml entry serves {url}, but so does "
                f"{page.name}; the redirect page would overwrite it"
            )
    return findings


def stub_target(page_text: str) -> str | None:
    """The refresh target of a redirect page, or None for a real page."""
    match = _REFRESH.search(page_text)
    return html.unescape(match.group(1)) if match else None


def resolve_in_site(site_dir: Path, url: str) -> tuple[str | None, str]:
    """Follow a URL through a built site tree to the page it lands on.

    Returns (final URL, "") when the URL resolves to a real page within
    MAX_HOPS, and (None, why) when it does not.
    """
    visited: list[str] = []
    cursor = url
    for _hop in range(MAX_HOPS + 1):
        if cursor in visited:
            return None, f"redirect loop in the built site: {' -> '.join(visited)}"
        visited.append(cursor)
        page = site_dir / cursor.strip("/") / "index.html"
        if not page.is_file():
            return None, f"{cursor} is not in the built site (no {page.name} there)"
        target = stub_target(page.read_text(encoding="utf-8"))
        if target is None:
            return cursor, ""
        if "://" in target:
            return None, f"{cursor} redirects off the site, to {target}"
        resolved = posixpath.normpath(posixpath.join(cursor, target.partition("#")[0]))
        cursor = normalize_url(resolved)
    return None, f"more than {MAX_HOPS} redirect hops: {' -> '.join(visited)} ..."


def check_built_site(site_dir: Path, history: list[str], mapping: dict) -> list[str]:
    """With a built site, every historical URL and mapping resolves inside it."""
    findings: list[str] = []
    if not (site_dir / "index.html").is_file():
        return [f"{site_dir} does not look like a built site: no index.html at root"]
    for old, target in mapping["redirects"].items():
        final, why = resolve_in_site(site_dir, old)
        if final is None:
            findings.append(f"mapped URL {old}: {why}")
        elif final != target:
            findings.append(
                f"mapped URL {old} lands on {final} in the built site, "
                f"but the map says {target}"
            )
        target_page = site_dir / target.strip("/") / "index.html"
        if not target_page.is_file():
            findings.append(f"mapped target {target} is not in the built site")
        elif stub_target(target_page.read_text(encoding="utf-8")) is not None:
            findings.append(
                f"mapped target {target} is itself a redirect page in the built site"
            )
    for url in history:
        if url in mapping["tombstones"]:
            continue
        final, why = resolve_in_site(site_dir, url)
        if final is None:
            findings.append(f"historical URL {url}: {why}")
    return findings


def run(root: Path, site_dir: Path | None = None) -> tuple[list[str], str]:
    """All checks over a repo checkout; returns findings and a summary line."""
    docs_dir = root / DOCS_DIR
    history, findings = load_history(root / HISTORY_FILE)
    mapping, map_findings = load_map(root / MAP_FILE)
    findings += map_findings
    entries, yml_findings = load_redirects_yml(root / REDIRECTS_FILE)
    findings += yml_findings
    if not mapping:
        return findings, "the map did not load; nothing else was checked"
    yml_urls = {url_of_page(old): url_of_page(new) for old, new in entries.items()}
    merged = dict(yml_urls)
    merged.update(mapping["redirects"])
    findings += check_map_targets(mapping, docs_dir)
    findings += check_history_covered(history, mapping, yml_urls, docs_dir)
    findings += check_no_chains(merged)
    findings += check_map_materialized(mapping, yml_urls)
    findings += check_no_shadowed_urls(yml_urls, docs_dir)
    if site_dir is not None:
        findings += check_built_site(site_dir, history, mapping)
    summary = (
        f"checked {len(history)} historical URLs, {len(mapping['redirects'])} mapped "
        f"dead URLs, {len(mapping['tombstones'])} tombstones and {len(entries)} "
        f"docs/redirects.yml entries"
        + (f" against the built site at {site_dir}" if site_dir is not None else "")
        + f": {len(findings)} finding(s)"
    )
    return findings, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.partition("\n")[0])
    parser.add_argument(
        "--root", type=Path, default=REPO_ROOT, help="the repository checkout"
    )
    parser.add_argument(
        "--site-dir",
        type=Path,
        default=None,
        help="a built site tree (mkdocs.yml's site_dir after `mkdocs build`); "
        "without it only the sources are checked",
    )
    args = parser.parse_args(argv)
    findings, summary = run(args.root, args.site_dir)
    for finding in findings:
        print(f"error: {finding}")
    print(summary)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
