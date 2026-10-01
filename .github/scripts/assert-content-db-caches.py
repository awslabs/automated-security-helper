#!/usr/bin/env python3
"""Fail when a workflow caches a scanner content database outside its declared age bound.

WHY THIS EXISTS

A vulnerability database in the Actions cache keeps being restored while it ages. Saving on
main only bounds the cache's size, not the age of what it hands out. So every cached content
database has to be keyed on a time bucket derived from the bound the scanner itself enforces,
and that bound is declared once, in automated_security_helper/utils/content_databases.py.

This gate is what keeps the YAML honest about it. For every `actions/cache`,
`actions/cache/restore` and `actions/cache/save` step under .github/, it checks:

  1. A step whose path is a registered database's cache path:
     - the database must be declared `cacheable_in_ci`, which only one with CI age guards
       is; every database declares a max age, but that bounds what a scan accepts, not what
       a cache hands out;
     - the step must be a restore or a save, not the combined `actions/cache`, whose post-job
       save fires on pull requests too;
     - there must be no `restore-keys`: a prefix fallback restores an older bucket, which is
       the unbounded case the bucket exists to prevent;
     - the key must reference an output of a step in the same job whose `run` calls
       `content_databases cache-key <that database>`, so the bucket is computed from the
       registry and not typed into YAML;
     - a save must be gated on a push to the default branch, spelled as either
       `refs/heads/main` or the `default_branch` expression, with no `||`.
  2. A step whose path LOOKS like a content database (it names a scanner that has one) but is
     not a registered path fails, unless it is listed in NOT_CONTENT_DATABASES with a reason.
     That is the "caches a content database that is not in the registry" case.

It runs a self-test first, the same way assert-publish-surfaces.py does: synthetic fixtures for
each violation above must each come back red, and a compliant fixture must come back green, so
a detector that has stopped matching cannot report a clean tree.

KNOWN LIMITATIONS

  * Only `uses: actions/cache*` steps are read. A tool that caches its own database through a
    built-in cache input (none does today) would need adding here.
  * Paths are compared as source text after trimming, so `~/.cache/grype/db/` with a trailing
    slash is a different path. The cheaper direction to be wrong in: it fails as unregistered.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_DIR = REPO_ROOT / ".github"
REGISTRY_PATH = (
    REPO_ROOT / "automated_security_helper" / "utils" / "content_databases.py"
)

# Words that mark a cache path as belonging to a scanner that has a content database. A
# path naming one of these must either be a registered database path or be listed below.
CONTENT_DB_HINTS = ("grype", "trivy", "semgrep", "opengrep", "vulnerability", "vuln-db")

# Cache paths that match a hint but are not content databases, and why.
NOT_CONTENT_DATABASES = {
    "~/.opengrep/cli/latest": (
        "the OpenGrep release binary, not its rules; keyed weekly so a cache cannot pin a "
        "scanner to one build"
    ),
}

CACHE_ACTIONS = ("actions/cache", "actions/cache/restore", "actions/cache/save")
MAIN_PUSH_EVENT = "github.event_name == 'push'"
MAIN_REF_FORMS = (
    "github.ref == 'refs/heads/main'",
    "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)",
)


def _load_registry():
    spec = importlib.util.spec_from_file_location("content_databases", REGISTRY_PATH)
    module = importlib.util.module_from_spec(spec)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load the registry from {REGISTRY_PATH}")
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class Violation:
    file: str
    step: str
    message: str


def _flatten(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "|".join(_flatten(v) for v in value)
    return "|".join(line.strip() for line in str(value).splitlines() if line.strip())


def _steps_lists(document: object):
    """Every list of steps: jobs.<id>.steps in a workflow, runs.steps in a composite action."""
    if not isinstance(document, dict):
        return
    for job in (document.get("jobs") or {}).values():
        if isinstance(job, dict) and isinstance(job.get("steps"), list):
            yield job["steps"]
    runs = document.get("runs")
    if isinstance(runs, dict) and isinstance(runs.get("steps"), list):
        yield runs["steps"]


def check_text(rel_path: str, text: str, registry) -> list[Violation]:
    violations: list[Violation] = []
    by_path = {entry.cache_path: entry for entry in registry.CONTENT_DATABASES}
    for document in yaml.safe_load_all(text):
        for steps in _steps_lists(document):
            ids = {s.get("id"): s for s in steps if isinstance(s, dict) and s.get("id")}
            for step in steps:
                if not isinstance(step, dict) or not isinstance(step.get("uses"), str):
                    continue
                action = step["uses"].split("@", 1)[0].strip()
                if action not in CACHE_ACTIONS:
                    continue
                name = str(step.get("name") or f"(unnamed {action})")
                inputs = step.get("with") if isinstance(step.get("with"), dict) else {}
                paths = [p for p in _flatten(inputs.get("path")).split("|") if p]

                def fail(message: str) -> None:
                    violations.append(Violation(rel_path, name, message))

                registered = [by_path[p] for p in paths if p in by_path]
                if not registered:
                    for path in paths:
                        lowered = path.lower()
                        if path in NOT_CONTENT_DATABASES:
                            continue
                        if any(hint in lowered for hint in CONTENT_DB_HINTS):
                            fail(
                                f"caches {path!r}, which looks like a scanner content "
                                "database but is not declared in "
                                "automated_security_helper/utils/content_databases.py. "
                                "Declare it with its max age, or list the path in "
                                "NOT_CONTENT_DATABASES with the reason it is not one."
                            )
                    continue

                for entry in registered:
                    if not entry.cacheable:
                        fail(
                            f"caches {entry.name}, which is not declared cacheable in CI "
                            "(cacheable_in_ci): no CI guard holds a restored copy to its "
                            "max age, so it must not be cached"
                        )
                        continue
                    if action == "actions/cache":
                        fail(
                            f"caches {entry.name} with actions/cache, whose post-job save "
                            "runs on pull requests too. Use actions/cache/restore and a "
                            "separate actions/cache/save gated on a push to main."
                        )
                    if "restore-keys" in inputs:
                        fail(
                            f"restores {entry.name} with restore-keys; a prefix fallback "
                            "hands out an older bucket, which defeats the age bound"
                        )
                    key = _flatten(inputs.get("key"))
                    refs = re.findall(
                        r"steps\.([A-Za-z0-9_-]+)\.outputs\.[A-Za-z0-9_-]+", key
                    )
                    marker = f"content_databases cache-key {entry.name}"
                    derived = any(
                        marker in " ".join(str(ids.get(ref, {}).get("run", "")).split())
                        for ref in refs
                    )
                    if not derived:
                        fail(
                            f"keys {entry.name} as {key!r}, which does not reference an "
                            f"output of a step running `{marker}` in this job. The time "
                            "bucket has to come from the registry, not from YAML."
                        )
                    if action == "actions/cache/save":
                        condition = " ".join(str(step.get("if", "")).split())
                        if (
                            MAIN_PUSH_EVENT not in condition
                            or not any(form in condition for form in MAIN_REF_FORMS)
                            or "||" in condition
                        ):
                            fail(
                                f"saves {entry.name} under if: {condition!r}; a save must "
                                "require a push to the default branch, with no `||`"
                            )
    return violations


def check_tree(registry) -> tuple[int, list[Violation]]:
    violations: list[Violation] = []
    count = 0
    for path in sorted(GITHUB_DIR.rglob("*")):
        if not path.is_file() or path.suffix not in {".yml", ".yaml"}:
            continue
        text = path.read_text(encoding="utf-8")
        count += text.count("actions/cache")
        violations.extend(
            check_text(path.relative_to(REPO_ROOT).as_posix(), text, registry)
        )
    return count, violations


# ------------------------------------------------------------------------------ self-test

_KEY_STEP = """
      - id: cachekeys
        run: |
          echo "grype-db=$(python -m automated_security_helper.utils.content_databases cache-key grype-db)" >> "$GITHUB_OUTPUT"
"""

_COMPLIANT = (
    """
name: fixture
on: [pull_request, push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
"""
    + _KEY_STEP
    + """
      - id: restore
        uses: actions/cache/restore@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: ~/.cache/grype/db
          key: grype-db-${{ runner.os }}-${{ steps.cachekeys.outputs.grype-db }}
      - uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        with:
          path: ~/.opengrep/cli/latest
          key: opengrep-${{ runner.os }}-week
      - uses: actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0
        if: github.event_name == 'push' && github.ref == 'refs/heads/main'
        with:
          path: ~/.cache/grype/db
          key: grype-db-${{ runner.os }}-${{ steps.cachekeys.outputs.grype-db }}
"""
)


def _variant(old: str, new: str) -> str:
    if old not in _COMPLIANT:
        raise SystemExit(
            f"self-test fixture drifted: {old!r} is not in the compliant fixture"
        )
    return _COMPLIANT.replace(old, new, 1)


def self_test(registry) -> int:
    cases = [
        ("compliant fixture", _COMPLIANT, 0),
        (
            "grype keyed by date, not the registry",
            _variant(
                "key: grype-db-${{ runner.os }}-${{ steps.cachekeys.outputs.grype-db }}\n      - uses: actions/cache@",
                "key: grype-db-${{ runner.os }}-2026-09-30\n      - uses: actions/cache@",
            ),
            1,
        ),
        (
            "grype restored with a restore-keys fallback",
            _variant(
                "key: grype-db-${{ runner.os }}-${{ steps.cachekeys.outputs.grype-db }}\n      - uses: actions/cache@",
                "key: grype-db-${{ runner.os }}-${{ steps.cachekeys.outputs.grype-db }}\n"
                "          restore-keys: grype-db-\n      - uses: actions/cache@",
            ),
            1,
        ),
        (
            "grype cached with the combined actions/cache",
            _variant("actions/cache/restore@", "actions/cache@"),
            1,
        ),
        (
            "grype saved on every event",
            _variant(
                "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
                "if: always()",
            ),
            1,
        ),
        (
            "grype saved on main OR a pull request",
            _variant(
                "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
                "if: github.event_name == 'push' && github.ref == 'refs/heads/main' || true",
            ),
            1,
        ),
        (
            "an unregistered trivy database",
            _variant("path: ~/.opengrep/cli/latest", "path: ~/.cache/trivy"),
            1,
        ),
        (
            "a registered database not declared cacheable in CI",
            _variant("path: ~/.opengrep/cli/latest", "path: /deps/.semgrep"),
            1,
        ),
        (
            "a key step that does not call the registry",
            _variant(
                "python -m automated_security_helper.utils.content_databases cache-key grype-db",
                "date -u +%Y-%m-%d",
            ),
            2,
        ),
    ]
    failures = 0
    print("Self-test: does this gate still detect and still fail?\n")
    for name, text, want in cases:
        got = len(check_text("fixture.yml", text, registry))
        ok = (got == 0) if want == 0 else (got >= want)
        print(
            f"  {'ok  ' if ok else 'FAIL'} {name}: {got} violation(s), want {'0' if want == 0 else f'>={want}'}"
        )
        failures += 0 if ok else 1
    print()
    if failures:
        print(
            f"::error::assert-content-db-caches.py self-test failed {failures} case(s)."
        )
        return 1
    print("Self-test passed: every violation still comes back red.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    registry = _load_registry()
    if args.self_test:
        return self_test(registry)

    count, violations = check_tree(registry)
    if count == 0:
        print(
            "::error::no actions/cache step was found under .github/; the scan found nothing"
        )
        return 1
    for v in violations:
        print(f"::error file={v.file}::{v.file} step '{v.step}' {v.message}")
    if violations:
        print(f"FAILED: {len(violations)} content-database cache violation(s).")
        return 1
    registered = ", ".join(
        f"{e.name} (max age {registry.go_duration(e.max_age)}, "
        f"{'cacheable in CI' if e.cacheable else 'not cacheable in CI'})"
        for e in registry.CONTENT_DATABASES
    )
    print(
        f"OK: every content-database cache under .github/ derives from the registry: {registered}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
