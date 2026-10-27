# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How an ignore path and a suppression path read a directory, ``./`` and ``\\``.

An ignore path ending in ``/`` (or ``\\``) names a directory and covers the files
under it: ``vendor/``, ``vendor/**``, ``**/vendor/**`` and ``**/vendor/`` all name
the files under ``vendor``, the way the tools that receive ignore paths read a
trailing slash, and so does ASH's own SARIF step: a finding under ``vendor/`` that a
scanner reports anyway (snyk-code receives no ignore paths) is not left actionable.
Every place ASH reads an ignore path goes through ``ignore_path_matches`` or
``ignore_path_pattern``.

A suppression's ``path`` keeps its literal meaning, so ``vendor/`` matches no file;
``vendor/**/*`` is how a suppression names every file inside ``vendor``
(``directory_spelling``).

A backslash is a separator in the pattern only, and the matcher drops a leading
``./`` from neither side: a path is compared as it is given. ``./``, ``.\\``, ``.``
and ``""`` match no path in any reader (``path_matching.names_no_path``). The SARIF
step reads a finding's location as the path it names before it compares, so
``./vendor/v.py``, ``vendor/./v.py`` and ``vendor//v.py`` are ``vendor/v.py``; a
``..`` component is kept as it is written.

A bare ``vendor``, with no slash and no glob, names the path ``vendor`` itself, and
``ash config lint`` points out that it matches nothing inside the directory.
"""

import sys
from pathlib import PurePosixPath

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.config_linter import ConfigLinter
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.path_matching import (
    _path_pattern_matches,
    directory_spelling,
)
from automated_security_helper.utils import sarif_utils
from automated_security_helper.utils.sarif_utils import (
    _normalize_sarif_uri,
    apply_suppressions_to_sarif,
)
from automated_security_helper.utils.suppression_matcher import (
    file_path_matches,
    ignore_path_matches,
)

AshConfig.model_rebuild()

#: What the warning about a path that names a directory says.
DIRECTORY_ADVICE = "points to a directory"

#: Ignore paths that name the files under vendor.
DIRECTORY_FORMS = [
    "vendor/",
    "vendor/**",
    "**/vendor/**",
    "**/vendor/",
    "vendor\\",
]
FILES_UNDER_VENDOR = ["vendor/v.py", "vendor/lib/deep/v.py"]

#: The same directory forms spelled in another case. Matching is case-sensitive:
#: on a case-sensitive filesystem VENDOR/ is another directory.
OTHER_CASE_FORMS = ["VENDOR/", "Vendor/**", "**/VENDOR/**", "**/Vendor/"]

#: Suppression paths that name the files under vendor, and ones that, read
#: literally, name none of them.
SUPPRESSION_DIRECTORY_FORMS = ["vendor/**", "**/vendor/**", "vendor/**/*"]
LITERAL_SUPPRESSION_FORMS = ["vendor/", "**/vendor/", "VENDOR/", "vendor\\"]


@pytest.mark.parametrize("pattern", DIRECTORY_FORMS)
@pytest.mark.parametrize("path", FILES_UNDER_VENDOR)
def test_every_directory_form_matches_the_files_under_it(pattern, path):
    assert ignore_path_matches(path, pattern), (
        f"{pattern!r} should cover {path!r}: it names the vendor directory"
    )


@pytest.mark.parametrize("pattern", DIRECTORY_FORMS)
@pytest.mark.parametrize(
    "path", ["vendorized/v.py", "src/vendor.py", "src/vendor2/v.py"]
)
def test_a_directory_form_does_not_reach_outside_it(pattern, path):
    assert not ignore_path_matches(path, pattern), (pattern, path)


@pytest.mark.parametrize("pattern", OTHER_CASE_FORMS)
@pytest.mark.parametrize("path", FILES_UNDER_VENDOR)
def test_a_directory_form_in_another_case_names_another_directory(pattern, path):
    """``VENDOR/`` covers the files under ``VENDOR``, not those under ``vendor``,
    as an ignore path and as a suppression path alike."""
    assert not ignore_path_matches(path, pattern), (pattern, path)
    assert not file_path_matches(path, pattern), (pattern, path)
    spelled = pattern.strip("*/").join(path.split("vendor", 1))
    assert ignore_path_matches(spelled, pattern), (pattern, spelled)


@pytest.mark.parametrize("path", FILES_UNDER_VENDOR)
def test_a_suppression_path_reads_a_trailing_slash_literally(path):
    for pattern in SUPPRESSION_DIRECTORY_FORMS:
        assert file_path_matches(path, pattern), (pattern, path)
    for pattern in LITERAL_SUPPRESSION_FORMS:
        assert not file_path_matches(path, pattern), (pattern, path)


@pytest.mark.parametrize(
    "pattern,path,expected",
    [
        # A bare name is the path itself.
        ("vendor", "vendor/v.py", False),
        ("vendor", "vendor", True),
        # The long form keeps matching the path itself; the
        # suppressions guide says so.
        ("vendor/**", "vendor", True),
        # ./ is dropped from neither side: a path is compared as it is given.
        ("./src/app.py", "src/app.py", False),
        ("src/app.py", "./src/app.py", False),
        ("./src/*.py", "src/app.py", False),
        ("./src/app.py", "./src/app.py", True),
        # A backslash is a separator in the pattern, part of a name in the path.
        ("src\\app.py", "src/app.py", True),
        ("src/app.py", "src\\app.py", False),
        ("src/*.py", ".\\src\\app.py", False),
        # A slash alone, or a pattern naming the scan root, names nothing.
        ("/", "vendor/v.py", False),
        ("./", "vendor/v.py", False),
        ("./", "./vendor/v.py", False),
        (".\\", "./vendor/v.py", False),
        (".", ".", False),
        ("", "", False),
        ("", "vendor/v.py", False),
    ],
)
def test_other_forms(pattern, path, expected):
    assert file_path_matches(path, pattern) is expected
    assert ignore_path_matches(path, pattern) is expected


@pytest.mark.parametrize(
    "pattern,path",
    [
        ("**/.*/", ".env"),
        ("**/.*/", "app/.env"),
        ("**/.*/", "app/config/.npmrc"),
        ("build*/", "buildspec.yml"),
        ("*/", "Makefile"),
        ("vendor/", "vendor"),
    ],
)
def test_a_trailing_slash_does_not_cover_a_file_of_that_name(pattern, path):
    """``X/`` names the files under a directory X, never a file named like X.

    Read as ``X/**``, whose ``**`` also matches no component at all, ``**/.*/``
    would cover every dotfile, and the detect-secrets pre-filter reads ignore
    paths this way; ``X/`` covers only files under a directory, so ``.env`` stays
    in the secrets scan.
    """
    assert ignore_path_matches(path, pattern) is False


@pytest.mark.parametrize(
    "pattern,path",
    [
        ("**/.*/", ".git/config"),
        ("**/.*/", "app/.cache/deep/x.py"),
        ("build*/", "build/out.py"),
        ("*/", "src/a.py"),
    ],
)
def test_a_trailing_slash_covers_the_files_under_the_directory(pattern, path):
    assert ignore_path_matches(path, pattern) is True


#: The paths of the reader matrix below.
_MATRIX_PATHS = [
    "vendor/a.py",
    "vendor/sub/b.py",
    "vendorx/c.py",
    "a/vendor/d.py",
    "vendor",
    "./vendor/a.py",
    "VENDOR/a.py",
    "vendor\\a.py",
    ".git/config",
    "x.py",
    "src/x.py",
    "",
]

#: For each pattern, the paths it matches as an ignore path, and as a suppression
#: path where that differs (None: the same). Only a pattern ending in a separator
#: reads differently: as an ignore path it names the directory's files, as a
#: suppression path it is literal.
_MATCHED_PATHS = {
    "vendor/": (("vendor/a.py", "vendor/sub/b.py"), ()),
    "vendor": (("vendor",), None),
    "vendor/*": (("vendor/a.py", "vendor/sub/b.py"), None),
    "vendor/**": (("vendor/a.py", "vendor/sub/b.py", "vendor"), None),
    "a/vendor/": (("a/vendor/d.py",), ()),
    "/vendor/": ((), None),
    "vendor//": (("vendor/a.py", "vendor/sub/b.py"), ()),
    "vendor\\": (("vendor/a.py", "vendor/sub/b.py"), ()),
    "./vendor/": (("./vendor/a.py",), ()),
    "**/vendor/": (
        ("vendor/a.py", "vendor/sub/b.py", "a/vendor/d.py", "./vendor/a.py"),
        (),
    ),
    ".git/": ((".git/config",), ()),
    "ven*/": (("vendor/a.py", "vendor/sub/b.py", "vendorx/c.py"), ()),
    "v[e]ndor/": (("vendor/a.py", "vendor/sub/b.py"), ()),
    # Case is compared as written: VENDOR/ is another directory.
    "VENDOR/": (("VENDOR/a.py",), ()),
    "./": ((), None),
    ".\\": ((), None),
    "/": ((), None),
    "//": ((), None),
    "": ((), None),
}


@pytest.mark.parametrize("pattern", list(_MATCHED_PATHS))
@pytest.mark.parametrize("path", _MATRIX_PATHS)
def test_every_reader_matches_the_paths_listed_for_the_pattern(pattern, path):
    """The two ignore-path readers and the two suppression readers, cell by cell.

    Within each pair the readers agree, and the pairs differ only on a pattern
    ending in a separator. No ``./`` is dropped and no backslash in a path is read
    as a separator; ``./``, ``.\\``, ``/``, ``//`` and ``""`` match nothing.
    """
    as_ignore, as_suppression = _MATCHED_PATHS[pattern]
    expected_ignore = path in as_ignore
    expected_suppression = path in (
        as_ignore if as_suppression is None else as_suppression
    )
    answers = {
        "ignore_path_matches": ignore_path_matches(path, pattern),
        "IgnorePathWithReason.matches_path": IgnorePathWithReason(
            path=pattern, reason="r"
        ).matches_path(path),
        "file_path_matches": file_path_matches(path, pattern),
        "_path_pattern_matches": _path_pattern_matches(path, pattern),
    }
    assert answers == {
        "ignore_path_matches": expected_ignore,
        "IgnorePathWithReason.matches_path": expected_ignore,
        "file_path_matches": expected_suppression,
        "_path_pattern_matches": expected_suppression,
    }, (pattern, path)


def test_only_a_trailing_separator_reads_differently():
    differs = [
        p
        for p, (_, as_suppression) in _MATCHED_PATHS.items()
        if as_suppression is not None
    ]
    assert differs and all(p.endswith(("/", "\\")) for p in differs), differs


def _sarif(uri: str) -> SarifReport:
    return SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="snyk-code", version="1")),
                results=[
                    Result(
                        ruleId="python/Sqli",
                        message=Message(text="finding"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(uri=uri),
                                    region=Region(startLine=1, endLine=1),
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )


def _context(tmp_path, config):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return PluginContext(source_dir=source, output_dir=output, config=config)


@pytest.mark.parametrize("pattern", DIRECTORY_FORMS)
def test_sarif_step_drops_a_finding_under_each_form(tmp_path, pattern):
    config = AshConfig(
        project_name="t",
        global_settings={
            "ignore_paths": [IgnorePathWithReason(path=pattern, reason="vendored")]
        },
    )
    result = apply_suppressions_to_sarif(
        _sarif("vendor/v.py"), _context(tmp_path, config)
    )
    assert result.runs[0].results == [], (
        f"ignore path {pattern!r} left the vendor/v.py finding actionable"
    )


def _ignoring(tmp_path, pattern):
    """A context whose config has the one ignore path *pattern*."""
    config = AshConfig(
        project_name="t",
        global_settings={
            "ignore_paths": [IgnorePathWithReason(path=pattern, reason="vendored")]
        },
    )
    return _context(tmp_path, config)


def test_sarif_step_reads_a_dot_slash_uri_as_the_path_it_names(tmp_path):
    """A finding a scanner reports at ``./vendor/v.py`` is in ``vendor/v.py``, so
    ``vendor/**`` drops it. The matcher still drops no ``./``: the SARIF step reads
    the location's ``.`` components before it compares."""
    result = apply_suppressions_to_sarif(
        _sarif("./vendor/v.py"), _ignoring(tmp_path, "vendor/**")
    )
    assert result.runs[0].results == []


@pytest.mark.parametrize(
    "uri",
    [
        "vendor/./v.py",
        ".//vendor/v.py",
        "vendor//v.py",
        "<source>/./vendor/v.py",
        "<source>//vendor/v.py",
    ],
)
def test_sarif_step_reads_dot_and_empty_components_as_the_path_they_name(tmp_path, uri):
    """``vendor/v.py`` names one file, so it covers a location only when the
    location is read as that file's path: a ``.`` or empty component names the
    directory it is in, in a relative URI and in one under the source directory."""
    context = _ignoring(tmp_path, "vendor/v.py")
    uri = uri.replace("<source>", context.source_dir.resolve().as_posix())
    result = apply_suppressions_to_sarif(_sarif(uri), context)
    assert result.runs[0].results == [], uri


@pytest.mark.parametrize("uri", ["../v.py", "vendor/../v.py"])
def test_sarif_step_keeps_a_dot_dot_component(tmp_path, uri):
    """``..`` is kept as it is written. ``../v.py`` is outside the scanned
    directory, so the ignore path ``v.py``, the file at its top, does not cover it.
    ``vendor/../v.py`` is kept too: when ``vendor`` is a symlink, the file it names
    is not that one."""
    result = apply_suppressions_to_sarif(_sarif(uri), _ignoring(tmp_path, "v.py"))
    assert len(result.runs[0].results) == 1, uri
    assert not result.runs[0].results[0].suppressions


@pytest.mark.skipif(
    sys.platform == "win32", reason="a backslash is a separator in a Windows root"
)
def test_sarif_step_keeps_a_backslash_in_a_posix_file_name(tmp_path):
    """Under a POSIX source directory ``a\\b.py`` is one file name, so ``**/b.py``
    (a ``b.py`` in some directory) does not cover it; reading the backslash as a
    separator would."""
    result = apply_suppressions_to_sarif(
        _sarif("a\\b.py"), _ignoring(tmp_path, "**/b.py")
    )
    assert len(result.runs[0].results) == 1
    assert not result.runs[0].results[0].suppressions


@pytest.mark.parametrize(
    "rule_id, end_line, finding_id",
    [
        ("python/Sqli", 1, "6880f913-d64e-405d-93b2-c353b4757074"),
        ("R1", None, "63e19c1a-da85-4b53-8465-5106e51f2428"),
    ],
)
def test_sarif_step_gives_a_dot_slash_location_the_file_path_and_id_of_its_file(
    tmp_path, monkeypatch, rule_id, end_line, finding_id
):
    """``./vendor/v.py`` is matched, and identified, as ``vendor/v.py``: the
    finding the suppression step builds has that file_path and that id."""
    seen = []

    def record(finding, suppressions, symbol_resolver=None):
        seen.append((finding.file_path, finding.id))
        return False, None

    monkeypatch.setattr(sarif_utils, "should_suppress_finding", record)
    suppression = AshSuppression(rule_id="other/Rule", path="x.py", reason="r")
    config = AshConfig(
        project_name="t", global_settings={"suppressions": [suppression]}
    )
    report = _sarif("./vendor/v.py")
    (result,) = report.runs[0].results
    result.ruleId = rule_id
    result.locations[0].physicalLocation.root.region = Region(
        startLine=1, endLine=end_line
    )
    apply_suppressions_to_sarif(report, _context(tmp_path, config))
    assert seen == [("vendor/v.py", finding_id)]
    assert finding_id == sarif_utils.get_finding_id(rule_id, "vendor/v.py", 1, end_line)


@pytest.mark.parametrize(
    "uri", ["file://<source>/vendor/v.py", "file://<source>/./vendor/v.py"]
)
def test_sarif_step_reads_a_file_uri_as_the_path_it_names(tmp_path, uri):
    """``file://`` goes first, and the path left is read as any location is, so
    ``vendor/v.py`` covers the file with and without a ``.`` component."""
    context = _ignoring(tmp_path, "vendor/v.py")
    uri = uri.replace("<source>", context.source_dir.resolve().as_posix())
    result = apply_suppressions_to_sarif(_sarif(uri), context)
    assert result.runs[0].results == [], uri


@pytest.mark.parametrize(
    "uri", ["file:///C:/ws/src/vendor/v.py", "file:///C:/ws/src/./vendor/v.py"]
)
def test_a_windows_file_uri_is_read_from_its_drive(uri):
    """``file:///C:/ws/...`` names ``C:/ws/...``: the slash before the drive goes
    with the scheme, and the Windows source directory's prefix is stripped."""
    prefix = "C:/ws/src/"
    assert (
        _normalize_sarif_uri(uri, prefix, "/" + prefix, prefix[2:], None)
        == "vendor/v.py"
    )


#: Locations with a scheme other than ``file`` and an authority.
OTHER_SCHEMES = [
    "https://h/p",
    "https://h/vendor/v.py",
    "vscode://x/./y",
    "HTTPS://h//p",
]


@pytest.mark.parametrize("uri", OTHER_SCHEMES)
def test_a_location_with_another_scheme_is_kept_as_written(uri):
    prefix = "/ws/src/"
    assert (
        _normalize_sarif_uri(uri, prefix, "/" + prefix, None, PurePosixPath("src"))
        == uri
    )


def _outcome(tmp_path, uri, kind, pattern):
    """What the SARIF step does with a finding at *uri* under one pattern."""
    if kind == "ignore":
        context = _ignoring(tmp_path, pattern)
    else:
        suppression = AshSuppression(rule_id="python/Sqli", path=pattern, reason="r")
        context = _context(
            tmp_path,
            AshConfig(
                project_name="t", global_settings={"suppressions": [suppression]}
            ),
        )
    results = apply_suppressions_to_sarif(_sarif(uri), context).runs[0].results
    if not results:
        return "dropped"
    return "suppressed" if results[0].suppressions else "kept"


@pytest.mark.parametrize("uri", OTHER_SCHEMES)
@pytest.mark.parametrize("kind", ["ignore", "suppress"])
@pytest.mark.parametrize("pattern", ["vendor/**", "vendor/v.py"])
def test_a_pattern_for_a_file_in_the_tree_does_not_cover_another_scheme(
    tmp_path, uri, kind, pattern
):
    """``https://h/vendor/v.py`` is not the file ``vendor/v.py`` in the tree."""
    assert _outcome(tmp_path, uri, kind, pattern) == "kept", (uri, kind, pattern)


@pytest.mark.parametrize("uri", OTHER_SCHEMES)
@pytest.mark.parametrize(
    "kind, expected", [("ignore", "dropped"), ("suppress", "suppressed")]
)
@pytest.mark.parametrize("pattern", ["**", "**/*", "<the uri>"])
def test_a_pattern_for_every_path_covers_another_scheme(
    tmp_path, uri, kind, expected, pattern
):
    """``**`` covers every finding, one located at a URL included, and so does the
    URL's own text."""
    pattern = uri if pattern == "<the uri>" else pattern
    assert _outcome(tmp_path, uri, kind, pattern) == expected, (uri, kind, pattern)


@pytest.mark.parametrize(
    "uri, expected",
    [
        ("", ""),
        # Only a literal "file://" is read as a path.
        ("FILE:///src/x.py", "FILE:///src/x.py"),
        ("file:/src/x.py", "file:/src/x.py"),
        # A scheme with no authority is folded as a path is.
        ("vscode:x/./y", "vscode:x/y"),
        ("ab:c/./x.py", "ab:c/x.py"),
        ("./ab:c/x.py", "ab:c/x.py"),
    ],
)
def test_a_location_is_spelled_as_the_matchers_read_it(uri, expected):
    prefix = "/ws/src/"
    assert _normalize_sarif_uri(uri, prefix, "/" + prefix, None, None) == expected


def test_a_dot_slash_path_with_a_colon_is_covered_like_any_path(tmp_path):
    """``./ab:c/x.py`` is a path in the tree, so ``ab:c/**`` covers it."""
    assert _outcome(tmp_path, "./ab:c/x.py", "ignore", "ab:c/**") == "dropped"


def test_the_source_directory_reads_the_same_with_a_trailing_slash(tmp_path):
    root = (tmp_path / "src").resolve()
    prefix = root.as_posix() + "/"
    rest = (prefix, "/" + prefix, None, PurePosixPath(root.name))
    assert _normalize_sarif_uri(prefix, *rest) == _normalize_sarif_uri(
        prefix.rstrip("/"), *rest
    )


@pytest.mark.parametrize(
    "path, suppressed", [("vendor/", False), ("vendor/**/*", True)]
)
def test_a_suppression_path_keeps_a_trailing_slash_literal(tmp_path, path, suppressed):
    """``vendor/`` as a suppression path covers no file; ``vendor/**/*`` covers the
    files inside the directory."""
    suppression = AshSuppression(rule_id="python/Sqli", path=path, reason="r")
    config = AshConfig(
        project_name="t", global_settings={"suppressions": [suppression]}
    )
    result = apply_suppressions_to_sarif(
        _sarif("vendor/lib/v.py"), _context(tmp_path, config)
    )
    (finding,) = result.runs[0].results
    assert bool(finding.suppressions) is suppressed, (path, finding.suppressions)


class TestConfigChecksAgree:
    """lint and validate stop calling a trailing-slash pattern ineffective."""

    @staticmethod
    def _write(tmp_path, pattern):
        (tmp_path / "vendor").mkdir()
        config = tmp_path / ".ash.yaml"
        config.write_text(
            "project_name: t\n"
            "global_settings:\n"
            "  ignore_paths:\n"
            f"    - path: '{pattern}'\n"
            "      reason: vendored\n",
            encoding="utf-8",
        )
        return config

    @pytest.mark.parametrize("pattern", ["vendor/", "./vendor/"])
    def test_lint_accepts_a_trailing_slash(self, tmp_path, pattern):
        config = self._write(tmp_path, pattern)
        issues = ConfigLinter.lint(config, source_dir=tmp_path).issues
        assert not [i for i in issues if DIRECTORY_ADVICE in i.message], issues

    @pytest.mark.parametrize("pattern", ["vendor/", "./vendor/"])
    def test_validate_accepts_a_trailing_slash(self, tmp_path, pattern):
        config = self._write(tmp_path, pattern)
        _, errors = ConfigValidator.validate_config_file(config, source_dir=tmp_path)
        assert not [e for e in errors if DIRECTORY_ADVICE in e], errors

    def test_a_bare_directory_name_is_flagged(self, tmp_path):
        config = self._write(tmp_path, "vendor")
        issues = ConfigLinter.lint(config, source_dir=tmp_path).issues
        assert [i for i in issues if DIRECTORY_ADVICE in i.message], issues


class TestDirectoryAdvice:
    """One spelling of "every file inside the directory", the one the scan reads.

    For an ignore path ``<dir>/``; for a suppression path ``<dir>/**/*``, because
    ``<dir>/**`` also matches a path named exactly ``<dir>``. lint, validate and
    the absolute-path warning all spell it with path_matching.directory_spelling.
    """

    @pytest.mark.parametrize(
        "directory, ignore_path, spelling",
        [
            ("vendor", True, "vendor/"),
            ("vendor/", True, "vendor/"),
            ("docs", False, "docs/**/*"),
            ("docs\\", False, "docs/**/*"),
        ],
    )
    def test_the_spelling(self, directory, ignore_path, spelling):
        assert directory_spelling(directory, ignore_path=ignore_path) == spelling

    @staticmethod
    def _config(tmp_path, kind):
        (tmp_path / "docs").mkdir()
        entry = (
            "  ignore_paths:\n    - path: 'docs'\n      reason: r\n"
            if kind == "ignore"
            else "  suppressions:\n    - rule_id: B101\n      path: 'docs'\n"
            "      reason: r\n"
        )
        config = tmp_path / ".ash.yaml"
        config.write_text(
            f"project_name: t\nglobal_settings:\n{entry}", encoding="utf-8"
        )
        return config

    @pytest.mark.parametrize(
        "kind, advice",
        [
            (
                "ignore",
                (
                    "Path 'docs' points to a directory but matches no file in it. "
                    "Use 'docs/' to ignore every file inside the directory."
                ),
            ),
            (
                "suppression",
                (
                    "Path 'docs' points to a directory but matches no file in it. "
                    "Use 'docs/**/*' to suppress the findings in every file "
                    "inside the directory."
                ),
            ),
        ],
    )
    def test_lint_and_validate_give_the_same_advice(self, tmp_path, kind, advice):
        config = self._config(tmp_path, kind)

        lint = [
            i.message
            for i in ConfigLinter.lint(config, source_dir=tmp_path).issues
            if DIRECTORY_ADVICE in i.message
        ]
        _, problems = ConfigValidator.validate_config_file(config, source_dir=tmp_path)

        assert lint == [advice], lint
        assert [p for p in problems if DIRECTORY_ADVICE in p] == [advice], problems


@pytest.mark.parametrize(
    "uri",
    [
        "node_modules/braces/package.json",
        "deploy/cdk/node_modules/jest/package.json",
        ".venv/lib/python3.12/site-packages/pkg/METADATA",
    ],
)
def test_dependency_findings_under_known_tool_directories_are_kept(tmp_path, uri):
    """ASH's built-in skip list is for the code scanners, not the SARIF step.

    It holds node_modules/, .venv/ and venv/ with trailing slashes. Matched
    literally, they never dropped a finding; read as directories they would drop
    every grype and npm-audit finding located at a dependency's package.json.
    """
    config = AshConfig(project_name="t")
    result = apply_suppressions_to_sarif(_sarif(uri), _context(tmp_path, config))
    assert len(result.runs[0].results) == 1, f"the finding at {uri} was dropped"
