# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An absolute ignore or suppression path is pointed out, with the spelling that works.

ASH matches the ``path`` of an ignore path or a suppression against file paths
relative to the scan root (utils/path_matching.py), so a pattern that starts with
``/``, or with a drive such as ``C:\\``, matches nothing anywhere: the files it was
meant to exclude are scanned, and the only other sign is an INFO line saying no
files are under the ignore paths. So ``ash config lint`` and ``ash config validate``
warn about such a pattern, naming the relative spelling: the rest of the path after
the scan root when the pattern is under it, otherwise the pattern without its
leading slashes. The matcher is unchanged.
"""

from pathlib import Path, PureWindowsPath

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintSeverity,
)
from automated_security_helper.config.config_validator import (
    ConfigValidator,
    absolute_path_warning,
)
from automated_security_helper.utils.path_matching import _path_pattern_matches

ABSOLUTE = "is absolute"


def _write(tmp_path: Path, ignore_path=None, suppression_path=None) -> Path:
    (tmp_path / "vendor").mkdir(exist_ok=True)
    lines = ["project_name: t", "global_settings:"]
    if ignore_path is not None:
        lines += ["  ignore_paths:", f"    - path: '{ignore_path}'", "      reason: r"]
    if suppression_path is not None:
        lines += [
            "  suppressions:",
            "    - rule_id: B101",
            f"      path: '{suppression_path}'",
            "      reason: r",
        ]
    config = tmp_path / ".ash.yaml"
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config


def _lint(config: Path, tmp_path: Path):
    return [
        issue
        for issue in ConfigLinter.lint(config, source_dir=tmp_path).issues
        if ABSOLUTE in issue.message
    ]


def _validate(config: Path, tmp_path: Path):
    valid, problems = ConfigValidator.validate_config_file(config, source_dir=tmp_path)
    return valid, [p for p in problems if ABSOLUTE in p]


def test_the_matcher_reads_an_absolute_pattern_as_matching_nothing():
    """The premise, and the semantics this change leaves alone."""
    assert _path_pattern_matches("vendor/a.py", "vendor/**")
    assert not _path_pattern_matches("vendor/a.py", "/vendor/**")
    assert not _path_pattern_matches("vendor/a.py", "C:/repo/vendor/**")


@pytest.mark.parametrize(
    "pattern, relative",
    [
        pytest.param("/vendor/**", "vendor/**", id="leading-slash"),
        # vendor is a directory under the root, and "vendor" alone would match
        # only a file of that name: the directory is spelled "vendor/".
        pytest.param("/vendor", "vendor/", id="leading-slash-no-glob"),
        pytest.param("{root}/vendor", "vendor/", id="absolute-directory-no-glob"),
        pytest.param("{root}/vendor/**", "vendor/**", id="absolute-under-the-root"),
        pytest.param(
            "{root}\\vendor\\**", "vendor/**", id="absolute-under-the-root-backslashes"
        ),
    ],
)
def test_lint_and_validate_name_the_relative_spelling(tmp_path, pattern, relative):
    pattern = pattern.format(root=tmp_path.resolve().as_posix())
    config = _write(tmp_path, ignore_path=pattern)

    (issue,) = _lint(config, tmp_path)
    assert issue.severity == LintSeverity.WARNING, issue
    assert issue.path == "global_settings.ignore_paths[0].path", issue
    assert f"'{pattern}'" in issue.message, issue.message
    assert f"Use '{relative}'" in issue.message, issue.message

    valid, (warning,) = _validate(config, tmp_path)
    assert valid, "a scan accepts the file, so validate still calls it valid"
    assert f"'{pattern}'" in warning and f"Use '{relative}'" in warning, warning


@pytest.mark.parametrize(
    "pattern",
    [
        pytest.param("C:\\elsewhere\\vendor\\**", id="drive-outside-the-root"),
        pytest.param("/", id="only-a-slash"),
        pytest.param("/**", id="only-a-glob"),
        # A UNC share is a drive of its own, never under the scan root.
        pytest.param("//vendor/", id="unc-forward-slashes"),
        pytest.param("\\\\server\\share\\vendor\\**", id="unc-backslashes"),
        # "/x" names x under the root only when x is there.
        pytest.param("/elsewhere/vendor/**", id="leading-slash-naming-nothing"),
        # A POSIX path's case is the path: an upper-cased root is another one.
        pytest.param("{upper_root}/vendor/**", id="root-in-another-case"),
        # ".." leaves the root: no spelling under it names that directory.
        pytest.param("/../{outside}/**", id="leading-slash-dot-dot"),
        pytest.param("{root}/../{outside}/**", id="under-the-root-dot-dot"),
        pytest.param("/./vendor/**", id="leading-slash-dot"),
    ],
)
def test_without_a_relative_spelling_it_says_to_write_one(tmp_path, pattern):
    # Each exists, so a spelling of it would be offered if nothing ruled it
    # out: server/share/vendor for the UNC share, the directory beside the
    # root for "..".
    (tmp_path / "server" / "share" / "vendor").mkdir(parents=True)
    outside = f"outside-{tmp_path.name}"
    (tmp_path.resolve().parent / outside).mkdir()
    pattern = pattern.format(
        upper_root=tmp_path.resolve().as_posix().upper(),
        root=tmp_path.resolve().as_posix(),
        outside=outside,
    )
    config = _write(tmp_path, ignore_path=pattern)

    (issue,) = _lint(config, tmp_path)
    assert "Write it relative to the scan root" in issue.message, issue.message
    assert "Use '" not in issue.message, issue.message
    _, (warning,) = _validate(config, tmp_path)
    assert "Write it relative to the scan root" in warning, warning


def test_a_suppression_path_is_checked_too(tmp_path):
    """Suppressions use the same matcher, so an absolute one suppresses nothing."""
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = _write(tmp_path, suppression_path="/app.py")

    (issue,) = _lint(config, tmp_path)
    assert issue.path == "global_settings.suppressions[0].path", issue
    assert "Use 'app.py'" in issue.message, issue.message
    _, (warning,) = _validate(config, tmp_path)
    assert "Use 'app.py'" in warning, warning


@pytest.mark.parametrize("pattern", ["/vendor", "{root}/vendor"])
def test_a_suppression_naming_a_directory_gets_its_files(tmp_path, pattern):
    """A glob-free remainder that is a directory under the root is spelled as
    the files under it: "vendor/**/*" for a suppression path, not "vendor",
    which matches only a file of that name."""
    pattern = pattern.format(root=tmp_path.resolve().as_posix())
    config = _write(tmp_path, suppression_path=pattern)

    (issue,) = _lint(config, tmp_path)
    assert "Use 'vendor/**/*' for" in issue.message, issue.message
    _, (warning,) = _validate(config, tmp_path)
    assert "Use 'vendor/**/*' for" in warning, warning


@pytest.mark.parametrize(
    "kind, relative",
    [
        # An ignore path's "dir/" names the directory's files, so it is kept.
        pytest.param("ignore_path", "vendor/", id="ignore-path-keeps-dir-slash"),
        # A suppression's "dir/" is read as written, and its "dir/**" also
        # matches a file named dir: the files under it are "dir/**/*".
        pytest.param("suppression_path", "vendor/**/*", id="suppression-dir"),
    ],
)
def test_a_directory_is_spelled_as_the_kind_of_path_reads_it(tmp_path, kind, relative):
    pattern = tmp_path.resolve().as_posix() + "/vendor/"
    config = _write(tmp_path, **{kind: pattern})

    (issue,) = _lint(config, tmp_path)
    assert f"Use '{relative}' for" in issue.message, issue.message
    _, (warning,) = _validate(config, tmp_path)
    assert f"Use '{relative}' for" in warning, warning


@pytest.mark.parametrize(
    "pattern, root, relative",
    [
        pytest.param("c:/repo/vendor/**", "C:/Repo", "vendor/**", id="drive-case"),
        pytest.param("C:\\Repo\\vendor\\**", "C:/Repo", "vendor/**", id="drive"),
        # A scan root on a UNC share: a path under it is under the root.
        pytest.param(
            "//server/share/repo/vendor/**",
            "//server/share/repo",
            "vendor/**",
            id="unc-root",
        ),
        pytest.param(
            "\\\\Server\\Share\\Repo\\vendor\\**",
            "//server/share/repo",
            "vendor/**",
            id="unc-root-case",
        ),
    ],
)
def test_a_drive_path_under_a_windows_root_matches_in_any_case(pattern, root, relative):
    """Windows paths compare without case, so a drive path under the root in
    another case still gets the rest of it as the spelling."""
    warning = absolute_path_warning(pattern, PureWindowsPath(root))

    assert warning is not None and f"Use '{relative}'" in warning, warning


@pytest.mark.parametrize("pattern", ["vendor/**", "./vendor/**", "**/vendor/", "*.py"])
def test_a_relative_pattern_draws_no_warning(tmp_path, pattern):
    config = _write(tmp_path, ignore_path=pattern, suppression_path=pattern)

    assert _lint(config, tmp_path) == []
    assert _validate(config, tmp_path) == (True, [])


def test_one_a_base_supplies_is_a_warning_too(tmp_path):
    """Only the validator sees a path an ``extends`` base supplies; lint shows
    its warning once, as a warning, not as an error that fails lint."""
    (tmp_path / "vendor").mkdir()
    (tmp_path / "base.yaml").write_text(
        "project_name: t\nglobal_settings:\n  ignore_paths:\n"
        "    - path: '/vendor/**'\n      reason: r\n",
        encoding="utf-8",
    )
    config = tmp_path / ".ash.yaml"
    config.write_text("extends: base.yaml\nproject_name: t\n", encoding="utf-8")

    (issue,) = _lint(config, tmp_path)
    assert issue.severity == LintSeverity.WARNING, issue
    assert issue.category == LintCategory.IGNORE_PATH_ISSUE, issue
    assert "Use 'vendor/**'" in issue.message, issue.message


def test_the_warning_names_the_base_a_path_comes_from(tmp_path):
    """In a chain, the file to edit is the one that holds the path: the warning
    names it. One the checked file holds itself is located by lint instead."""
    (tmp_path / "vendor").mkdir()
    (tmp_path / "root.yaml").write_text(
        "project_name: t\nglobal_settings:\n  ignore_paths:\n"
        "    - path: '/vendor/**'\n      reason: r\n",
        encoding="utf-8",
    )
    (tmp_path / "middle.yaml").write_text(
        "extends: root.yaml\nglobal_settings:\n  suppressions:\n"
        "    - rule_id: B101\n      path: '/vendor/'\n      reason: r\n",
        encoding="utf-8",
    )
    config = tmp_path / ".ash.yaml"
    config.write_text("extends: middle.yaml\nproject_name: t\n", encoding="utf-8")

    _, warnings = _validate(config, tmp_path)
    by_pattern = {w.split("'")[1]: w for w in warnings}
    assert by_pattern["/vendor/**"].endswith(
        f"It is in {(tmp_path / 'root.yaml').resolve().as_posix()}."
    ), warnings
    assert by_pattern["/vendor/"].endswith(
        f"It is in {(tmp_path / 'middle.yaml').resolve().as_posix()}."
    ), warnings
    assert sorted(i.message for i in _lint(config, tmp_path)) == sorted(warnings)


def test_a_path_the_checked_file_holds_names_no_file(tmp_path):
    config = _write(tmp_path, ignore_path="/vendor/**")

    _, (warning,) = _validate(config, tmp_path)
    assert "It is in" not in warning, warning


def test_an_absolute_directory_is_not_called_a_missing_glob(tmp_path):
    """``/vendor`` joined to the scan root is ``/vendor`` itself, not the repo's
    vendor directory; the directory check must not advise ``/vendor/``."""
    config = _write(tmp_path, ignore_path=tmp_path.resolve().as_posix() + "/vendor")

    issues = ConfigLinter.lint(config, source_dir=tmp_path).issues
    assert [i for i in issues if ABSOLUTE in i.message], issues
    assert not [i for i in issues if "matches no file in it" in i.message], issues


@pytest.mark.parametrize("command", ["lint", "validate"])
def test_the_printed_warning_shows_the_pattern_without_obeying_it(
    tmp_path, monkeypatch, command
):
    """The pattern is printed through the console's escaping, once."""
    hostile = "/vendor\x1b[31m\n::error title=x::y/**"
    config = _write(tmp_path, ignore_path=hostile.replace("\n", "\\n"))
    # YAML single quotes keep "\n" as two characters; write the real newline
    # in a double-quoted scalar instead.
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "'" + hostile.replace("\n", "\\n") + "'",
            '"/vendor\\e[31m\\n::error title=x::y/**"',
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["config", command, "--config", str(config)])

    assert ABSOLUTE in result.output, result.output
    assert "\x1b" not in result.output, repr(result.output)
    assert not [
        line for line in result.output.splitlines() if line.lstrip().startswith("::")
    ], repr(result.output)
    assert "\\x1b[31m" in result.output, repr(result.output)
    assert "\\\\x1b" not in result.output, "escaped twice: " + repr(result.output)
    # Reported once, lint's copy and validate's folded into one, and on one line:
    # the pattern's newline is shown as an escape, so it cannot start a line of
    # its own choosing.
    assert result.output.count(ABSOLUTE) == 1, repr(result.output)
    (line,) = [line for line in result.output.splitlines() if ABSOLUTE in line]
    assert "\\x0a::error title=x::y/**" in line, repr(line)
    assert "\\\\x0a" not in result.output, "escaped twice: " + repr(result.output)


#: A path segment of a value read from the environment, which the advice for an
#: absolute path must not print, whole or in part.
_ENV_SEGMENT = "envpathsegment"


@pytest.mark.parametrize("where", ["file", "base"])
@pytest.mark.parametrize("kind", ["outside-root", "under-root"])
@pytest.mark.parametrize("command", ["lint", "validate"])
def test_a_path_read_from_the_environment_is_not_spelled_out(
    tmp_path, monkeypatch, command, kind, where
):
    """The advice for an absolute path spells the rest of it relative to the root.

    Every message hides a value read from the environment as `<value>`, and a
    relative spelling is a piece of the value, which that hides nothing of, so a
    path read from the environment is only told to be written relative.
    """
    root = tmp_path.resolve()
    # What /<segment>/vendor/** names before its glob exists under the root, so
    # the literal path gets the spelling <segment>/vendor/**.
    (root / _ENV_SEGMENT / "vendor").mkdir(parents=True)
    value = (
        f"/{_ENV_SEGMENT}/vendor/**"
        if kind == "outside-root"
        else f"{root.as_posix()}/{_ENV_SEGMENT}2/lib/**"
    )
    monkeypatch.setenv("ASH_TEST_ENV_PATH", value)
    entry = "  ignore_paths:\n    - path: ${ASH_TEST_ENV_PATH}\n      reason: r\n"
    config = tmp_path / ".ash.yaml"
    if where == "file":
        config.write_text(
            f"project_name: t\nglobal_settings:\n{entry}", encoding="utf-8"
        )
    else:
        (tmp_path / "base.yaml").write_text(
            f"global_settings:\n{entry}", encoding="utf-8"
        )
        config.write_text("project_name: t\nextends: base.yaml\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["config", command, "--config", str(config)])

    assert ABSOLUTE in result.output, result.output
    assert _ENV_SEGMENT not in result.output, result.output
    assert "Write it relative to the scan root." in result.output, result.output


def test_a_literal_path_gets_its_spelling(tmp_path, monkeypatch):
    """Control: the same path written in the file is spelled out."""
    root = tmp_path.resolve()
    # What /<segment>/vendor/** names before its glob exists under the root, so
    # the literal path gets the spelling <segment>/vendor/**.
    (root / _ENV_SEGMENT / "vendor").mkdir(parents=True)
    config = _write(tmp_path, ignore_path=f"/{_ENV_SEGMENT}/vendor/**")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["config", "lint", "--config", str(config)])

    assert f"Use '{_ENV_SEGMENT}/vendor/**'" in result.output, result.output
