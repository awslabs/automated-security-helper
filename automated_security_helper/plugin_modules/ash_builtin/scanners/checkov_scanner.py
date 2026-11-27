"""Module containing the Checkov security scanner implementation."""

import logging
import os
import json
import re
import shutil
from pathlib import Path
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)
from urllib.parse import quote, unquote

import yaml
from pydantic import Field, PrivateAttr
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.config.path_trust import (
    cwd_outside_scanned_tree,
    derived_roots,
    honored_path,
    resolved_path,
)
from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.options import (
    ScannerOptionsBase,
    tool_version_constraint,
)
from automated_security_helper.models.vocab import TargetType
from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase
from automated_security_helper.base.uv_tool_mixin import (
    _record_direct_route_version,
    _restore_uv_route,
    tool_name,
)
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.models.core import ToolArgs
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ToolExtraArg,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
)
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.get_scan_set import file_links_leaving_tree
from automated_security_helper.utils.link_exclusions import (
    ignored_entries,
    walked_files,
)
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_vcs_frameworks,
)
from automated_security_helper.utils.package_identity import ASH_RESOURCE_ID_KEY
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_atomic_write
from automated_security_helper.utils.scanned_tree import REASON_LINK_LEAVES_TREE
from automated_security_helper.utils.suppression_matcher import active_ignore_paths
from automated_security_helper.utils.uv_tool_runner import get_uv_tool_command


CheckFrameworks = Literal[
    "all",
    "ansible",
    "argo_workflows",
    "arm",
    "azure_pipelines",
    "bicep",
    "bitbucket_pipelines",
    "cdk",
    "circleci_pipelines",
    "cloudformation",
    "dockerfile",
    "github_configuration",
    "github_actions",
    "gitlab_configuration",
    "gitlab_ci",
    "bitbucket_configuration",
    "helm",
    "json",
    "yaml",
    "kubernetes",
    "kustomize",
    "openapi",
    "sca_package",
    "sca_image",
    "secrets",
    "serverless",
    "terraform",
    "terraform_json",
    "terraform_plan",
    "sast",
    "sast_python",
    "sast_java",
    "sast_javascript",
    "sast_typescript",
    "sast_golang",
    "3d_policy",
]

# Checkov's "all" framework set includes VCS server-configuration frameworks
# that audit remote platform settings via API tokens (such as
# CI_SERVER_URL/CI_JOB_TOKEN in GitLab CI) and write fetched config caches under
# cwd rather than scanning repository files. They are skipped unless explicitly
# requested (_process_config_options), and their remote fetches are disabled
# for offline scans (_execute_scan), which then warn for each one that runs.
# Each one's API token reaches checkov only when that framework runs in an
# online scan (_without_unused_vcs_tokens). Rather than hardcoding the vendor
# list, the environment variables are derived from the skip set by checkov's
# naming rule, and the token variables, which follow none, are a measured table
# (checkov_vcs_frameworks has the rule, the table and their measurements).
#
# The skip set is the measured floor and does NOT follow the CheckFrameworks
# mirror: the mirror tracks the newest checkov, while checkov ends the run with
# parser.error on a --skip-framework value it does not know, and the
# >=3.2.0,<4.0.0 constraint admits releases that predate a newer name. Adding a
# VCS framework to the skip set is an explicit decision that also raises the
# constraint's lower bound to the first release that has it.
_VCS_CONFIGURATION_FRAMEWORKS: Tuple[str, ...] = (
    checkov_vcs_frameworks.KNOWN_VCS_CONFIGURATION_FRAMEWORKS
)

_VCS_CONFIG_FETCH_ENV_VARS: Tuple[str, ...] = (
    checkov_vcs_frameworks.vcs_config_fetch_env_vars(_VCS_CONFIGURATION_FRAMEWORKS)
)


# Characters an output directory's path cannot hold for ASH to pass it to checkov
# as --skip-path, escaped or not: they can break the regex checkov's terraform
# module finder builds from every --skip-path value. See
# CheckovScanner._output_dir_skip_patterns.
_CHECKOV_UNSAFE_SKIP_PATH_CHARS = frozenset("()")

# checkov's VCS configuration frameworks fetch the repository host's settings
# through its API and write them to a directory below checkov's working
# directory, which these variables name. ASH runs checkov from the filesystem
# root (CheckovScanner._subprocess_cwd), which a user that is not root cannot
# write to, so the scan stopped with a PermissionError (``/gitlab_conf``) and
# checkov exited 2. Writing into the scanned tree is what moving the working
# directory avoided. Each directory goes under the scanner's results directory
# instead, unless the operator named one, and what an earlier run left in it is
# removed before checkov starts (CheckovScanner._remove_earlier_vcs_conf).
# checkov joins the value to its working directory with ``os.path.join``, so an
# absolute path is used as it is. The variables and their default directory
# names are derived from the skip set above by checkov's naming rule
# (checkov_vcs_frameworks has the rule and its measurements).
_CHECKOV_VCS_CONF_DIR_ENV = dict(
    checkov_vcs_frameworks.vcs_conf_dir_env_vars(_VCS_CONFIGURATION_FRAMEWORKS)
)

# The directory below a target's results directory that holds the conf
# directories ASH names. A directory of its own, because checkov's GitHub
# framework removes its directory when it exists.
_VCS_CONF_ROOT_NAME = "vcs-config"

# The variable each VCS configuration framework in the skip set reads its API
# token from (checkov_vcs_frameworks.VCS_TOKEN_ENV_VARS has the measurements).
# checkov reads all three when it starts, whichever frameworks run, so a token
# reaches checkov only for a framework that runs in an online scan
# (_without_unused_vcs_tokens). A framework added to the skip set without an
# entry there fails at import, so its token is never passed through unnoticed.
_CHECKOV_VCS_TOKEN_ENV = {
    framework: checkov_vcs_frameworks.VCS_TOKEN_ENV_VARS[framework]
    for framework in _VCS_CONFIGURATION_FRAMEWORKS
}


def _vcs_frameworks_that_run(
    frameworks: Sequence[str], skip_frameworks: Sequence[str]
) -> Tuple[str, ...]:
    """The VCS configuration frameworks checkov runs, given the frameworks it reads
    and the ones it skips: each one ``frameworks`` names, or every one when it
    names ``all``, less those ``skip_frameworks`` names."""
    return tuple(
        framework
        for framework in _VCS_CONFIGURATION_FRAMEWORKS
        if ("all" in frameworks or framework in frameworks)
        and framework not in skip_frameworks
    )


def _ash_named_vcs_conf_dirs(
    results_dir: Path, environment: Mapping[str, str]
) -> dict[str, Path]:
    """The conf directory ASH names below ``results_dir`` for each VCS
    configuration framework whose variable ``environment`` does not set, keyed by
    the variable (see ``_CHECKOV_VCS_CONF_DIR_ENV``). A variable the operator set
    keeps its value, and its directory is not ASH's."""
    conf_root = results_dir.joinpath(_VCS_CONF_ROOT_NAME)
    return {
        variable: conf_root.joinpath(name)
        for variable, name in _CHECKOV_VCS_CONF_DIR_ENV.items()
        if variable not in environment
    }


def _without_unused_vcs_tokens(
    environment: Mapping[str, str], frameworks_run: Sequence[str], offline: bool
) -> dict[str, str]:
    """``environment`` without the API token of each VCS configuration framework
    that cannot use it: every one in an offline scan, which fetches nothing, and
    in an online scan each one that does not run (``frameworks_run`` is the set
    ``_vcs_frameworks_that_run`` gives). A framework that runs online keeps its
    token. Names are compared without case, as Windows reads them, so a variable
    spelled in another case is left out with the token it names."""
    unused = {
        variable.upper()
        for framework, variable in _CHECKOV_VCS_TOKEN_ENV.items()
        if offline or framework not in frameworks_run
    }
    return {
        name: value for name, value in environment.items() if name.upper() not in unused
    }


#: How ``_skip_path_text`` writes the characters checkov's terraform module finder
#: would read as a group or a character class once it joins the values a character
#: at a time (``_module_finder_compiles``), and the dot: each as a class that holds
#: it alone. ``re.search`` reads ``[(]`` as it reads ``\(``.
_SKIP_PATH_CLASS_SPELLINGS = {
    ".": "[.]",
    "(": "[(]",
    ")": "[)]",
    "[": "[\\[]",
    "]": "[\\]]",
}


def _skip_path_text(text: str) -> str:
    """``text`` as the literal part of a ``--skip-path`` value.

    Each character is ``re.escape``d, except a dot, a parenthesis and a bracket,
    which are written as a class holding that character alone
    (``_SKIP_PATH_CLASS_SPELLINGS``). The dot for the reason ``_link_skip_patterns``
    gives. The others because checkov's terraform module finder joins every value
    into one regex a character at a time (``_module_finder_compiles``): there an
    escaped parenthesis becomes a group, which a ``]`` earlier in the list can
    leave unbalanced, and an escaped bracket opens or closes a character class.
    Written as a class, none of them opens a group or leaves a class open, so a
    value built from this text compiles wherever it sits in the list.
    ``re.search`` matches the same paths with either spelling.
    """
    return "".join(
        _SKIP_PATH_CLASS_SPELLINGS.get(character) or re.escape(character)
        for character in text
    )


def _known_directory_skip_values(root: str) -> List[str]:
    """The ``--skip-path`` values that skip the ``KNOWN_IGNORE_PATHS`` directories
    below ``root``, the scanned directory as ``_skip_path_root`` spells it.

    Two values for each entry, in the order of ``KNOWN_IGNORE_PATHS``. With
    ``name`` the entry without its slashes, and ``root`` and ``name`` escaped
    (``_skip_path_text``): ``<root>/<name>/`` for the directory directly below
    ``root``, and ``<root>/.{0,}/<name>/`` for one at any deeper level. For
    ``/repo`` and ``venv/`` that is ``/repo/venv/`` and ``/repo/.{0,}/venv/``.

    What they match. checkov applies each value with ``re.search`` and as a
    substring against ``os.path.join(<directory it walks>, <entry>)``
    (``filter_ignored_paths``), and every directory it walks starts with the
    absolute path of the scanned one (``_execute_scan`` hands it an absolute
    target). A value that starts with that path matches whole directory names
    below the scanned directory, at any depth, and never a component of the
    scanned directory's own path or above it: a target that is itself named
    ``venv``, or sits under a directory named ``venv``, ``.venv`` or
    ``node_modules``, is scanned. checkov's secrets framework is the exception: it
    adds its own list of names, ``venv`` and ``node_modules`` among them, to the
    values and matches them the same unanchored way (``checkov/secrets/utils.py``,
    ``EXCLUDED_PATHS``), so it still reads no file of such a target. The values
    this replaced, ``/venv/``, ``/[.]venv/`` and ``/node_modules/``, started at a
    ``/`` and so matched such an ancestor too: the walked paths of a target below
    ``/home/me/venv`` all hold ``/venv/``, every entry was removed, checkov read
    nothing, and ASH reported the target clean. A name is a whole directory name,
    so ``devenv/``, ``my.venv/``, ``venvx/`` and ``old_node_modules/`` are
    scanned.

    The substring half of checkov's test matches the value's own text. For the
    directly-below value of a name with no dot, under a root ``re.escape`` leaves
    unchanged, that is the same set of paths the regex half matches. For the
    deeper value, for a dotted name (``[.]venv``) and for a root holding a
    character ``_skip_path_text`` changes (``-``, a space, a dot, a parenthesis,
    a bracket), it matches only a path that holds that text literally, such as a
    directory named ``[.]venv``; the regex half does the work there.

    ``.{0,}``, not ``.*``: checkov's terraform module finder compiles
    ``'|'.join(f"({excluded_paths})")`` over the values (``module_finder.py``),
    one character per alternative, so a ``*`` there follows a ``|`` and fails with
    "nothing to repeat" whenever an earlier ``]`` has closed the character class
    the list's own ``[`` opens, which the ``[.]`` of the ``.venv`` values does.
    That fails the whole terraform scan. ``.{0,}`` is the same regex and compiles
    (``_module_finder_compiles``). It does not match a newline, so a directory
    whose name holds one, above a known directory, leaves that directory
    unmatched: checkov reads it, and ``_under_a_known_ignore_path`` says so.

    The values hold no ``^``, no group and no alternation. No ``^`` is needed:
    every walked path starts with the root, and a match further along can only be
    a known directory below it. A parenthesis or bracket in the root is written as
    a class holding it alone (``_skip_path_text``), so the values compile in the
    module finder's joined regex wherever they sit, and the ``[.]`` of the
    ``.venv`` values leaves it outside a character class, as the fixed values they
    replaced did. ``_execute_scan`` puts them where those were, so the operator's
    values after them compile, or do not, as before. A ``|`` or ``^`` ASH wrote
    would be read by a batch interpreter that re-reads the command line: cmd.exe
    splits an unquoted value at ``|`` and consumes ``^`` as its escape character,
    which is how the earlier ``(^|/)[.]venv/`` form failed the Install Method
    Validation run on Windows. A root can bring one in, and ``re.escape`` keeps it
    in the value, escaped. No value is sent on Windows at all.
    """
    anchor = _skip_path_text(root)
    values: List[str] = []
    for entry in KNOWN_IGNORE_PATHS:
        name = _skip_path_text(entry.strip("/"))
        values.append(f"{anchor}/{name}/")
        values.append(f"{anchor}/.{{0,}}/{name}/")
    return values


def _module_finder_compiles(values: List[str]) -> bool:
    """Whether checkov's terraform module finder can compile its regex over
    ``values``, the ``--skip-path`` values in the order checkov is given them.

    checkov 3.3.26 builds it as ``re.compile('|'.join(f"({excluded_paths})"))``
    (``checkov/terraform/module_loading/module_finder.py``): the list's text, joined
    one character at a time. When that fails to compile, checkov's whole terraform
    scan fails, so a value that makes it fail cannot be given.
    """
    if not values:
        return True
    try:
        re.compile("|".join(f"({list(values)})"))
    except re.error:
        return False
    return True


def _link_named_in_refusal(target: Path, links: Optional[List[str]] = None) -> str:
    """The link a refusal of ``target`` names: one whose path holds a parenthesis,
    the likely cause, or else the first.

    ``links`` is the list the caller already walked (``file_links_leaving_tree``),
    so the tree is not walked a second time for the message; without it the walk
    runs here. An empty list (the links are gone, or the caller had none) names
    no link rather than failing on an empty index.
    """
    if links is None:
        links = file_links_leaving_tree(target)
    with_parenthesis = [link for link in links if "(" in link or ")" in link]
    chosen = with_parenthesis or links
    return chosen[0] if chosen else "a link that leaves the scanned tree"


def _under_a_known_ignore_path(relative: str) -> bool:
    """Whether the values ``_known_directory_skip_values`` builds skip ``relative``
    (``/``-joined, below the target): it lies under a directory ``KNOWN_IGNORE_PATHS``
    names, so a link there needs no value of its own.

    That holds only for a scan that sends those values, which
    ``_links_leaving_tree`` is told. The deeper value's ``.{0,}`` does not match a
    newline, so a path that passes through a directory whose name holds one before
    it reaches a known directory is not skipped, and is not under one here.
    """
    names = {entry.strip("/") for entry in KNOWN_IGNORE_PATHS}
    directories = relative.split("/")[:-1]
    for index, part in enumerate(directories):
        if part in names:
            return not any("\n" in above for above in directories[:index])
    return False


def _skip_path_root(target: Path) -> str:
    """``target`` as the start of a ``--skip-path`` value: without a trailing ``/``,
    so the filesystem root does not become ``//``, a path checkov never walks."""
    return Path(target).as_posix().rstrip("/")


def _given_skip_paths(extra_args: List[ToolExtraArg]) -> List[str]:
    """The ``--skip-path`` values already in ``extra_args``, in order: the
    ``skip-path`` values of the operator's checkov config file and the operator's
    ``skip_path``. The values for the known directories, ASH's output directories,
    links and ignored paths are built for each scan in ``_execute_scan`` and are
    not among them."""
    values = []
    for arg in extra_args:
        key = str(arg.key)
        if key.startswith("--skip-path="):
            values.append(key[len("--skip-path=") :])
        elif key == "--skip-path" and arg.value is not None:
            values.append(str(arg.value))
    return values


def checkov_repo_file_path(file_path: str, cwd: str) -> str:
    """The ``repo_file_path`` checkov records for ``file_path`` when run in ``cwd``.

    A copy of ``checkov.common.output.record.Record._determine_repo_file_path``
    (checkov 3.3.26) with the working directory as a parameter: ``"/" +`` the path
    relative to the working directory, separators made ``/``, and every ``/..``
    removed, or the path without its drive when the drive differs. checkov puts
    this, without the leading ``/`` and URL-quoted, in each SARIF result's URI.
    tests/unit/plugin_modules/ash_builtin/test_checkov_repo_file_path.py pins the
    shape and the integration test compares it with checkov's output.
    """
    path = Path(file_path)
    if Path(cwd).drive == path.drive:
        return f"/{os.path.relpath(path, cwd)}".replace("\\", "/").replace("/..", "")
    return f"/{'/'.join(path.parts[1:])}"


def _source_relative_path(file_path: str, cwd: str) -> str:
    """The path ASH writes for ``file_path``: checkov's shape, with the name kept.

    The same ``"/" +`` relative path, or the path without its drive when the
    drive differs, as :func:`checkov_repo_file_path`, with two differences. A
    backslash becomes ``/`` only where it is a separator, on Windows: checkov's
    own conversion rewrites every one, which on POSIX turned the file ``a\\b.tf``
    into ``a/b.tf``, a path that names no file. And the ``..`` components are
    kept: checkov removes every ``/..``, which turned a file outside ``cwd``
    (``../elsewhere/x.tf``) into ``elsewhere/x.tf``, a path that reads as
    inside it and names nothing there. That copy is kept exact because the
    prefixes it rebuilds have to match what checkov wrote; this one is what ASH
    reports.
    """
    path = Path(file_path)
    if Path(cwd).drive == path.drive:
        relative = os.path.relpath(path, cwd)
        if "\\" in (os.sep, os.altsep):
            relative = relative.replace("\\", "/")
        return f"/{relative}"
    return f"/{'/'.join(path.parts[1:])}"


def _within(path: str, root: str) -> bool:
    """Whether ``path`` is ``root`` or below it, both absolute, as spelled."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # another drive, on Windows
        return False


#: The most characters the ``--skip-path`` values for globally ignored paths may
#: take together. Every ignored file that is not under a wholly ignored directory
#: is its own value, so a large ignore set could exceed the argument-list limit
#: (checkov cannot start) or multiply checkov's per-directory filtering until the
#: scan timeout. Past the budget the rest are left out: ASH drops checkov's
#: findings under an ignored path anyway.
_IGNORE_SKIP_PATH_CHAR_BUDGET = 100_000


def rewrite_checkov_paths(
    document: Any,
    *,
    ran_in: str,
    source_dir: str,
    scanned_dirs: Sequence[str] = (),
    scanned_files: Optional[Callable[[], Iterable[str]]] = None,
) -> None:
    """Make the paths in a checkov SARIF or JSON report read as if run in source_dir.

    ASH runs checkov from the filesystem root (``CheckovScanner._subprocess_cwd``),
    so the paths checkov writes relative to its working directory are absolute
    paths without the leading ``/``. They are recomputed here with the source
    directory as the working directory, which is what checkov wrote when ASH ran
    it there, so findings and the suppressions that match their paths are
    unchanged. The JSON report's ``file_abs_path`` is used as is. A SARIF URI is
    matched against how checkov writes each of ``scanned_dirs`` (the target and
    the source directory) from ``ran_in``, because checkov's ``/..`` removal also
    changes an ancestor directory whose name starts with ``..``; a URI that
    matches none is joined to ``ran_in``.

    checkov also writes every backslash as ``/``, so on POSIX its path for the
    file ``a\\b.tf`` is ``a/b.tf``. When the path rebuilt from a URI does not
    exist, *scanned_files* (the scan set) is read, once, and a file checkov
    spells exactly that way, and the only one, is used instead. When both
    ``a\\b.tf`` and ``a/b.tf`` exist, checkov's path names an existing file and
    is kept: its output cannot tell the two apart.
    """
    cwd = os.path.realpath(source_dir)
    given = os.path.abspath(source_dir)
    prefixes = [
        (checkov_repo_file_path(root, ran_in).rstrip("/"), root)
        for root in scanned_dirs
    ]
    # checkov's spelling of each scanned file, to that file; None where two
    # files share a spelling. Built on the first URI that names nothing.
    by_checkov_spelling: Optional[dict[str, Optional[str]]] = None

    def _recovered(written: str) -> Optional[str]:
        nonlocal by_checkov_spelling
        if scanned_files is None:
            return None
        if by_checkov_spelling is None:
            by_checkov_spelling = {}
            try:
                names = list(scanned_files())
            except (OSError, ValueError, RuntimeError) as error:
                # The scan set is a convenience here (a name checkov respelled);
                # a set that cannot be read must not fail the whole report. The
                # URI then keeps checkov's form, as one with no match does.
                ASH_LOGGER.debug(
                    f"Could not read the scan set to recover checkov's paths: {error}",
                    extra=NO_MARKUP,
                )
                names = []
            for name in names:
                absolute = os.path.abspath(name)
                spelling = checkov_repo_file_path(absolute, ran_in)
                by_checkov_spelling[spelling] = (
                    None if spelling in by_checkov_spelling else absolute
                )
        return by_checkov_spelling.get(written)

    def _absolute(uri: str) -> str:
        # surrogateescape both ways: checkov writes the bytes of a name that is
        # not UTF-8 percent-encoded, and the default decoding replaced them with
        # U+FFFD, a path that names no file and could never be re-encoded to the
        # bytes checkov wrote.
        written = "/" + unquote(uri, errors="surrogateescape")
        joined = next(
            (
                os.path.join(root, written[len(prefix) + 1 :])
                for prefix, root in prefixes
                if written.startswith(prefix + "/")
            ),
            None,
        )
        if joined is None:
            joined = os.path.join(ran_in, unquote(uri, errors="surrogateescape"))
        if not os.path.lexists(joined):
            return _recovered(written) or joined
        return joined

    def _uri(uri: str) -> str:
        # Relative to the source directory as given before its real path: the
        # scanned dirs were spelled as given, so with a symlink component in the
        # source directory the real path alone gave an absolute-looking path.
        absolute = _absolute(uri)
        base = given if _within(absolute, given) else cwd
        return quote(
            _source_relative_path(absolute, base).lstrip("/"),
            errors="surrogateescape",
        )

    def _locations(items: Any) -> None:
        for location in items or []:
            artifact = (location.get("physicalLocation") or {}).get("artifactLocation")
            if isinstance(artifact, dict) and isinstance(artifact.get("uri"), str):
                # A URL (the guideline attach_checkov_guidelines writes as a
                # related location) is not a path to rebuild.
                if artifact["uri"].startswith(("https://", "http://")):
                    continue
                artifact["uri"] = _uri(artifact["uri"])

    if isinstance(document, dict) and "runs" in document:
        for run in document.get("runs") or []:
            for result in run.get("results") or []:
                _locations(result.get("locations"))
                _locations(result.get("relatedLocations"))
            for artifact in run.get("artifacts") or []:
                location = artifact.get("location")
                if isinstance(location, dict) and isinstance(location.get("uri"), str):
                    location["uri"] = _uri(location["uri"])
        return

    reports = document if isinstance(document, list) else [document]
    for report in reports:
        results = report.get("results") if isinstance(report, dict) else None
        for records in (results or {}).values():
            for record in records if isinstance(records, list) else []:
                if isinstance(record, dict) and isinstance(
                    record.get("file_abs_path"), str
                ):
                    # The same choice _uri makes for the SARIF report: checkov
                    # wrote the path as the scanned directory was given, so a
                    # symlinked source directory is relative to the given
                    # spelling, and the two reports agree on the file.
                    written = os.path.abspath(record["file_abs_path"])
                    base = given if _within(written, given) else cwd
                    record["repo_file_path"] = _source_relative_path(written, base)


#: The checkov frameworks whose records name the infrastructure resource a check
#: was run on. Every checkov record has a ``resource`` field, and what it holds
#: depends on the runner, so a framework is listed here only after its records
#: were read (checkov 3.4.10) and its ids were found to name one resource in a
#: file:
#:
#: - terraform ``aws_db_instance.this`` (the type and name), terraform_plan
#:   ``module.db.aws_db_instance.this`` (the resource address)
#: - cloudformation ``AWS::S3::Bucket.Bucket`` (the type and logical id)
#: - kubernetes ``Deployment.shop.web`` (the kind, namespace and name)
#: - bicep ``Microsoft.Storage/storageAccounts.st`` (the type and the symbolic
#:   name, which the parser keys a file's resources by, a nested one under its
#:   parent's name)
#:
#: Even for these, a record names no resource when its file's records give its
#: id at more than one line range: two resources then share the id
#: (:func:`checkov_resources`).
_RESOURCE_FRAMEWORKS = frozenset(
    {
        "terraform",
        "terraform_plan",
        "cloudformation",
        "kubernetes",
        "bicep",
    }
)

#: The checkov frameworks whose results carry no resource, and why. Together
#: with :data:`_RESOURCE_FRAMEWORKS` this names every runner checkov ships
#: (``checkov.main.DEFAULT_RUNNERS``); a test fails when checkov adds a runner
#: that is in neither, so a new framework is classified by reading its records
#: rather than taking whatever its ``resource`` field holds.
_NO_RESOURCE_FRAMEWORKS = {
    "terraform_json": "an id without the resource type: a Python check's record "
    "names resource.<name>, the kind of block and the name, so two resources of "
    "different types with one name share it, and a graph check's record names "
    "the same resource <type>.<name>",
    "arm": "an id that two resources can share with no line range to tell them "
    "apart: a name built from a parameter that has no default stays the template "
    "expression, every resource of a one-line template is at line 1, and a graph "
    "check gives a resource lines two above its other records",
    "secrets": "a hash of the secret (a SHA-1, or commit:hash), which must not "  # pragma: allowlist secret
    "become a resource id",
    "dockerfile": "the Dockerfile path, or the path and instruction "
    "(/Dockerfile.RUN): a file locator",
    "serverless": "a function or item name, or the literal 'complete'",
    "sast": "no resource: a source-code finding",
    "cdk": "no resource: a source-code finding",
    "sca_package": "a package locator, not an infrastructure resource",
    "sca_image": "an image locator, not an infrastructure resource",
    "github_actions": "a locator inside the workflow file (jobs(build).steps[2]): "
    "meaningful but a file position, not infrastructure",
    "gitlab_ci": "a locator inside the pipeline file: a file position",
    "circleci_pipelines": "a locator inside the pipeline file: a file position",
    "azure_pipelines": "a locator inside the pipeline file: a file position",
    "bitbucket_pipelines": "a locator inside the pipeline file: a file position",
    "argo_workflows": "a locator inside the workflow file: a file position",
    "ansible": "a locator inside the playbook: a file position",
    "openapi": "a locator inside the spec: a file position",
    "json": "a locator inside a custom-check JSON file: a file position",
    "yaml": "a locator inside a custom-check YAML file: a file position",
    "github_configuration": "a repository setting of a hosted service",
    "gitlab_configuration": "a repository setting of a hosted service",
    "bitbucket_configuration": "a repository setting of a hosted service",
    "helm": "not yet read: the runner needs the helm binary, which no sample "
    "run had; classify it by reading a record",
    "kustomize": "not yet read: the runner needs the kustomize binary, which no "
    "sample run had (its ids are prefixed, base:Deployment...); classify it by "
    "reading a record",
}

#: What identifies a checkov record in both of its reports: the rule, the file
#: as the SARIF URI spells it, and the line range.
_RecordKey = Tuple[str, str, int, int]


def _record_key(record: Any) -> Optional[_RecordKey]:
    """The key of a JSON report record, built as checkov builds its SARIF result.

    ``checkov.common.output.sarif`` (checkov 3.4.6) writes one result per failed
    or skipped record: ``ruleId`` is the ``check_id``, the URI is the quoted
    ``repo_file_path`` without its leading ``/``, and each line is the record's,
    or 1 when the record has 0 (a terraform plan has no lines). None for a
    record that does not have those fields in that shape.
    """
    if not isinstance(record, dict):
        return None
    check_id = record.get("check_id")
    repo_file_path = record.get("repo_file_path")
    lines = record.get("file_line_range")
    if not (isinstance(check_id, str) and isinstance(repo_file_path, str)):
        return None
    if not (isinstance(lines, list) and len(lines) == 2):
        return None
    try:
        start, end = (int(line) or 1 for line in lines)
    except (TypeError, ValueError):
        return None
    # surrogateescape, as _uri and _absolute: json.load reads the escape of a
    # name that is not UTF-8 as a lone surrogate, which strict encoding rejects.
    return (
        check_id,
        quote(repo_file_path.lstrip("/"), errors="surrogateescape"),
        start,
        end,
    )


def _result_key(result: Any) -> Optional[_RecordKey]:
    """The key of a SARIF result as checkov wrote it, or None without a location."""
    if not isinstance(result, dict):
        return None
    locations = result.get("locations")
    location = locations[0] if isinstance(locations, list) and locations else None
    physical = location.get("physicalLocation") if isinstance(location, dict) else None
    if not isinstance(physical, dict):
        return None
    artifact, region = physical.get("artifactLocation"), physical.get("region")
    if not (isinstance(artifact, dict) and isinstance(region, dict)):
        return None
    rule_id, uri = result.get("ruleId"), artifact.get("uri")
    start, end = region.get("startLine"), region.get("endLine")
    if not (isinstance(rule_id, str) and isinstance(uri, str)):
        return None
    if type(start) is not int or type(end) is not int:
        return None
    return rule_id, uri, start, end


def checkov_resources(json_report: Any) -> dict[_RecordKey, List[Optional[str]]]:
    """The resource of every record in checkov's JSON report, by record key.

    Each key holds one entry per record, in the order checkov's SARIF report
    lists the records' results: report by report, the failed records and then
    the skipped ones. An entry is the record's ``resource`` when its framework
    is one of :data:`_RESOURCE_FRAMEWORKS` and None otherwise, so a key's entries
    still count every record that has it.

    An entry is None as well when its file's records give its resource at more
    than one line range. Every check on one resource gives that resource's
    lines, so such an id is shared by two resources, and a suppression scoped to
    it would cover the findings of both. Neither is given it; a suppression for
    them is scoped by path and lines instead.

    Read before :func:`rewrite_checkov_paths` changes the report's paths: the
    keys are checkov's own spelling, which is what its SARIF URIs hold.
    """
    found = _record_values(
        json_report,
        lambda record, named: (
            record.get("resource")
            if named
            and isinstance(record.get("resource"), str)
            and record.get("resource")
            else None
        ),
    )
    shared = _resources_at_more_than_one_place(found)
    if not shared:
        return found
    return {
        key: [None if (key[1], value) in shared else value for value in values]
        for key, values in found.items()
    }


def _resources_at_more_than_one_place(
    found: dict[_RecordKey, List[Optional[str]]],
) -> set[Tuple[str, str]]:
    """The ``(file, resource)`` pairs that the records give at two or more line
    ranges, the file and the lines as a key spells them."""
    places: dict[Tuple[str, str], set[Tuple[int, int]]] = {}
    for (_rule, uri, start, end), resources in found.items():
        for resource in resources:
            if resource is not None:
                places.setdefault((uri, resource), set()).add((start, end))
    return {pair for pair, lines in places.items() if len(lines) > 1}


def checkov_guidelines(json_report: Any) -> dict[_RecordKey, List[Optional[str]]]:
    """The guideline URL of every record in checkov's JSON report, by record key.

    The same keys and the same per-key order as :func:`checkov_resources`. An
    entry is the record's ``guideline`` when it is an ``http(s)`` URL and None
    otherwise (checkov writes null for a check with no policy page). Every
    framework carries one: a guideline names the policy, not a resource, so the
    per-framework allow-list of resources does not apply.
    """
    return _record_values(
        json_report,
        lambda record, _named: (
            record.get("guideline")
            if isinstance(record.get("guideline"), str)
            and record["guideline"].startswith(("https://", "http://"))
            else None
        ),
    )


def _record_values(
    json_report: Any, value_of: Callable[[dict[str, Any], bool], Optional[str]]
) -> dict[_RecordKey, List[Optional[str]]]:
    """``value_of(record, in_a_resource_framework)`` for every record, by key."""
    found: dict[_RecordKey, List[Optional[str]]] = {}
    reports = json_report if isinstance(json_report, list) else [json_report]
    for report in reports:
        if not isinstance(report, dict):
            continue
        results = report.get("results")
        if not isinstance(results, dict):
            continue
        check_type = report.get("check_type")
        # A list or dict is not hashable: only a string can be a framework.
        named = isinstance(check_type, str) and check_type in _RESOURCE_FRAMEWORKS
        for kind in ("failed_checks", "skipped_checks"):
            records = results.get(kind)
            for record in records if isinstance(records, list) else []:
                key = _record_key(record)
                if key is None:
                    continue
                found.setdefault(key, []).append(value_of(record, named))
    return found


def attach_checkov_resources(
    sarif: Any, resources: dict[_RecordKey, List[Optional[str]]]
) -> int:
    """Write each result's resource into its properties; return how many were set.

    checkov's SARIF result says which rule failed and where, and not on which
    resource: two instances of one module, or two resources of a terraform plan
    (every plan result is at line 1 of the plan file), give results that differ
    in nothing. The JSON report names the resource, so it is copied to the
    result under :data:`ASH_RESOURCE_ID_KEY`, the key a resource-scoped
    suppression matches and the flat reports read ``resource_id`` from.

    Both reports list a key's records in the same order, so the n-th result
    with a key takes the n-th resource recorded for it. When the two reports
    disagree on how many records a key has, none of that key's results is
    given a resource: a wrong resource would bind a suppression to a finding
    it was not written for, and a missing one only fails closed.

    Must run on the SARIF as checkov wrote it, before its paths are rewritten.
    """

    def write(result: dict[str, Any], resource: str) -> None:
        properties = result.get("properties")
        if not isinstance(properties, dict):
            properties = {}
            result["properties"] = properties
        properties[ASH_RESOURCE_ID_KEY] = resource

    return _attach_by_key(sarif, resources, write)


def attach_checkov_guidelines(
    sarif: Any, guidelines: dict[_RecordKey, List[Optional[str]]]
) -> int:
    """Write each result's policy guideline URL as a related location.

    The flat model's ``references`` are the URIs of a result's
    ``relatedLocations``, and checkov's SARIF carries none: its JSON report
    names the policy page of each check (``guideline``), which this copies, on
    the same key and under the same count rule as :func:`attach_checkov_resources`.
    Must run on the SARIF as checkov wrote it, before its paths are rewritten;
    :func:`rewrite_checkov_paths` leaves an ``http(s)`` URI alone.
    """

    def write(result: dict[str, Any], guideline: str) -> None:
        related = result.get("relatedLocations")
        if not isinstance(related, list):
            related = []
            result["relatedLocations"] = related
        related.append({"physicalLocation": {"artifactLocation": {"uri": guideline}}})

    return _attach_by_key(sarif, guidelines, write)


def _attach_by_key(
    sarif: Any,
    values: dict[_RecordKey, List[Optional[str]]],
    write: Callable[[dict[str, Any], str], None],
) -> int:
    """``write`` each key's n-th value to the n-th SARIF result with that key."""
    if not isinstance(sarif, dict) or not values:
        return 0
    by_key: dict[_RecordKey, List[dict[str, Any]]] = {}
    for run in sarif.get("runs") or []:
        for result in (run.get("results") or []) if isinstance(run, dict) else []:
            key = _result_key(result)
            if key is not None and key in values:
                by_key.setdefault(key, []).append(result)
    attached = 0
    for key, results in by_key.items():
        named = values[key]
        if len(named) != len(results):
            continue
        for result, value in zip(results, named):
            if value is None:
                continue
            write(result, value)
            attached += 1
    return attached


def _directory_as_one_token(argv: List[str]) -> List[str]:
    """``--directory <path>`` as the single token ``--directory=<path>``.

    checkov also reads ``.checkov.yaml`` from the directory it scans, found by
    looking for a ``-d`` or ``--directory`` token followed by a path
    (``get_default_config_paths``). Passed as one token, the same option names no
    such pair, so a config file in the scanned directory is not read. Checked
    against the checkov ASH installs.
    """
    out: List[str] = []
    index = 0
    while index < len(argv):
        if argv[index] in ("--directory", "-d") and index + 1 < len(argv):
            out.append(f"--directory={argv[index + 1]}")
            index += 2
            continue
        out.append(argv[index])
        index += 1
    return out


class CheckovScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        Path | str | None,
        Field(
            description=(
                "Path to a Checkov configuration file. A relative path is taken "
                "from the directory of the config file that sets it, or from the "
                "working directory for --config-overrides, not from the source "
                "directory. Only a file the operator names and that lies outside "
                "the scanned tree is passed to Checkov; a `.checkov.yaml` or "
                "`.checkov.yml` found in the scanned tree is not read, and the "
                "scan tells Checkov to read none from its working directory "
                "either, because such a file can change what is reported."
            ),
        ),
    ] = None
    skip_path: Annotated[
        List[IgnorePathWithReason],
        Field(
            description=(
                "Path (file or directory) to skip, as a regular expression Checkov "
                "searches for in each path it walks, and also as a substring of "
                "that path. The paths Checkov walks start with the absolute path "
                'of the scanned directory. Word boundaries are not implicit: "dir1" '
                'skips any directory or subdirectory whose path holds "dir1". An '
                "entry whose path is empty is ignored (it would skip every file). "
                "Can be specified multiple times."
            ),
        ),
    ] = []
    additional_formats: Annotated[
        List[
            Literal[
                "cli",
                "csv",
                "cyclonedx",
                "cyclonedx_json",
                "json",
                "junitxml",
                "github_failed_only",
                "gitlab_sast",
                "sarif",
                "spdx",
            ]
        ],
        Field(
            description=(
                "List of additional formats to output. Defaults to including "
                "CycloneDX JSON. checkov's JSON report is written whatever this "
                "lists: ASH reads the resource of each finding from it, and "
                "rewrites its paths to the source-relative form the SARIF "
                "uses."
            )
        ),
    ] = ["cyclonedx_json"]
    offline: Annotated[
        bool,
        Field(
            description="Run in offline mode, disabling policy downloads. When true, this scanner runs offline even if ASH does not. ASH's own offline mode (--offline or ASH_OFFLINE) applies whatever this is set to; false follows it.",
            default=False,
        ),
    ]
    frameworks: Annotated[
        List[CheckFrameworks],
        Field(
            description=(
                "Specific frameworks to include with Checkov. Defaults to `all`, "
                "which leaves out checkov's `github_configuration`, "
                "`gitlab_configuration` and `bitbucket_configuration` frameworks: "
                "they check the repository host's settings through its API, not "
                "files in the scanned tree. Name one of them here, with or "
                "without `all`, to run it."
            )
        ),
    ] = ["all"]
    skip_frameworks: Annotated[
        List[CheckFrameworks],
        Field(
            description=(
                "Specific frameworks to exclude with Checkov. Defaults to none, "
                "though `all` in `frameworks` leaves out `github_configuration`, "
                "`gitlab_configuration` and `bitbucket_configuration` unless "
                "`frameworks` names them."
            )
        ),
    ] = []
    skip_ash_output_dir: Annotated[
        bool,
        Field(
            description=(
                "Tell Checkov to skip ASH's own output directories inside the "
                "scanned directory (this run's output directory and "
                ".ash/ash_output), so it does not parse ASH's previous reports. "
                "Defaults to true; set to false to let Checkov read them. Either "
                "way ASH drops the findings located there after the scan. Has no "
                "effect on Windows, where Checkov's --skip-path matching is "
                "unreliable."
            ),
        ),
    ] = True
    tool_version: Annotated[
        str | None,
        tool_version_constraint("scanners.checkov.options.tool_version"),
        Field(
            description=(
                "Version constraint for checkov installation, in pip requirement "
                "syntax. Leave unset to use the scanner's own default constraint."
            )
        ),
    ] = None
    install_timeout: Annotated[
        int,
        Field(description="Timeout in seconds for tool installation"),
    ] = 300


class CheckovScannerConfig(ScannerPluginConfigBase):
    name: Literal["checkov"] = "checkov"
    enabled: bool = True
    options: Annotated[
        CheckovScannerConfigOptions, Field(description="Configure Checkov scanner")
    ] = CheckovScannerConfigOptions()


@ash_scanner_plugin
class CheckovScanner(ScannerPluginBase[CheckovScannerConfig]):
    """CheckovScanner implements IaC scanning using Checkov."""

    display_name = "Checkov"
    docs_summary = "Infrastructure policy checks"
    covers = ("Terraform", "Kubernetes", "CloudFormation", "Other IaC frameworks")

    #: checkov is a Python package ASH runs through uv. See
    #: ScannerPluginBase.python_only.
    python_only: ClassVar[bool | None] = True

    # CKV_ too: checkov reads its own switches under that prefix as well
    # (CKV_SECRETS_SCAN_ENABLE_ALL, CKV_IGNORED_DIRECTORIES, ...), and under the
    # sandbox a variable the operator set that way never reached it.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        env_prefixes=("CHECKOV_", "CKV_")
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    #: The facets register row (base/scanner_facets.py), declaration only.
    #: The records read are the committed side report (tests/test_data/scanners/
    #: checkov/src.test.yaml.json, failed_checks[] keys check_id, file_path,
    #: file_line_range, check_name, resource, guideline, fixed_definition,
    #: code_block), the committed checkov-3.4.6 SARIF capture, and the SARIF
    #: checkov 3.4.6 writes: the capture under
    #: tests/test_data/scanners/checkov/resources/results_sarif.sarif holds
    #: only ruleId, URI and line range (its README says the messages, snippets
    #: and rules were left out), so the SARIF cells below are settled from
    #: checkov's own writer, checkov/common/output/sarif.py ``_create_results``
    #: (3.4.6): each result has ``level``, ``message.text``, ``attachments``
    #: and ``locations[0].physicalLocation`` with ``region.startLine``,
    #: ``region.endLine`` and ``region.snippet.text`` (the record's code_block
    #: joined), and no column, contextRegion, fingerprint or property bag.
    #: A cell the capture settles carries its evidence (MAPPED, or n/a with
    #: the reason read off the capture); a cell neither source settles is
    #: UNCONFIRMED, never n/a. resource_id is MAPPED:
    #: :func:`attach_checkov_resources` copies each record's ``resource`` from
    #: the JSON report onto its SARIF result under ``ash_resource_id``, and only
    #: for the frameworks in :data:`_RESOURCE_FRAMEWORKS` (the per-framework
    #: allow-list), because the other runners carry non-resources in that field.
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "check_id" (e.g. CKV_AWS_55), the SARIF result ruleId',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='SARIF result "level" (settled by the committed '
            'checkov-3.4.6 capture; the side report\'s "severity" stays '
            "null without a platform key)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "repo_file_path", the SARIF artifact uri '
            "(rewritten by rewrite_checkov_paths)",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "file_line_range", the SARIF region startLine/endLine',
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the committed checkov-3.4.6 capture's six SARIF regions "
            "carry startLine, endLine and snippet only, and the side report "
            "carries a line range only",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "check_name"',
        ),
        resource_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='check "resource" (the results_json.json side report), '
            "copied onto the SARIF result by attach_checkov_resources for the "
            "frameworks in _RESOURCE_FRAMEWORKS only",
            example="AWS::S3::Bucket.S3Bucket3",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="the side report's resource field is one dotted string "
            '("AWS::S3::Bucket.S3Bucket3"); no separate type field exists '
            "and splitting it would be a derivation",
        ),
        package_name=FacetDecl(
            state=FacetState.NA,
            reason="IaC policy checks over resources; no package exists in "
            "checkov's policy-check output",
        ),
        package_version=FacetDecl(
            state=FacetState.NA,
            reason="IaC policy checks over resources; no package exists in "
            "checkov's policy-check output",
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="IaC policy checks over resources; no package exists in "
            "checkov's policy-check output",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.NA,
            reason="checkov publishes its own check ids; no CVE taxonomy in "
            "the policy-check results",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="checkov publishes its own check ids; no CWE taxonomy in "
            "the policy-check results",
        ),
        fingerprints=FacetDecl(
            state=FacetState.NA,
            reason="none of the committed checkov-3.4.6 capture's six SARIF "
            "results carries fingerprints or partialFingerprints, and the "
            "side report carries no fingerprint",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="the side report has a fixed_definition key and it is null "
            "on every record read: 34 of 34 across terraform, cloudformation, "
            "kubernetes and dockerfile (checkov 3.4.5, an offline run beside "
            "the committed fixture), so no run ASH makes has shown "
            "a fix state to map; a populated record would redeclare it",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="check_name states the finding, not a remediation; no "
            "remediation text field exists in the side report",
        ),
        snippet=FacetDecl(
            state=FacetState.MAPPED,
            native_field="SARIF region.snippet.text (settled by the committed "
            'checkov-3.4.6 capture; the side report\'s "code_block" carries '
            "the same lines)",
        ),
        references=FacetDecl(
            state=FacetState.NA,
            reason='the side report has a "guideline" key and it is null on '
            "every record of the committed capture (9 of 9, checkov 3.4.6 "
            "insecure-s3), so no run ASH makes has shown a URL to map; "
            "attach_checkov_guidelines copies a non-null guideline onto the "
            "result as a related location, which the flat references read, "
            "so a capture whose records carry one redeclares this cell MAPPED",
        ),
        tags=FacetDecl(
            state=FacetState.NA,
            reason="the adapter adds no tags and the side report's "
            '"entity_tags" is null in the committed record',
        ),
        extras=FacetDecl(
            state=FacetState.NA,
            reason="none of the committed checkov-3.4.6 capture's six SARIF "
            "results carries a properties bag",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="checkov",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.PLATFORM_POLICIES,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.DEGRADED,
                offline_reason=(
                    "--skip-download is passed per scan so platform policies are not "
                    "fetched; the policies bundled in the pinned package still run, and "
                    "the PyPI update check is killed by CKV_SKIP_PACKAGE_UPDATE_CHECK"
                ),
                offline_strategy=OfflineStrategy.CACHE_FLAGS,
                sandbox_network=opsf.SandboxNetwork.NONE,
                sandbox_tension=(
                    "the sandbox declaration grants checkov no network even online, so a "
                    "sandboxed-online run and an unsandboxed-online run may differ in "
                    "platform policies"
                ),
                source=(
                    "checkov_scanner.py offline_strategy, sandbox_requirements, "
                    "--skip-download; utils/content_databases.py "
                    "SCANNERS_WITHOUT_CONTENT_DATABASE['checkov']"
                ),
                #: Design E5, measured 2026-11-24: checkov 3.4.7 (the pinned version)
                #: on one two-resource Terraform fixture, both runs unsandboxed under
                #: env -i, with network access and no platform API key. With
                #: --skip-download and without it, both runs reported the same 10
                #: failed checks (same check ids and resources, empty set difference
                #: both ways), so without a key the difference named in
                #: sandbox_tension did not show for this fixture and configuration.
                #: Not measured: why (the fetch path was not traced), other
                #: frameworks, and a run with a platform API key, which is the open
                #: question below.
                unconfirmed=(
                    "with a platform API key set, whether a sandboxed and an "
                    "unsandboxed online run differ; one differential run with a key "
                    "settles it (design E5)"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.SARIF,),
                side_reports=("results_json.json",),
                non_finding_artifacts=(),
                note="the side report is read by the resource-id attach (#1024)",
            ),
            targets=opsf.TargetsFacet(
                kinds=(
                    opsf.TargetKind.IAC_TERRAFORM,
                    opsf.TargetKind.IAC_KUBERNETES,
                    opsf.TargetKind.IAC_CLOUDFORMATION,
                    opsf.TargetKind.IAC_OTHER,
                ),
                tool_type=ScannerToolType.IAC,
                selection=(
                    "directory scan; precommit per-file with same-directory .tf/.tfvars "
                    "siblings (staged_scope_patterns)"
                ),
                covers_note=(
                    "covers named three frameworks; staged_scope_patterns also name "
                    "serverless, ansible, argo, azure-pipelines, circleci, github-actions, "
                    "gitlab-ci, openapi and bicep (iac_other); the display string was "
                    "widened and the register declares the wired truth"
                ),
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.UV_PYTHON,
                external_programs=(),
                invocations=opsf.Invocations.ONE,
                python_only=True,
                use_uv_tool=True,
            ),
            runtime_compat=opsf.RuntimeCompatFacet(
                rows=(
                    opsf.RuntimeCompatRow(
                        runtime=opsf.RuntimeName.PYTHON,
                        # No checkov release is known to fix this, so the tool
                        # side is open: the row applies at every checkov
                        # version until an upstream release passes array_hook.
                        tool_versions="",
                        # >=3.10 is checkov's own floor; <3.15 is the proved
                        # upper bound (3.14.9 parses, 3.15.0 raises).
                        runtime_request=">=3.10,<3.15",
                        resolution=opsf.CompatResolution.PIN,
                        reason=(
                            "CPython 3.15 made array_hook a required argument "
                            "of json.decoder.JSONArray (signature 3.14.9: "
                            "(s_and_end, scan_once, _w, _ws); 3.15.0: "
                            "(s_and_end, scan_once, array_hook, _w, _ws)); "
                            "checkov's Decoder.json_array "
                            "(checkov/common/parsers/json/decoder.py) calls it "
                            "without one, so every JSON document that holds an "
                            "array fails to parse, and on a large tree the "
                            "parallel runner can wait indefinitely on the worker "
                            "error; reported against checkov 3.4.3 and 3.4.0 on "
                            "3.15.0; a fix is proposed upstream in "
                            "bridgecrewio/checkov#7778 and not merged"
                        ),
                        upstream_issue=(
                            "https://github.com/bridgecrewio/checkov/issues/7777"
                        ),
                        # Unsolved upstream: re-read whenever the checkov
                        # version constraint moves. The re-check is the
                        # recorded default constraint below -- the consistency
                        # gate reds the moment _get_tool_version_constraint's
                        # default no longer equals it (the bump that follows an
                        # upstream fix), and the fix then drops the upper bound
                        # and closes the row.
                        open_ended=True,
                        # _get_tool_version_constraint's default, as of this
                        # row's writing.
                        recorded_default_constraint=">=3.2.0,<4.0.0",
                    ),
                ),
            ),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="a PyPI package run through uv; platform support is the package's and was not read here",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="the tool's own per-finding severity is mapped",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.INLINE_COMMENT,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.UNCONFIRMED,
                        surface="#checkov:skip comments",
                        cite="tool feature; checkov_scanner.py was not read for an ASH-side switch",
                        reason=(
                            "whether ASH leaves the tool's skip comments on was not read at "
                            "the adapter; one adapter read settles it"
                        ),
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.POSITIONAL_ONLY,
                note="the committed side-report fixtures (tests/test_data/scanners/checkov/src.*.json) carry no fingerprint key and the adapter writes none; identity is file and line through the shared floor",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=("CHECKOV_", "CKV_"),
                options_surface=(
                    "frameworks, skip_frameworks, additional_formats; no external-checks "
                    "directory option exists at the adapter, so custom policies are a "
                    "declared NO today"
                ),
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1),
                semantics="0 clean, 1 findings: the native-tool convention",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.PYPI_VIA_UV,
                selection_surfaces=("options.frameworks", "options.skip_frameworks"),
                upstream_license=(
                    "Apache-2.0 (source: utils/tool_downloads.py "
                    "THIRD_PARTY_LICENSES['checkov'], pinned commit 2f107f8)"
                ),
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.NONE,),
                note="IaC files in the scan set",
            ),
        )
    )

    #: --mode precommit --staged: checkov is handed each staged file as
    #: ``--file <path>`` -- and, for Terraform, the staged file's SAME-DIRECTORY
    #: ``.tf``/``.tfvars`` siblings as extra ``--file`` entries
    #: (_staged_scope_paths below; never a ``--directory``, which recurses) --
    #: in place of ``--directory <target>``, so it parses what the commit
    #: stages instead of walking the tree. The patterns name what checkov's
    #: frameworks read, so a
    #: commit staging none of them (a README, a .py refactor) skips checkov's
    #: startup entirely. The cost of a missing pattern is a skipped checkov run
    #: on a commit it could have read, never a wrong finding: extend the list
    #: when a framework's file kind is missing. The --skip-path values stay
    #: anchored at the directory target as before, the known directories' too
    #: (``_known_directory_skip_values``, built per scan from the target); the
    #: path rewriting already matches file paths (rewrite_checkov_paths's
    #: ``scanned_files``).
    staged_scope_patterns: ClassVar[Optional[Tuple[str, ...]]] = (
        # terraform / bicep / cloudformation / serverless / k8s / openapi /
        # ansible / argo / azure pipelines / circleci / github actions / gitlab
        # ci (json and yaml kinds are shared by most of these)
        "*.tf",
        "*.tfvars",
        "*.json",
        "*.yaml",
        "*.yml",
        "*.template",
        "*.bicep",
        # dockerfile
        "Dockerfile",
        "Dockerfile.*",
        "*.dockerfile",
        # sca / supply chain manifests the sca frameworks read
        "requirements*.txt",
        "Pipfile",
        "Pipfile.lock",
        "setup.py",
        "pyproject.toml",
        "go.mod",
        "go.sum",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "yarn.lock",
        "Gemfile",
        "Gemfile.lock",
        "*.csproj",
        "packages.config",
        "composer.json",
        "composer.lock",
    )
    staged_target_style: ClassVar[Optional[str]] = "per-file-flag"
    staged_target_flag: ClassVar[str] = "--file"

    #: The name endings whose staged files pull in their SAME-DIRECTORY
    #: Terraform siblings as extra ``--file`` entries: a Terraform file read
    #: alone loses the sibling variables.tf defaults, locals and module sources,
    #: so a single-file scan changes findings and a suppression written against
    #: a whole-tree result may stop matching. Compared on the lowercased name,
    #: as the staged pattern matching is (``Main.TF`` is Terraform to checkov).
    #: Siblings only, never the directory itself: ``--directory`` walks
    #: recursively, so a staged root main.tf became a full-tree scan and a
    #: nested one scanned every subdirectory, which is the cost --staged exists
    #: to avoid. A sibling's own findings are not the commit's: the engine
    #: filters the results to the staged files before the reports.
    _STAGED_TERRAFORM_SUFFIXES: ClassVar[Tuple[str, ...]] = (
        ".tf",
        ".tfvars",
        ".tf.json",
    )

    def _is_staged_terraform(self, path: Path) -> bool:
        return path.name.lower().endswith(self._STAGED_TERRAFORM_SUFFIXES)

    def _staged_scope_paths(self, target, target_type):
        """The base selection, plus the staged Terraform files' own-dir siblings.

        After the base filtering (patterns, symlinks, the run's scan set), so
        siblings are added only for a Terraform file the scan set admits, and
        the siblings themselves go through the same scan-set filter and symlink
        cut, so an ignored or linked sibling is not brought back in. Every
        target stays a file, so nothing recurses and two staged files in one
        directory cannot make checkov parse a file twice.
        """
        staged = super()._staged_scope_paths(target, target_type)
        if not staged:
            return staged
        seen = set(staged)
        sibling_candidates: List[Path] = []
        for directory in sorted(
            {p.parent for p in staged if self._is_staged_terraform(p)}
        ):
            try:
                entries = sorted(directory.iterdir())
            except OSError as error:
                ASH_LOGGER.debug(
                    f"Not reading {directory} for staged Terraform siblings: {error}"
                )
                continue
            for sibling in entries:
                if sibling in seen or sibling.is_symlink() or not sibling.is_file():
                    continue
                if self._is_staged_terraform(sibling):
                    sibling_candidates.append(sibling)
                    seen.add(sibling)
        if not sibling_candidates:
            return staged
        return staged + self._staged_targets_in_scan_set(
            sibling_candidates, Path(target)
        )

    check_conf: str = "NOT_PROVIDED"

    # The absolute target of the scan in progress, set by _execute_scan and read
    # when the results are rewritten (see rewrite_checkov_paths).
    _checkov_target: Optional[Path] = PrivateAttr(default=None)
    # The working directory the scan in progress runs checkov in, as
    # _subprocess_cwd chose it: the results are rewritten against it, not
    # against the root it is normally equal to (see _read_results_file).
    _checkov_cwd: Optional[Path] = PrivateAttr(default=None)
    # The VCS configuration frameworks the command line _process_config_options
    # builds runs, read by an offline scan to say what each one checks
    # (_warn_offline_vcs_frameworks).
    _vcs_frameworks_run: Tuple[str, ...] = PrivateAttr(default=())
    #: Where ``_execute_scan`` puts the known-directory values in ``args.extra_args``:
    #: after the ``skip-path`` values of the operator's checkov config file and
    #: before the operator's ``skip_path`` (set by ``_process_config_options``).
    _known_directory_skip_at: Optional[int] = PrivateAttr(default=None)

    def model_post_init(self, context):
        if self.config is None:
            self.config = CheckovScannerConfig()
        self.command = "checkov"
        self.use_uv_tool = True  # Enable UV tool execution
        self.tool_type = ScannerToolType.IAC

        # Set up explicit UV tool installation commands
        self._setup_uv_tool_install_commands()

        # The version probe is recorded here and run once, by the dependency
        # check, the SARIF step or the inventory (resolve_deferred_tool_version):
        # construction must start nothing, whoever constructs the scanner.
        self._deferred_tool_version_probe = ("checkov", self._uv_from_spec())
        self.args = ToolArgs(
            format_arg="--output",
            format_arg_value="sarif",
            output_arg="--output-file-path",
            scan_path_arg="--directory",
            extra_args=[],
        )
        super().model_post_init(context)

    def _tool_version_from_metadata(self) -> bool:
        """checkov loads no stevedore plugins, and ``checkov --version`` takes
        about 1.9 s warm (it imports its framework first), so the recorded
        version is read from the installed environment's metadata."""
        return True

    def _get_tool_version_constraint(self) -> str | None:
        """Get version constraint for checkov installation.

        Returns:
            The configured ``tool_version`` constraint if set, otherwise the
            default returned below. The literal is deliberately stated once, in
            the return statement, rather than repeated here where it could drift.
        """
        # Use configured tool version if provided, otherwise use default
        if self.config and self.config.options.tool_version:
            return self.config.options.tool_version

        # Use checkov-specific version constraint - checkov 3.2.0+ has improved stability
        # and better SARIF support, but avoid 4.x for now due to potential breaking changes
        return ">=3.2.0,<4.0.0"

    def validate_plugin_dependencies(self) -> bool:
        """Validate the scanner configuration and requirements.

        Returns:
            True if validation passes, False otherwise

        Raises:
            ScannerError: If validation fails
        """
        # First, while use_uv_tool still says what construction set: the
        # tool-version probe, which construction leaves to this point.
        self.resolve_deferred_tool_version()
        # A copy on PATH an earlier validation of this instance verified and
        # chose to run directly is honored while it still exists: re-running
        # selection from here skipped the use_uv_tool branch (that decision
        # set the flag False) and fell to the consolidated resolver, whose
        # answer flipped the scan back through uv and spent a cold version
        # probe doing it, so the verified copy never ran.
        if self._honored_verified_pre_installed():
            return True
        if not self._validate_uv_tool_availability():
            # UV missing: the resolver's direct binary, verified first. The
            # resolver probes under this scanner's own offline mode, as every uv
            # call of the mixin does: without it a scanner offline by its
            # options probed PyPI online while its run and install were offline.
            resolved = get_uv_tool_command(
                tool_name(self),
                from_spec=self._uv_probe_from_spec(),
                offline=self._is_offline_mode(),
            )
            if resolved is None:
                return False
            return self._accept_binary_on_path(resolved)

        # For UV tool-based scanners, attempt explicit installation if needed
        if self.use_uv_tool:
            # Check if tool is already available (UV-installed or pre-installed)
            installation_info = self._get_tool_installation_info()

            if installation_info.get("available"):
                # Runs a verified binary on PATH directly instead of re-resolving
                # through uv, and fails offline with the missing extras named (#520).
                return self._select_tool_execution(installation_info)

            # Tool not available, attempt installation
            self._plugin_log(
                "Checkov not found via UV tool, attempting explicit installation..."
            )

            # Attempt explicit tool installation with configured timeout
            timeout = self.config.options.install_timeout if self.config else 300
            if self._install_uv_tool(timeout=timeout):
                self._plugin_log("Successfully installed checkov via UV tool")
                self.dependencies_satisfied = True
                return True

            self._plugin_log(
                "UV tool installation failed for checkov, falling back to consolidated resolver",
                level=logging.WARNING,
            )

        # Final fallback: consolidated UV-or-direct-binary resolver. A binary it
        # found on PATH has to run directly: with use_uv_tool left True every
        # scan went through uv, whose install had just failed. And a dependency
        # declared satisfied is recorded as such, as the branches above record it.
        resolved = get_uv_tool_command(
            tool_name(self),
            from_spec=self._uv_probe_from_spec(),
            offline=self._is_offline_mode(),
        )
        if resolved is None:
            return False
        if resolved[:1] == ["uv"]:
            _restore_uv_route(self)
        elif self.use_uv_tool:
            # Off uv for the resolver's binary, which runs unverified and with no
            # version read: the uv probe's answer names another environment. A
            # re-validation already on a direct route keeps the record that route
            # made.
            _record_direct_route_version(self, None)
        self.use_uv_tool = resolved[:1] == ["uv"]
        self.dependencies_satisfied = True
        return True

    def _accept_binary_on_path(self, resolved: List[str]) -> bool:
        """Whether the checkov the resolver found with no uv may run the scan.

        Without uv there is no install to fall back on, so the binary on PATH is
        the scan's checkov: it is verified against the scan's version constraint
        as ``_select_tool_execution`` verifies one. Before this it was declared
        satisfied unverified. One that falls short is MISSING with the reason;
        one that cannot be verified runs, with a warning.
        """
        from automated_security_helper.utils.pre_installed_tool import (
            verify_pre_installed_tool,
        )

        if resolved[:1] == ["uv"]:
            _restore_uv_route(self)
            self.use_uv_tool = True
            self.dependencies_satisfied = True
            return True
        executable = resolved[0]
        checked = verify_pre_installed_tool(
            executable,
            tool_name(self),
            None,
            self._get_tool_version_constraint(),
            uv_executable=None,
            values=self._values_to_redact(),
        )
        if checked.status == "unsatisfied":
            reason = (
                f"uv is not installed and the checkov on PATH ({executable}) "
                f"cannot be used: {checked.detail}"
            )
            self.dependency_unavailable_reason = reason
            self._plugin_log(reason, level=logging.ERROR)
            self.dependencies_satisfied = False
            return False
        if checked.status != "satisfied":
            self._plugin_log(
                f"uv is not installed and the checkov on PATH ({executable}) "
                f"could not be verified against the scan's requirement "
                f"({checked.detail}); running it anyway.",
                level=logging.WARNING,
            )
        _record_direct_route_version(self, getattr(checked, "version", None))
        self.use_uv_tool = False
        self.dependencies_satisfied = True
        return True

    @staticmethod
    def _config_file_values(config_file: str) -> dict[str, Any]:
        """The operator's checkov config file as a mapping, or {} when it cannot
        be read as one.

        checkov takes a value given on the command line over the file's
        (configargparse), and ASH always passes ``--framework`` and
        ``--skip-path`` values, so a ``framework`` or ``skip-path`` the operator
        put in the file was silently overridden. ``_process_config_options``
        reads the two keys here and folds them into the command line. A file
        that cannot be parsed changes nothing: checkov reads it itself and
        reports it.
        """
        try:
            with open(config_file, encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
            ASH_LOGGER.debug(
                f"Could not read the checkov config file {config_file} for its "
                f"framework and skip-path values: {error}",
                extra=NO_MARKUP,
            )
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def _process_config_options(self):
        # Checkov config path
        configured_file = self.config.options.config_file
        if configured_file is not None and not str(configured_file).strip():
            # "" or whitespace resolved to the source directory itself, which
            # exists, so the discovery stopped there and a directory was handed
            # to checkov as its config file.
            ASH_LOGGER.warning(
                "Ignoring an empty scanners.checkov.options.config_file: it names "
                "no file. Checkov runs without a config file; no config file is "
                "discovered from the scanned tree in its place."
            )
            configured_file = None
        possible_config_paths = [
            item
            for item in [
                configured_file,
                ".checkov.yaml",
                ".ash/.checkov.yaml",
                ".checkov.yml",
                ".ash/.checkov.yml",
            ]
            if item is not None
        ]

        # Resolve config candidates against source_dir, not the process working
        # directory, and hand checkov an absolute path.
        #
        # The subprocess runs with cwd=context.source_dir (see
        # PluginBase._run_subprocess), so probing with a bare Path(...).exists()
        # asked a different question than the one checkov would answer: it tested
        # the directory ASH happens to be invoked from. When that directory was
        # ASH's own checkout, the probe matched ASH's ".ash/.checkov.yaml" and
        # passed it through get_shortest_name, which relativises against the
        # process cwd. checkov then could not open it, wrote no SARIF, and the
        # scanner reported ERROR with zero findings.
        #
        # This used to line up by accident: the pre-decomposition run_ash_scan
        # chdir'd the whole process into source_dir, so process cwd and subprocess
        # cwd were the same directory. Resolving explicitly keeps the behaviour
        # correct without a global chdir, which also matters for scanning several
        # projects in one process.
        source_dir = Path(self.context.source_dir)
        context_config = getattr(self.context, "config", None)
        file_values: dict = {}
        for index, conf_path in enumerate(possible_config_paths):
            configured = index == 0 and configured_file is not None
            if not resolved_path(conf_path, source_dir).exists():
                if configured:
                    # A configured file that does not exist takes no discovered
                    # replacement (config/path_trust.py, "Configured tool inputs
                    # that are refused or missing").
                    ASH_LOGGER.warning(
                        text_without_values(
                            f"Configured checkov config file does not exist: "
                            f"{conf_path}. Checkov will run without a config "
                            "file; no config file is discovered from the "
                            "scanned tree in its place.",
                            self._environment_values(),
                        )
                    )
                    break
                continue
            # A config file inside the scanned tree is not passed to checkov, and
            # neither is one the scan derived from the repository (under the
            # output or work directory) unless the operator's own configuration
            # names it; see config/path_trust.py. A candidate found by name is
            # the checkout's, never the operator's. The path passed is the one
            # that was checked.
            if configured:
                from automated_security_helper.config.operator_only_options import (
                    operator_wrote_value,
                )

                operator_written = operator_wrote_value(
                    context_config,
                    "scanner",
                    "checkov",
                    ("options", "config_file"),
                    conf_path,
                    config_from_context=self._config_from_context,
                )
            else:
                operator_written = False
            candidate = honored_path(
                conf_path,
                source_dir=source_dir,
                config=context_config,
                key="scanners.checkov.options.config_file"
                if configured
                else f"checkov config file {conf_path}",
                derived_dirs=derived_roots(self.context),
                operator_written=operator_written,
            )
            if candidate is not None:
                self.args.extra_args.append(
                    ToolExtraArg(key="--config-file", value=candidate.as_posix())
                )
                file_values = self._config_file_values(candidate.as_posix())
                break
            if configured:
                # Refused: the configured value takes no discovered
                # replacement; checkov runs without a config file.
                ASH_LOGGER.warning(
                    "Configured checkov config file was not used because it "
                    "is repository-influenced. Checkov will run without a "
                    "config file; no config file is discovered from the "
                    "scanned tree in its place."
                )
                break

        # --skip-download is decided per scan, in _execute_scan: the offline mode
        # is read at the moment it is asked (_scanner_offline), and this runs at
        # construction, so a scanner built before --offline took effect ran online.

        # The JSON report is always asked for: it is the only checkov report that
        # names the resource of each record (attach_checkov_resources).
        for item in dict.fromkeys([*self.config.options.additional_formats, "json"]):
            self.args.extra_args.append(ToolExtraArg(key="--output", value=item))
        # An empty list is read as checkov reads it, as all: checkov's parser gives
        # --framework no default, and its normalization sets ['all'] when none is
        # given (checkov 3.3.26 common/util/ext_argument_parser.py:248 and
        # main.py:248-250). So it is passed as all is, with the config file's
        # frameworks in its place and the VCS configuration frameworks left out
        # (below); passed as nothing, it ran all three.
        frameworks = list(self.config.options.frameworks) or ["all"]
        file_frameworks = file_values.get("framework")
        if isinstance(file_frameworks, str):
            file_frameworks = [file_frameworks]
        file_names_frameworks = (
            isinstance(file_frameworks, list)
            and bool(file_frameworks)
            and all(isinstance(item, str) for item in file_frameworks)
        )
        if frameworks == ["all"] and file_names_frameworks:
            # The option is at its default, or empty and read as it, and the
            # operator's file names the frameworks: the file's would have been
            # overridden by the default on the command line, so the file's are
            # passed instead.
            frameworks = list(file_frameworks)
        for item in frameworks:
            self.args.extra_args.append(ToolExtraArg(key="--framework", value=item))
        skip_frameworks: list[str] = list(self.config.options.skip_frameworks)
        file_skip_frameworks = file_values.get("skip-framework")
        if isinstance(file_skip_frameworks, str):
            file_skip_frameworks = [file_skip_frameworks]
        for item in (
            file_skip_frameworks if isinstance(file_skip_frameworks, list) else []
        ):
            # Passed on the command line too, since the command line's
            # --skip-framework list replaces the file's whole, and this scanner
            # passes one on almost every run (the VCS frameworks below).
            if isinstance(item, str) and item.strip() and item not in skip_frameworks:
                skip_frameworks.append(item)
        if "all" in frameworks:
            # Checkov's "all" includes VCS server-configuration frameworks that
            # audit remote server settings over the network rather than files in
            # the scanned tree. Skip them unless explicitly requested via
            # frameworks (or an external checkov config file's framework key),
            # including beside "all".
            for vcs_framework in _VCS_CONFIGURATION_FRAMEWORKS:
                if vcs_framework in frameworks or vcs_framework in skip_frameworks:
                    continue
                skip_frameworks.append(vcs_framework)
        for item in skip_frameworks:
            self.args.extra_args.append(
                ToolExtraArg(key="--skip-framework", value=item)
            )
        # The frameworks checkov reads are the command line's: it always names at
        # least one, since an empty list is passed as all (above).
        self._vcs_frameworks_run = _vcs_frameworks_that_run(frameworks, skip_frameworks)
        file_skips = file_values.get("skip-path")
        if isinstance(file_skips, str):
            file_skips = [file_skips]
        for item in file_skips if isinstance(file_skips, list) else []:
            # Passed on the command line too, since the command line's --skip-path
            # list replaces the file's whole.
            if isinstance(item, str) and item.strip():
                self.args.extra_args.append(
                    ToolExtraArg(key=f"--skip-path={item}", value=None)
                )

        # The KNOWN_IGNORE_PATHS directories get their values at this point of the
        # command line, where the fixed values used to be, but per scan: each value
        # starts with the scanned directory's path. _execute_scan puts them here
        # (_known_directory_skip_patterns), so checkov's module finder reads the
        # operator's skip_path values below in the state it always did.
        self._known_directory_skip_at = len(self.args.extra_args)

        for item in active_ignore_paths(
            self.config.options.skip_path, where="scanners.checkov.options.skip_path"
        ):
            if not str(item.path).strip():
                # "--skip-path=" matches every path, as a regex and as a substring,
                # so checkov would scan nothing and the scan would read as clean.
                ASH_LOGGER.warning(
                    f"Ignoring an empty scanners.checkov.options.skip_path entry "
                    f"(reason: {text_without_values(str(item.reason), self._environment_values())}): "
                    "an empty --skip-path would exclude every file.",
                    extra=NO_MARKUP,
                )
                continue
            # NO_MARKUP: the path and the reason are the config's text, and a
            # "[/" in either is a closing Rich tag that raises instead of printing.
            # Redacted: a configured value can come from the environment, and
            # ash.log keeps DEBUG lines under --debug.
            ASH_LOGGER.debug(
                text_without_values(
                    f"Path '{item.path}' excluded from {self.config.name} scan "
                    f"for reason: {item.reason}",
                    self._environment_values(),
                ),
                extra=NO_MARKUP,
            )
            self.args.extra_args.append(
                ToolExtraArg(
                    key=f"--skip-path={item.path}",
                    value=None,
                )
            )

        return super()._process_config_options()

    def _execute_scan(
        self,
        target: Path,
        target_type: TargetType,
        global_ignore_paths: List[IgnorePathWithReason],
    ):
        """Resolve final argv and results path for Checkov.

        Checkov writes results into a directory and chooses the filename;
        we point ``--output-file-path`` at the parent dir but read
        ``results_sarif.sarif`` from inside it.
        """
        # Absolute, because checkov runs from the filesystem root
        # (_subprocess_cwd), where a relative path names something else.
        target = Path(os.path.abspath(target))
        self._checkov_target = target
        target_results_dir = Path(
            os.path.abspath(self.results_dir.joinpath(target_type))
        )
        if "," in str(target_results_dir):
            # checkov splits --output-file-path on commas into one path per
            # output format, so a results directory holding one is written
            # outside the results directory, possibly over an existing file.
            raise ScannerError(
                f"Not running checkov: its results directory "
                f"{target_results_dir.as_posix()} holds a comma, which checkov "
                "reads as a separator between per-format output paths. Use an "
                "--output-dir without a comma."
            )
        results_file = target_results_dir.joinpath("results_sarif.sarif")
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A previous run into the same directory left its reports; a checkov
        # that fails before writing would leave them to be read as this run's.
        for stale in (results_file, results_file.parent / "results_json.json"):
            try:
                stale.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                ASH_LOGGER.debug(
                    f"Could not remove the previous {stale.name}: {error}",
                    extra=NO_MARKUP,
                )

        # Added for this resolution only and then removed, as bandit does with its
        # excluded paths: the pattern depends on the target, and extra_args
        # persists across scan() calls. A new list: the one extra_args holds is
        # put back as it was, unchanged.
        original_extra_args = self.args.extra_args
        # The known-directory values go where _process_config_options left room for
        # them: after the skip-path values of the operator's checkov config file
        # and before the operator's skip_path. checkov's terraform module finder
        # joins every value into one regex (_module_finder_compiles), and the values
        # before an operator's value decide how it is read there; these leave it as
        # the fixed values they replaced did (_known_directory_skip_values).
        split = min(self._known_directory_skip_at or 0, len(original_extra_args))
        before, after = original_extra_args[:split], original_extra_args[split:]
        known = self._known_directory_skip_patterns(target)
        # In the order checkov is given them, which is the order the module finder
        # joins them in.
        given = [*_given_skip_paths(before), *known, *_given_skip_paths(after)]
        # checkov's terraform module finder fails the whole terraform scan when it
        # cannot compile its regex. The known-directory values compile wherever they
        # sit (_skip_path_text), so when the list does not, the operator's own
        # values are the cause and are named: before this the refusal always blamed
        # a link, and ran even when there was no link.
        if not _module_finder_compiles(given):
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: the "
                "scanners.checkov.options.skip_path values, joined as checkov's "
                "terraform module finder joins them, do not compile as a regular "
                "expression, so checkov's terraform scan would fail. Balance the "
                "parentheses and brackets in them."
            )
        skips: List[str] = []
        for value in self._output_dir_skip_patterns(target):
            # An output directory ASH drops findings under anyway: left out of
            # --skip-path, with a note, rather than refusing the target.
            if _module_finder_compiles([*given, *skips, value]):
                skips.append(value)
                continue
            ASH_LOGGER.warning(
                f"Not excluding ASH's output directory from checkov with "
                f"{value!r}: with it, checkov's terraform module finder cannot "
                "compile its regex. ASH drops checkov's findings there.",
                extra=NO_MARKUP,
            )
        # A link under a known directory needs a value of its own unless this scan
        # sends the values that skip that directory whole, which it does not on
        # Windows.
        link_paths = self._links_leaving_tree(
            target, known_directories_skipped=bool(known)
        )
        links = self._link_skip_patterns(target, link_paths)
        # A link has to be left out, so a target whose link values break the
        # module finder is not scanned; an ignored path is only left out of
        # --skip-path, as ASH drops checkov's findings there anyway.
        if links and not _module_finder_compiles([*given, *skips, *links]):
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: "
                f"{_link_named_in_refusal(target, link_paths)!r}: "
                f"{REASON_LINK_LEAVES_TREE}, "
                "and the --skip-path values that would leave such links out fail "
                "checkov's terraform scan, so checkov would read the file it points at."
            )
        skips.extend(links)
        offline = self._scanner_offline()
        if offline:
            # Decided here, per scan, for the reason _process_config_options gives.
            skips_offline = [ToolExtraArg(key="--skip-download", value="")]
            ASH_LOGGER.info(
                "Running Checkov in offline mode - policy downloads disabled"
            )
        else:
            skips_offline = []
        # Directory entries (ending in "/") first: one of them keeps checkov out of
        # a whole tree for a few characters, where per-file entries use the budget
        # up one file at a time; a stable sort keeps each group's own order.
        ignored = sorted(
            self._ignore_skip_patterns(target, global_ignore_paths),
            key=lambda value: not value.endswith("/"),
        )
        budgeted: List[str] = []
        used = 0
        for value in ignored:
            used += len(value) + len("--skip-path") + 2
            if used > _IGNORE_SKIP_PATH_CHAR_BUDGET:
                # WARNING, not DEBUG: paths are often ignored because checkov
                # chokes on them, so a cut here can come back as a stall or a
                # finding in an ignored file with no visible cause.
                ASH_LOGGER.warning(
                    f"Not passing {len(ignored) - len(budgeted)} of {len(ignored)} "
                    "ignored paths to checkov --skip-path: together they take more "
                    f"than {_IGNORE_SKIP_PATH_CHAR_BUDGET} characters of command "
                    "line. checkov still reads those files; ASH drops its findings "
                    "there.",
                    extra=NO_MARKUP,
                )
                break
            budgeted.append(value)
        # One compile over the whole list first: compiling once per value over the
        # accumulated list was quadratic in the number of ignored files, before
        # the tool started and outside its timeout. Only when the whole list fails
        # is each value tried on its own, to find the ones that break it.
        if _module_finder_compiles([*given, *skips, *budgeted]):
            skips.extend(budgeted)
            budgeted = []
        for value in budgeted:
            if _module_finder_compiles([*given, *skips, value]):
                skips.append(value)
                continue
            ASH_LOGGER.debug(
                f"Not passing ignored path {value!r} to checkov --skip-path: with it, "
                "checkov's terraform module finder cannot compile its regex. ASH "
                "drops checkov's findings there.",
                extra=NO_MARKUP,
            )
        self.args.extra_args = [
            *before,
            *(ToolExtraArg(key="--skip-path", value=value) for value in known),
            *after,
            *skips_offline,
            *(ToolExtraArg(key="--skip-path", value=skip) for skip in skips),
        ]
        try:
            final_args = self._resolve_arguments(
                target=target,
                # We want to use the parent here, not the results_file, as Checkov is expecting the output
                # directory and not the file name.
                results_file=target_results_dir,
            )
        finally:
            self.args.extra_args = original_extra_args
        # The environment checkov runs with: the host's, with a conf directory
        # below the results directory for each VCS configuration framework whose
        # variable the operator did not set. One read of the host's environment
        # decides both which directories are ASH's and what checkov inherits.
        subprocess_env = snapshot_environ()
        ash_named = _ash_named_vcs_conf_dirs(target_results_dir, subprocess_env)
        self._remove_earlier_vcs_conf(
            target_results_dir.joinpath(_VCS_CONF_ROOT_NAME), ash_named.values()
        )
        subprocess_env.update(
            (variable, str(conf_dir)) for variable, conf_dir in ash_named.items()
        )
        # checkov reads each VCS configuration framework's API token when it
        # starts, whether or not the framework runs (checkov_vcs_frameworks has the
        # measurements), so a token it cannot use is not handed to it: offline,
        # where nothing is fetched, or for a framework that does not run.
        kept = _without_unused_vcs_tokens(
            subprocess_env, self._vcs_frameworks_run, offline
        )
        left_out = {name.upper() for name in subprocess_env if name not in kept}
        for framework, variable in _CHECKOV_VCS_TOKEN_ENV.items():
            if variable.upper() in left_out:
                ASH_LOGGER.debug(
                    f"Not passing {variable} to checkov: its {framework} framework "
                    + (
                        "fetches nothing in an offline scan."
                        if offline
                        else "does not run in this scan."
                    )
                )
        subprocess_env = kept
        if offline:
            # The VCS configuration frameworks fetch remote platform settings
            # over the network; an offline scan turns those fetches off even
            # when the operator enabled such a framework explicitly.
            for fetch_var in _VCS_CONFIG_FETCH_ENV_VARS:
                subprocess_env[fetch_var] = "False"
            self._warn_offline_vcs_frameworks(ash_named)
        return _directory_as_one_token(final_args), results_file, subprocess_env

    def _remove_earlier_vcs_conf(
        self, conf_root: Path, conf_dirs: Iterable[Path]
    ) -> None:
        """Remove what an earlier run left in the conf directories ASH names.

        checkov's GitLab and Bitbucket frameworks check the files their directory
        holds, and write one only when its fetch returns data (``persist_all_confs``
        and the ``persist_*`` methods it calls; each runner scans the directory
        after them; read at checkov 3.3.26). So a file an earlier run fetched was
        checked again and reported as this scan's: in an offline scan, which
        fetches nothing, and online when a fetch returns nothing. GitHub's
        framework removes its own directory. A directory the operator named is
        not passed here and is left as it is.

        Nothing is removed through a link: a ``vcs-config`` or conf directory that
        is a link, or a file in the place of one, is removed itself.
        """
        conf_dirs = list(conf_dirs)
        if not conf_dirs:
            return
        if conf_root.is_symlink() or (conf_root.exists() and not conf_root.is_dir()):
            # Every directory ASH names is below it, so removing it removes them.
            conf_dirs = [conf_root]
        for conf_dir in conf_dirs:
            try:
                if conf_dir.is_symlink() or not conf_dir.is_dir():
                    conf_dir.unlink(missing_ok=True)
                else:
                    shutil.rmtree(conf_dir)
            except OSError as error:
                ASH_LOGGER.warning(
                    "Could not remove what an earlier checkov run left in a VCS "
                    "configuration framework's conf directory: "
                    f"{error_text(error, self._environment_values())}. That "
                    "framework may report those settings as this scan's.",
                    extra=NO_MARKUP,
                )

    def _warn_offline_vcs_frameworks(self, ash_named: Mapping[str, Path]) -> None:
        """Say what each VCS configuration framework that runs reads offline.

        An offline scan turns its fetch of the repository host's settings off
        (``_VCS_CONFIG_FETCH_ENV_VARS``), so the framework checks only the files
        already in its conf directory. The scan said nothing about it, and the
        framework read as clean on an empty directory, or reported an earlier
        run's settings as current on one that held them.
        """
        for framework in self._vcs_frameworks_run:
            ((variable, _),) = checkov_vcs_frameworks.vcs_conf_dir_env_vars(
                (framework,)
            )
            if variable in ash_named:
                ASH_LOGGER.warning(
                    f"checkov's {framework} framework runs in this offline scan, "
                    "which does not fetch the repository host's settings it "
                    "checks, so it reports nothing: ASH empties the directory it "
                    f"reads ({variable}, below the results directory) before "
                    "each run. Run online to check those settings, or set "
                    f"{variable} to a directory of settings fetched earlier."
                )
            else:
                ASH_LOGGER.warning(
                    f"checkov's {framework} framework runs in this offline scan, "
                    "which does not fetch the repository host's settings it "
                    "checks: it checks the files already in the directory "
                    f"{variable} names, which may be older than this scan."
                )

    def _known_directory_skip_patterns(self, target: Path) -> List[str]:
        """The ``--skip-path`` values that skip the ``KNOWN_IGNORE_PATHS`` directories
        below ``target`` (``_known_directory_skip_values``), or none on Windows.

        None on Windows, where checkov's walked paths are not ``/``-joined, as for
        ``_ignore_skip_patterns`` and ``_output_dir_skip_patterns``; checkov's own
        rules still skip directories named ``node_modules`` and, by default,
        dot-named ones on every platform (``CKV_IGNORED_DIRECTORIES`` and
        ``CKV_IGNORE_HIDDEN_DIRECTORIES``). ``_execute_scan`` tells
        ``_links_leaving_tree`` whether any are sent.
        """
        if os.sep != "/":
            # checkov joins walked paths with os.sep, so on Windows the values
            # would have to carry backslashes, which are regex escapes to the
            # re.search half of its match and to the module finder's joined regex.
            ASH_LOGGER.debug(
                "Not excluding the .venv, venv and node_modules directories from "
                "checkov on Windows; add them to scanners.checkov.options.skip_path "
                "if needed."
            )
            return []
        return _known_directory_skip_values(_skip_path_root(target))

    def _ignore_skip_patterns(
        self, target: Path, global_ignore_paths: List[IgnorePathWithReason] | None
    ) -> List[str]:
        """One ``--skip-path`` for each path the global ignore paths ignore.

        The paths come from ``ignored_entries``, which matches each pattern as ASH
        does when it drops findings. A file is written as a link's path is
        (``_link_skip_patterns``): anchored at both ends, so it matches that file
        alone. A directory whose every file is ignored is anchored at the start and
        ends with ``/``, so it matches every path below it and not a sibling that
        shares its name's start. ``_execute_scan`` leaves out of ``--skip-path`` a
        value that would make checkov's terraform module finder fail to compile its
        regex (``_module_finder_compiles``); checkov then reads that path, and ASH
        drops its findings. None on Windows, where checkov's walked paths are not
        ``/``-joined.
        """
        if os.sep != "/" or not global_ignore_paths:
            return []
        files, _ = walked_files(target)
        entries = ignored_entries(
            target, self.context.source_dir, global_ignore_paths, files
        )
        root = _skip_path_root(target)
        escaped_dot = "\\."
        patterns = []
        for entry in entries:
            literal = re.escape(f"{root}/{entry}").replace(escaped_dot, "[.]")
            patterns.append("^" + literal + ("" if entry.endswith("/") else "$"))
        return patterns

    @staticmethod
    def _links_leaving_tree(
        target: Path, *, known_directories_skipped: bool
    ) -> List[str]:
        """The links to files whose target leaves ``target``, as checkov walks them.

        With ``known_directories_skipped``, less the ones under a directory
        ``KNOWN_IGNORE_PATHS`` names: checkov is then told to skip those directories
        whole (``_known_directory_skip_patterns``), so a value per link there only
        lengthened the command line (a ``node_modules`` with thousands of links
        reached the argument-list limit). That holds only for a scan that sends the
        known-directory values, which one on Windows does not, so the caller says
        which it is. Without them every link is returned and gets a value of its own
        (``_link_skip_patterns``) or refuses the target, so checkov reads no file a
        link points at outside the tree.
        """
        links = file_links_leaving_tree(target)
        if not known_directories_skipped:
            return list(links)
        return [
            relative for relative in links if not _under_a_known_ignore_path(relative)
        ]

    def _link_skip_patterns(
        self, target: Path, links: Optional[List[str]] = None
    ) -> List[str]:
        """One ``--skip-path`` for each link to a file whose target leaves ``target``.

        ``links`` is the list ``_links_leaving_tree`` found, when the caller
        already walked the tree; without it the walk runs here.

        checkov 3.3.26 reads a link to a file in directory mode, relative or
        absolute, and reports it at the link's path (measured), so a link the
        repository committed would have checkov read a file outside the scanned tree.
        The links come from ``file_links_leaving_tree``, which walks as checkov
        does: it does not descend links to directories, and it ignores ignore files.

        Built here, for links ASH found, and kept apart from the operator's
        ``skip_path`` values, which are passed as they are: each is the link's path
        as checkov walks it (the ``--directory`` value joined with the link's path
        below it), ``re.escape``d and anchored at both ends, so it matches that path
        and no other -- ``a/main.tf`` does not also skip ``a/main.tf.json``. checkov
        applies a value with ``re.search`` and as a substring, and the substring
        test cannot match a path either, since the value starts with ``^``. Escaped
        values with parentheses, brackets, braces, spaces, commas, quotes and
        ``? * + | $ ^ #`` were measured against checkov 3.3.26, including the regex
        its Terraform module finder builds from every value: each skipped exactly
        its own link.

        Every dot is ``[.]``, not ``\\.``: checkov's secrets runner, with
        --enable-secret-scan-all-files (or CKV_SECRETS_SCAN_ENABLE_ALL), compiles
        each value after replacing ``.terraform`` with ``\\.terraform``
        (``checkov/secrets/utils.py`` ``filter_excluded_paths``), which would turn
        an escaped ``\\.terraform`` into ``\\\\.terraform``, and that matches no path.

        checkov's terraform module finder joins every ``--skip-path`` into one
        regex a character at a time (``_module_finder_compiles``), and the ``]`` of
        a ``[.]`` can turn a later unmatched parenthesis into an open group of that
        regex: measured with checkov 3.3.26's expression, the values for ``x.tf``
        and ``a(b.tf`` together fail to compile, and with them the whole terraform
        scan, while ``x.tf`` and ``l (1).tf`` compile. ``_execute_scan`` refuses
        the target when the values do not compile.

        Raises:
            ScannerError: When there is such a link and checkov's walked paths use
                a separator other than ``/`` (Windows), where the values cannot
                match them. checkov is then not run on ``target``, rather than read
                the file the link points at.
        """
        if links is None:
            links = self._links_leaving_tree(
                target,
                known_directories_skipped=bool(
                    self._known_directory_skip_patterns(target)
                ),
            )
        if not links:
            return []
        if os.sep != "/":
            raise ScannerError(
                f"Not running checkov on {Path(target).as_posix()}: {links[0]!r}: "
                f"{REASON_LINK_LEAVES_TREE}, and checkov's --skip-path cannot leave "
                "out a single file on this platform, so checkov would read the file "
                "it points at."
            )
        root = _skip_path_root(target)
        # Every dot as "[.]", not "\.": checkov's secrets runner, with
        # --enable-secret-scan-all-files (or CKV_SECRETS_SCAN_ENABLE_ALL), compiles
        # each value after replacing ".terraform" with "\.terraform"
        # (checkov/secrets/utils.py filter_excluded_paths), which would turn an
        # escaped "\.terraform" into "\\.terraform", and that matches no path.
        escaped_dot = "\\."
        return [
            "^" + re.escape(f"{root}/{relative}").replace(escaped_dot, "[.]") + "$"
            for relative in links
        ]

    def _subprocess_cwd(self, results_dir: Path) -> Path | None:
        """Run checkov from the filesystem root, outside the scanned tree.

        checkov reads ``.checkov.yaml`` and ``.checkov.yml`` from its working
        directory as default config files, whatever ``--config-file`` says
        (``checkov.common.util.config_utils.get_default_config_paths``), so the
        source directory is not usable. A directory under the results directory
        is not either: when the output directory is inside the source directory,
        checkov's paths relative to it drop their ``..`` components and can no
        longer be told apart. Every path relative to the root is absolute, so
        ``rewrite_checkov_paths`` recovers the source-relative form exactly.
        """
        chosen = cwd_outside_scanned_tree(
            self._scanned_target(),
            results_dir=results_dir,
            source_dir=self.context.source_dir,
            config=getattr(self.context, "config", None),
        )
        # Kept for _read_results_file: the directory is usually the root, but
        # cwd_outside_scanned_tree makes another when the root is inside the
        # tree, and the paths checkov writes are relative to the one it ran in.
        self._checkov_cwd = Path(chosen) if chosen is not None else None
        return chosen

    def _scanned_target(self) -> Path:
        """The target of the scan in progress, or the source directory."""
        return self._checkov_target or Path(os.path.abspath(self.context.source_dir))

    def _read_results_file(self, results_file: Path) -> Optional[dict[str, Any]]:
        """Read checkov's SARIF with its paths made relative to the source directory.

        The JSON report checkov always writes is rewritten the same way, whatever
        ``additional_formats`` lists, so it matches. CycloneDX
        carries no such path. Each result is first given the resource the JSON
        report names for it (:func:`attach_checkov_resources`).
        """
        target = self._scanned_target()
        # The directory checkov ran in (_subprocess_cwd): the root, unless that
        # lies inside the tree and another directory was made. Read as the
        # root always, the paths of such a run were rebuilt against the wrong base.
        ran_in = (
            self._checkov_cwd.as_posix()
            if self._checkov_cwd is not None
            else Path(target).anchor
        )
        source_dir = os.path.abspath(self.context.source_dir)
        scanned_dirs = [target.as_posix(), Path(source_dir).as_posix()]
        json_report = Path(results_file).parent / "results_json.json"
        resources: dict[_RecordKey, List[Optional[str]]] = {}
        guidelines: dict[_RecordKey, List[Optional[str]]] = {}
        if json_report.is_file():
            try:
                with open(json_report, encoding="utf-8") as handle:
                    document = json.load(handle)
                # Before the paths are rewritten: the keys are checkov's spelling.
                # Each read has its own guard: a failure reading the resources
                # or the guidelines costs only those, never the rewrite below.
                try:
                    resources = checkov_resources(document)
                except (TypeError, ValueError, RuntimeError) as error:
                    ASH_LOGGER.warning(
                        f"Could not read the resources in {json_report}: {error}. "
                        "Its results name no resource.",
                        extra=NO_MARKUP,
                    )
                try:
                    guidelines = checkov_guidelines(document)
                except (TypeError, ValueError, RuntimeError) as error:
                    ASH_LOGGER.warning(
                        f"Could not read the guidelines in {json_report}: {error}. "
                        "Its results carry no guideline.",
                        extra=NO_MARKUP,
                    )
                # Always: checkov writes this report whatever additional_formats
                # lists, so leaving it unrewritten would leave a file in the
                # output directory whose paths no longer match the SARIF.
                rewrite_checkov_paths(
                    document,
                    ran_in=ran_in,
                    source_dir=source_dir,
                    scanned_dirs=scanned_dirs,
                )
                # Staged beside it under the write guard and renamed into place
                # when the block ends: a failure while writing (disk full) left a
                # truncated report under the name, where the reporters read it as
                # damaged output. The guard's atomic form does the staging, the
                # rename and the cleanup on a raise, so no rename of its own is
                # made here (every write below an output directory goes through
                # fs_guard, which the output-writers audit checks).
                with open_for_atomic_write(json_report) as handle:
                    json.dump(document, handle, indent=4)
            except (OSError, ValueError) as error:
                # A WARNING, not DEBUG: the report is left with checkov's
                # root-relative paths, which no suppression matches, and its
                # findings get no ash_resource_id, so suppressions scoped to a
                # resource stop matching and the findings they hid come back.
                ASH_LOGGER.warning(
                    f"Could not rewrite the paths in {json_report}: {error}. "
                    "Its paths stay as checkov wrote them, and its findings "
                    "carry no resource id, so suppressions scoped to a "
                    "resource no longer match them.",
                    extra=NO_MARKUP,
                )
        raw = super()._read_results_file(results_file)
        if raw is not None:
            attach_checkov_resources(raw, resources)
            attach_checkov_guidelines(raw, guidelines)
            rewrite_checkov_paths(
                raw,
                ran_in=ran_in,
                source_dir=source_dir,
                scanned_dirs=scanned_dirs,
                scanned_files=self._scan_set,
            )
        return raw

    def _scan_set(self) -> List[str]:
        """The run's scan set, for names checkov rewrote (see rewrite_checkov_paths)."""
        from automated_security_helper.utils.scan_output_dirs import scan_set_of

        return scan_set_of(self.context)

    def _output_dir_skip_patterns(self, target: Path) -> List[str]:
        """``--skip-path`` values matching each ASH output directory under ``target``.

        Why: Checkov is given the whole directory, and ``--framework all``
        includes parsers (openapi, generic JSON/YAML) that read report files. A
        report it cannot read can stall the run until the scan timeout kills it
        (#628). Checkov already skips hidden directories, so the default
        ``.ash/ash_output`` was safe, but ``--output-dir`` pointed at a visible
        directory inside the source -- common in CI -- was scanned, and so was the
        ``.ash/ash_output`` of an earlier run when ``--output-dir`` moved this one.

        Checkov tests each value both as a regex (``re.search``) and as a
        substring against ``os.path.join(root, name)``, where ``root`` comes from
        walking the ``--directory`` value as given. So each value is an output
        directory spelled from that same string, with a trailing ``/`` so ``out``
        does not also skip ``outer/``, and ``re.escape``d
        (``utils/scan_output_dirs.escape_for_pattern``): unescaped, ``out.1/``
        also skipped ``outx1/``, ``out+1/`` also skipped ``out1/`` and
        ``outt1/``, and ``out|q/`` skipped every directory. Measured by calling
        checkov 3.3.26's ``filter_ignored_paths`` the way its runners walk a tree.

        Anchored at the start with ``^`` (unanchored, the value also skipped a
        deeper path holding the same text), not grouped, and a path holding ``(``
        or ``)`` is not emitted at all; the warning names ``skip_path`` instead.
        Checkov's terraform
        module finder joins every ``--skip-path`` value into one regex a character
        at a time (``'|'.join(f"({excluded_paths})")`` in ``module_finder.py``),
        which separates each escape from the character it escapes. Measured on
        3.3.26 with every printable character in an escaped value: none breaks
        that regex alone, a ``]`` followed by an unmatched parenthesis does, and
        so does an unmatched parenthesis after a user ``skip_path`` holding
        ``]``; it then fails the whole terraform scan. ASH leaves out every path
        with a parenthesis instead of working out whether it is matched.

        A path holding ``.terraform`` matches nothing in the secrets runner, which
        rewrites ``.terraform`` in each value to ``\\.terraform`` and so turns the
        escape into a literal backslash (measured on 3.3.26; the bicep and
        terraform-json runners apply the same rewrite). Those runners then read the
        directory, and ASH drops their findings there.

        Nothing is emitted on Windows, where checkov's walked paths use ``\\``.
        Findings checkov reports there anyway are dropped after the scan.
        """
        from automated_security_helper.utils.scan_output_dirs import (
            PatternSyntax,
            escape_for_pattern,
        )

        options = getattr(self.config, "options", None)
        if not getattr(options, "skip_ash_output_dir", True):
            return []
        scanner_name = getattr(self.config, "name", "checkov")
        relatives = self._ash_output_dirs_inside(target)
        if not relatives:
            return []
        if os.sep != "/":
            # checkov joins walked paths with os.sep, so on Windows the value
            # would have to carry backslashes, which are regex escapes to the
            # re.search half of its match and to the module finder's joined
            # regex. checkov documents --skip-path as unreliable on Windows
            # (the TODO in filter_ignored_paths); leave the previous behavior.
            ASH_LOGGER.debug(
                f"Not excluding ASH's output directories from {scanner_name} on "
                "Windows; add them to scanners.checkov.options.skip_path if needed."
            )
            return []
        patterns = []
        for relative in relatives:
            output_path = f"{_skip_path_root(target)}/{relative.as_posix()}/"
            if _CHECKOV_UNSAFE_SKIP_PATH_CHARS & set(output_path):
                ASH_LOGGER.warning(
                    f"Not excluding ASH's output directory {output_path} from "
                    f"{scanner_name}: the path has characters checkov cannot take "
                    "in --skip-path. Add it to scanners.checkov.options.skip_path, "
                    "or move --output-dir outside the source directory.",
                    extra=NO_MARKUP,
                )
                continue
            ASH_LOGGER.debug(
                f"Path '{output_path}' excluded from {scanner_name} scan for "
                "reason: ASH output directory",
                extra=NO_MARKUP,
            )
            # Anchored at the start: unanchored, the value also skipped a deeper
            # path that holds the same text (a copy of the tree under itself).
            patterns.append("^" + escape_for_pattern(output_path, PatternSyntax.REGEX))
        return patterns
