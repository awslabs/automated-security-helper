# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every tool, image and Jenkins plugin the CI runners use is pinned.

WHY THIS EXISTS
---------------
The Docs CI Runners workflow downloads the runners (nektos/act, gitlab-ci-local,
Jenkinsfile Runner, the AWS CodeBuild local agent script, the CircleCI CLI), pulls the
images they run, and loads Jenkins plugins, on every run. Each comes from one committed
manifest, tests/integration/docs/ci_runners/runners.toml, and install_tools.py checks
every download against it. An entry without a sha256, a tag-only image, or a plugin
fetched through the update center's resolver would let a run use whatever those names
point at that day, so this file fails the manifest instead.

The manifest's format:

* ``[tools.<name>]``: ``version``, ``url`` (https), ``sha256`` (64 lowercase hex),
  ``license``, ``source`` (where the checksum came from), and ``executable``, the
  program to run, as a relative POSIX path inside the tool's install directory (for a
  file that is not an archive, its file name);
* ``[images.<name>]``: ``ref`` (``<name>@sha256:<64 hex>``, no tag), ``license`` (a
  license name, or "unknown"), ``source``; one of them is the Dockerfile's base image
  at its pinned digest;
* ``[jenkins.cores.lts]``: the current LTS WAR, ``war_url`` and ``war_sha256``, the
  ``java`` major version it runs on, and ``plugins = "jenkins/plugins-lts.toml"``;
* ``[jenkins.cores.bundled]``: the core Jenkinsfile Runner's release is built against,
  ``core_version``, ``java``, and ``plugins = "jenkins/plugins-bundled.toml"``.

Both cores carry ``core_version``, ``war_url`` (that version's WAR on get.jenkins.io),
``war_sha256``, ``java`` and ``plugins``: the release's zip holds the launcher only, so
the bundled core's WAR is pinned too.

Each plugins file is a full closure for its core: ``[[plugin]]`` entries with ``name``,
``version``, the exact ``.hpi`` ``url``, ``sha256`` and the ``dependencies`` that
version declares (the non-optional ones), each of which is itself an entry, or, for
the bundled core only, listed in a top-level ``bundled`` list of plugins the release
already ships. The release ships none, so that list is present and empty.

No url in the manifest, the plugins files or the two scripts is plain http.

WHAT THIS DOES NOT CHECK
------------------------
That a checksum is the right one for its URL: that needs the network, and each entry
says in ``source`` where its value was read. Nor that a plugin's ``dependencies`` are
the ones its version declares: they are taken as recorded when the closure was
resolved, and only checked against the closure here, not derived again.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
CI_RUNNERS = REPO_ROOT / "tests" / "integration" / "docs" / "ci_runners"
MANIFEST = CI_RUNNERS / "runners.toml"
CORES = ("lts", "bundled")
LEG_RUNNERS = (
    "act",
    "gitlab-ci-local",
    "jenkinsfile-runner-lts",
    "jenkinsfile-runner-bundled",
    "codebuild-agent",
    "circleci",
)
SHA256 = re.compile(r"[0-9a-f]{64}")
#: <registry host>/<path>@sha256:<digest>, or a Docker Hub <path>@sha256:<digest>; a tag
#: is not allowed, digest or not.
IMAGE_REF = re.compile(
    r"(?:[a-z0-9.-]+\.[a-z]{2,}(?::[0-9]+)?/)?[a-z0-9._-]+(?:/[a-z0-9._-]+)*"
    r"@sha256:[0-9a-f]{64}"
)
#: The plugins the docs' Jenkinsfile needs: a declarative pipeline (pipeline-model-
#: definition, on workflow-job and workflow-cps), its sh step (workflow-durable-task-step),
#: archiveArtifacts (a core step run through workflow-basic-steps) and junit.
PAGE_PLUGINS = (
    "pipeline-model-definition",
    "workflow-job",
    "workflow-cps",
    "workflow-durable-task-step",
    "workflow-basic-steps",
    "junit",
)
#: Jenkinsfile Runner's last release and the core it ships (its pom.xml at the tag:
#: jenkins.version 2.375.4, java.level 11).
JFR_RELEASE = "1.0-beta-32"
JFR_CORE = "2.375.4"
JFR_JAVA = "11"


def _rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _toml(path: Path) -> dict:
    if not path.is_file():
        pytest.fail(f"missing {_rel(path)}, a manifest of the CI runners' pins")
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _manifest() -> dict:
    """runners.toml, read in each test, so a missing file fails each test on its own."""
    return _toml(MANIFEST)


def _nonempty_str(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _https(url) -> bool:
    return (
        isinstance(url, str)
        and url.startswith("https://")
        and not re.search(r"\s", url)
    )


def _checks():
    """scripts/docs_checks.py, loaded by path under the name the docs tests share."""
    name = "_ash_docs_checks"
    if name not in sys.modules:
        if str(REPO_ROOT) not in sys.path:
            sys.path.insert(0, str(REPO_ROOT))
        spec = importlib.util.spec_from_file_location(
            name, REPO_ROOT / "scripts" / "docs_checks.py"
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


#: The url file names install_tools.py unpacks; any other file is installed as is.
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".zip")


def _relative_posix_path(value) -> bool:
    """A relative POSIX path, written plainly: no leading /, no .. or . segment, no
    empty segment, no backslash."""
    if not (isinstance(value, str) and value) or "\\" in value:
        return False
    return all(part not in ("", ".", "..") for part in value.split("/"))


def test_every_tool_is_pinned_by_sha256_to_an_https_url():
    tools = _manifest().get("tools")
    assert isinstance(tools, dict) and tools, (
        "runners.toml has no [tools.<name>] tables"
    )
    problems = []
    for name, entry in tools.items():
        if not _nonempty_str(entry.get("version")):
            problems.append(f"tools.{name}: no version")
        if not _https(entry.get("url")):
            problems.append(f"tools.{name}: url {entry.get('url')!r} is not https")
        if not (
            isinstance(entry.get("sha256"), str) and SHA256.fullmatch(entry["sha256"])
        ):
            problems.append(
                f"tools.{name}: sha256 {entry.get('sha256')!r} is not 64 lowercase hex"
            )
        for key in ("license", "source"):
            if not _nonempty_str(entry.get(key)):
                problems.append(f"tools.{name}: no {key}")
    assert not problems, problems


def test_every_tool_names_the_program_to_run_inside_its_install_dir():
    """install_tools.py installs each tool under <bin-dir>/<name>/ and checks that
    ``executable`` is there; the runners' launchers run that path."""
    for ok in (
        "act",
        "bin/jenkinsfile-runner",
        "circleci-cli_1.5.0_linux_amd64/circleci",
    ):
        assert _relative_posix_path(ok), ok
    for bad in (
        "",
        "/usr/bin/act",
        "../act",
        "bin/../act",
        "bin\\act",
        "bin//act",
        "./act",
    ):
        assert not _relative_posix_path(bad), bad
    tools = _manifest().get("tools")
    assert isinstance(tools, dict) and tools, (
        "runners.toml has no [tools.<name>] tables"
    )
    problems = []
    for name, entry in tools.items():
        executable = entry.get("executable")
        if not _relative_posix_path(executable):
            problems.append(
                f"tools.{name}: executable {executable!r} is not a relative POSIX path"
                " without .."
            )
            continue
        file_name = urlsplit(str(entry.get("url", ""))).path.rsplit("/", 1)[-1]
        if not file_name.endswith(ARCHIVE_SUFFIXES) and executable != file_name:
            problems.append(
                f"tools.{name}: {file_name} is installed as is, so its executable is"
                f" {file_name!r}, not {executable!r}"
            )
    assert not problems, problems


def test_every_image_is_pinned_by_digest():
    _the_image_reference_rule_refuses_every_tag()
    images = _manifest().get("images")
    assert isinstance(images, dict) and images, (
        "runners.toml has no [images.<name>] tables"
    )
    problems = []
    for name, entry in images.items():
        ref = entry.get("ref")
        if not (isinstance(ref, str) and IMAGE_REF.fullmatch(ref)):
            problems.append(
                f"images.{name}: ref {ref!r} is not <name>@sha256:<64 hex> with no tag"
            )
        for key in ("license", "source"):
            if not _nonempty_str(entry.get(key)):
                problems.append(f"images.{name}: no {key} (a license name or unknown)")
    assert not problems, problems


def _the_image_reference_rule_refuses_every_tag():
    """Control for the image rule, so it cannot pass a tag-only reference."""
    digest = "a" * 64
    for ok in (
        f"public.ecr.aws/docker/library/python@sha256:{digest}",
        f"circleci/picard@sha256:{digest}",
        f"docker.io/cimg/python@sha256:{digest}",
    ):
        assert IMAGE_REF.fullmatch(ok), ok
    for bad in (
        "python:3.12",
        "public.ecr.aws/docker/library/python:3.12",
        f"public.ecr.aws/docker/library/python:3.12@sha256:{digest}",
        f"cimg/python@sha256:{digest[:63]}",
        f"cimg/python@sha256:{digest.upper()}",
        "cimg/python",
    ):
        assert not IMAGE_REF.fullmatch(bad), bad


def _without_tag(image: str) -> str:
    """The image name without its tag. A tag follows the last /, so a registry port
    before it stays."""
    head, slash, last = image.rpartition("/")
    return head + slash + last.split(":", 1)[0]


def test_the_dockerfile_s_base_image_is_pinned_at_its_digest():
    """The CI image the GitLab pipeline builds from the repository's Dockerfile is built
    with --build-arg BASE_IMAGE=<base>@<digest>, and the allowlist check accepts that
    pull only if the manifest lists exactly that reference."""
    assert _without_tag("registry.example.com:5000/team/python:3.12") == (
        "registry.example.com:5000/team/python"
    )
    assert _without_tag("python:3.12-slim") == "python"
    assert _without_tag("public.ecr.aws/docker/library/python") == (
        "public.ecr.aws/docker/library/python"
    )
    defaults = _checks().dockerfile_arg_defaults(
        (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    )
    (base,) = defaults["BASE_IMAGE"]
    (digest,) = defaults["BASE_IMAGE_DIGEST"]
    assert isinstance(base, str) and isinstance(digest, str), (base, digest)
    expected = f"{_without_tag(base)}@{digest}"
    refs = [entry.get("ref") for entry in _manifest().get("images", {}).values()]
    assert expected in refs, (
        f"no [images.<name>] has ref {expected!r}, the Dockerfile's BASE_IMAGE at its"
        f" BASE_IMAGE_DIGEST; the manifest has {refs}"
    )


def test_the_lts_core_is_a_war_from_get_jenkins_io_pinned_by_sha256():
    core = _manifest().get("jenkins", {}).get("cores", {}).get("lts")
    assert isinstance(core, dict), "runners.toml has no [jenkins.cores.lts]"
    url = core.get("war_url")
    assert _https(url), url
    parts = urlsplit(url)
    assert parts.hostname == "get.jenkins.io", url
    assert re.fullmatch(r"/war-stable/\d+\.\d+\.\d+/jenkins\.war", parts.path), (
        f"{url} is not a war-stable (LTS) release's jenkins.war"
    )
    assert isinstance(core.get("war_sha256"), str) and SHA256.fullmatch(
        core["war_sha256"]
    )
    java = core.get("java")
    assert isinstance(java, str) and java.isdigit() and int(java) >= 17, java
    assert core.get("plugins") == "jenkins/plugins-lts.toml"


def test_the_bundled_core_is_the_one_jenkinsfile_runner_ships():
    manifest = _manifest()
    core = manifest.get("jenkins", {}).get("cores", {}).get("bundled")
    assert isinstance(core, dict), "runners.toml has no [jenkins.cores.bundled]"
    assert core.get("core_version") == JFR_CORE
    assert core.get("java") == JFR_JAVA
    assert core.get("plugins") == "jenkins/plugins-bundled.toml"
    runners = [
        entry
        for entry in manifest.get("tools", {}).values()
        if "jenkinsfile-runner" in str(entry.get("url", ""))
    ]
    assert [entry.get("version") for entry in runners] == [JFR_RELEASE], (
        "one Jenkinsfile Runner, its last release, whose core the bundled leg uses"
    )


@pytest.mark.parametrize("core", CORES)
def test_each_core_pins_its_own_war_by_version_and_sha256(core):
    """The release's zip holds the launcher only, so each core names its version and
    pins that version's WAR, and the url's version is the core's version."""
    entry = _manifest().get("jenkins", {}).get("cores", {}).get(core)
    assert isinstance(entry, dict), f"runners.toml has no [jenkins.cores.{core}]"
    keys = ("core_version", "war_url", "war_sha256", "java", "plugins")
    assert not [key for key in keys if key not in entry], (
        f"jenkins.cores.{core} lacks {[key for key in keys if key not in entry]}"
    )
    version = entry["core_version"]
    assert isinstance(version, str) and re.fullmatch(r"\d+\.\d+\.\d+", version), version
    assert (
        entry["war_url"] == f"https://get.jenkins.io/war-stable/{version}/jenkins.war"
    )
    assert isinstance(entry["war_sha256"], str) and SHA256.fullmatch(
        entry["war_sha256"]
    ), entry["war_sha256"]
    assert isinstance(entry["java"], str) and entry["java"].isdigit(), entry["java"]
    assert entry["plugins"] == f"jenkins/plugins-{core}.toml"


def _plugins(manifest: dict, core: str) -> tuple[list[dict], list[str], dict]:
    rel = manifest["jenkins"]["cores"][core]["plugins"]
    document = _toml(CI_RUNNERS / rel)
    entries = document.get("plugin")
    assert isinstance(entries, list) and entries, f"{rel} has no [[plugin]] entries"
    return entries, list(document.get("bundled", [])), document


@pytest.mark.parametrize("core", CORES)
def test_each_core_has_a_full_plugin_closure_of_exact_hpi_files(core):
    entries, bundled, document = _plugins(_manifest(), core)
    if core == "lts":
        assert "bundled" not in document, (
            "the LTS core is a bare WAR, so its closure lists every plugin it loads"
        )
    names = [entry.get("name") for entry in entries]
    assert len(names) == len(set(names)), f"a plugin is listed twice: {names}"
    available = set(names) | set(bundled)
    problems = []
    for entry in entries:
        name, version, url = entry.get("name"), entry.get("version"), entry.get("url")
        if not (_nonempty_str(name) and _nonempty_str(version)):
            problems.append(f"{entry}: needs name and version")
            continue
        if not _https(url):
            problems.append(f"{name}: url {url!r} is not https")
            continue
        parts = urlsplit(url)
        if (
            parts.hostname == "updates.jenkins.io"
            or "/latest/" in parts.path
            or parts.query
        ):
            problems.append(f"{name}: {url} goes through the update center's resolver")
        if not parts.path.endswith(f"/{name}/{version}/{name}.hpi"):
            problems.append(f"{name}: {url} is not the .hpi of {name} {version}")
        if not (
            isinstance(entry.get("sha256"), str) and SHA256.fullmatch(entry["sha256"])
        ):
            problems.append(f"{name}: sha256 is not 64 lowercase hex")
        dependencies = entry.get("dependencies")
        if not (
            isinstance(dependencies, list)
            and all(isinstance(d, str) for d in dependencies)
        ):
            problems.append(f"{name}: dependencies must be a list of plugin names")
            continue
        missing = sorted(set(dependencies) - available)
        if missing:
            problems.append(
                f"{name} {version} depends on {missing}, which the closure lacks"
            )
    for plugin in PAGE_PLUGINS:
        if plugin not in available:
            problems.append(
                f"the docs' Jenkinsfile needs {plugin}, which the closure lacks"
            )
    if "junit" not in names:
        problems.append(
            "junit is not in Jenkinsfile Runner's release, so it is an entry"
        )
    assert not problems, problems


def test_the_bundled_closure_says_the_release_ships_no_plugins():
    """The release's zip has no plugins, so the bundled file says so with an explicit,
    empty ``bundled`` list, and every plugin the core loads is an entry. The LTS file
    has no ``bundled`` key at all."""
    manifest = _manifest()
    _entries, _bundled, document = _plugins(manifest, "bundled")
    assert "bundled" in document and document["bundled"] == [], (
        f"plugins-bundled.toml needs bundled = [], not {document.get('bundled', '<absent>')!r}"
    )
    _entries, _bundled, lts = _plugins(manifest, "lts")
    assert "bundled" not in lts


# ---------------------------------------------------------------------------
# install_tools.py uses the manifest and nothing else
# ---------------------------------------------------------------------------


def _install_tools():
    path = CI_RUNNERS / "install_tools.py"
    if not path.is_file():
        pytest.fail(f"missing {_rel(path)}, which installs the pinned tools")
    name = "_ash_ci_runners_install_tools"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name], path


def test_install_tools_maps_every_leg_to_pins_in_the_manifest():
    manifest = _manifest()
    module, _ = _install_tools()
    pins = getattr(module, "RUNNER_PINS", None)
    assert isinstance(pins, dict), "install_tools.py defines no RUNNER_PINS"
    assert set(pins) == set(LEG_RUNNERS)

    def exists(key: str) -> bool:
        node = manifest
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return False
            node = node[part]
        return isinstance(node, dict)

    named = {key for keys in pins.values() for key in keys}
    assert all(exists(key) for key in named), sorted(k for k in named if not exists(k))
    every = {f"tools.{n}" for n in manifest.get("tools", {})}
    every |= {f"images.{n}" for n in manifest.get("images", {})}
    every |= {
        f"jenkins.cores.{c}" for c in manifest.get("jenkins", {}).get("cores", {})
    }
    assert every <= named, f"pins no leg uses: {sorted(every - named)}"
    assert "jenkins.cores.lts" in pins["jenkinsfile-runner-lts"]
    assert "jenkins.cores.bundled" in pins["jenkinsfile-runner-bundled"]


#: Strings that would mean resolving a plugin or a dependency at run time.
RESOLVERS = (
    "updates.jenkins.io",
    "update-center",
    "updatecenter",
    "repo.jenkins-ci.org",
    "maven",
    "mvn",
    "jenkins-plugin-manager",
)


def test_install_tools_resolves_nothing_at_run_time():
    """No string the code holds names the update center, a Maven repository, or the
    plugin manager, which resolves dependencies from the update center. Comments may."""
    _module, path = _install_tools()
    tree = ast.parse(path.read_text(encoding="utf-8"))
    # Docstrings and other bare string statements are prose, like comments.
    prose = {
        id(child.value)
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
        if isinstance(child, ast.Expr)
        and isinstance(child.value, ast.Constant)
        and isinstance(child.value.value, str)
    }
    strings = [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in prose
    ]
    found = sorted(
        {word for text in strings for word in RESOLVERS if word in text.lower()}
    )
    assert not found, f"install_tools.py holds {found}"


def _string_constants(path: Path) -> list[str]:
    """Every string constant in a Python file, docstrings and f-string parts included."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]


def test_no_url_the_runners_use_is_plain_http():
    """Every download is https. The pinned files are read whole, comments included;
    the two scripts by their string constants."""
    problems = []
    for path in (
        MANIFEST,
        CI_RUNNERS / "jenkins" / "plugins-lts.toml",
        CI_RUNNERS / "jenkins" / "plugins-bundled.toml",
    ):
        if not path.is_file():
            pytest.fail(f"missing {_rel(path)}")
        if "http://" in path.read_text(encoding="utf-8").lower():
            problems.append(f"{_rel(path)} has a plain http url")
    for stem in ("install_tools", "image_allowlist"):
        path = CI_RUNNERS / f"{stem}.py"
        if not path.is_file():
            pytest.fail(f"missing {_rel(path)}")
        found = [text for text in _string_constants(path) if "http://" in text.lower()]
        if found:
            problems.append(f"{_rel(path)} holds plain http in {found}")
    assert not problems, problems
