# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Install providers build commands; they run nothing and substitute nothing.

Covers the recognizer (a declared command parsed by exact shape), each provider's
mapping and refusal text, the selection rules of ``--providers`` (permission
boundary plus preference order, a refusal naming every provider tried), the
virtualenv helpers (file reads only) and the ``--binary-path`` validator (hashes the
file, never runs it).
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.utils import install_providers as ip
from automated_security_helper.utils.download_utils import (
    create_pinned_tool_install_command,
)
from tests.utils.stand_ins import write_stand_in

pytestmark = pytest.mark.unit


def _marker_program(directory: Path, name: str, marker: Path) -> Path:
    """A program named ``name`` that creates ``marker`` if it is ever started.

    In the form the host starts (``tests/utils/stand_ins.py``): the script on POSIX,
    a ``<name>.bat`` launcher for it on Windows, where a shebang script is no
    program. The path returned is the file a start names, the one a test forces.
    """
    source = f"open({str(marker)!r}, 'w').close()\n"
    return write_stand_in(directory, name, source).files[-1]


DEFAULT = ip.RouteContext(platform_name="linux", arch="amd64", bin_dir=Path("/x/bin"))
EXPLICIT = ip.RouteContext(
    platform_name="linux", arch="amd64", bin_dir=Path("/x/bin"), explicit=True
)
UV_TOOL = [
    "uv",
    "tool",
    "install",
    "--python",
    ">=3.10,<3.14",
    "--with",
    "dep>=1",
    "checkov>=3,<4",
]


def _tool(argv=None, tool="checkov"):
    return ip.classify_install_command(argv or UV_TOOL, False, tool)


def _argvs(route):
    return [list(command) for command in route.commands]


def test_recognizer_parses_python_request_and_with_dependencies_from_the_argv():
    request = _tool()

    assert request.kind == ip.CommandKind.PYTHON_TOOL
    assert request.spec == "checkov>=3,<4"
    assert request.runtime_request == ">=3.10,<3.14"
    assert request.with_dependencies == ("dep>=1",)


def test_recognizer_keeps_a_uv_shape_it_does_not_understand_opaque():
    request = _tool(["uv", "tool", "install", "--editable", "x", "y"])

    assert request.kind == ip.CommandKind.OPAQUE
    assert request.native_provider == "uv"


def test_recognizer_passes_apt_npm_gem_shell_and_pinned_commands_to_their_owners():
    pinned = list(
        create_pinned_tool_install_command("grype", "linux", "amd64", "/b").args
    )
    owners = {
        "apt": ip.classify_install_command(["apt-get", "install", "-y", "jq"]),
        "npm": ip.classify_install_command(["npm", "install", "-g", "x"]),
        "gem": ip.classify_install_command(["gem", "install", "cfn-nag"]),
        "custom": ip.classify_install_command(["echo $HOME"], True),
        "release-download": ip.classify_install_command(pinned, False, "grype"),
        "pip": ip.classify_install_command(
            [sys.executable, "-m", "pip", "install", "a"]
        ),
    }

    for owner, request in owners.items():
        assert request.native_provider == owner, (owner, request)
    assert owners["release-download"].tool == "grype"


@pytest.mark.parametrize(
    "argv",
    [
        UV_TOOL,
        ["apt-get", "install", "-y", "jq=1.7"],
        ["gem", "install", "cfn-nag"],
        ["npm", "install", "-g", "x@1"],
        [sys.executable, "-m", "pip", "install", "ash[sarif]"],
    ],
)
def test_the_default_route_rebuilds_the_declared_argv_byte_for_byte(argv):
    request = ip.classify_install_command(argv, False, "checkov")

    route = ip.route_install(request, ip.EnvOptions(), providers=None, context=DEFAULT)

    assert isinstance(route, ip.Route), route
    assert _argvs(route) == [argv]
    assert route.provider == request.native_provider
    assert route.skipped == ()


def test_pipx_maps_with_dependencies_to_inject_commands():
    request = ip.classify_install_command(
        ["uv", "tool", "install", "--python", "3.12", "--with", "dep>=1", "bandit>=1"],
        False,
        "bandit",
    )

    route = ip.route_install(
        request, ip.EnvOptions(), providers=["pipx"], context=EXPLICIT
    )

    assert _argvs(route) == [
        ["pipx", "install", "--python", "3.12", "bandit>=1"],
        ["pipx", "inject", "bandit", "dep>=1"],
    ]


def test_pipx_refuses_a_specifier_runtime_request_naming_the_capability():
    refused = ip.route_install(
        _tool(), ip.EnvOptions(), providers=["pipx"], context=EXPLICIT
    )

    assert isinstance(refused, ip.Refused)
    expected_reason = (
        "pipx does not support interpreter requests (an interpreter request "
        "given as a version range ('>=3.10,<3.14'); pipx --python takes an "
        "executable, a version or a path)"
    )
    assert refused.tried == (("pipx", expected_reason),)
    assert refused.text.endswith(
        "Nothing was installed for checkov; no provider outside the list was tried "
        "and none was substituted."
    )


def test_a_refusal_never_falls_back_to_another_provider():
    refused = ip.route_install(
        _tool(), ip.EnvOptions(), providers=["pipx", "cargo"], context=EXPLICIT
    )

    assert isinstance(refused, ip.Refused)
    assert [name for name, _ in refused.tried] == ["pipx", "cargo"]
    assert "uv" not in [name for name, _ in refused.tried]


def test_the_first_listed_capable_provider_wins_and_earlier_skips_are_kept():
    route = ip.route_install(
        _tool(), ip.EnvOptions(), providers=["pipx", "uv"], context=EXPLICIT
    )

    assert route.provider == "uv"
    assert [name for name, _ in route.skipped] == ["pipx"]
    assert _argvs(route) == [UV_TOOL]


def test_a_system_package_manager_builds_from_the_facet_row_with_its_caveat():
    route = ip.route_install(
        _tool(), ip.EnvOptions(), providers=["brew"], context=EXPLICIT
    )

    assert _argvs(route) == [["brew", "install", "checkov"]]
    assert route.caveats and "not the plugin's declared range" in route.caveats[0]


def _with_an_apt_row(monkeypatch):
    """A facet that names an apt package, which no shipped row does yet."""
    from automated_security_helper.base.install_package_facets import (
        EcosystemPackage,
        InstallPackageFacet,
    )

    facet = InstallPackageFacet(
        tool="jq-like",
        rows=(EcosystemPackage("apt", "jq", "distro packages lag"),),
        preference=("apt",),
    )
    monkeypatch.setattr(ip, "install_package_facet", lambda tool: facet)


def test_a_privileged_manager_refuses_when_the_run_is_not_root_and_adds_no_sudo(
    monkeypatch,
):
    _with_an_apt_row(monkeypatch)
    request = ip.classify_install_command(["gem", "install", "x"], False, "jq-like")

    refused = ip.route_install(
        request, ip.EnvOptions(), providers=["apt"], context=EXPLICIT
    )

    assert isinstance(refused, ip.Refused)
    assert "apt does not support unprivileged installs" in refused.text
    assert "ASH does not add sudo" in refused.text


def test_a_privileged_manager_with_a_row_builds_when_root(monkeypatch):
    _with_an_apt_row(monkeypatch)
    root = ip.RouteContext(
        platform_name="linux", arch="amd64", bin_dir=None, is_root=True, explicit=True
    )
    request = ip.classify_install_command(["gem", "install", "x"], False, "jq-like")

    route = ip.route_install(request, ip.EnvOptions(), providers=["apt"], context=root)

    assert _argvs(route) == [["apt-get", "install", "-y", "jq"]]
    assert route.caveats == ("distro packages lag",)


def test_a_manager_with_no_row_for_the_tool_is_refused_naming_the_missing_row():
    request = ip.classify_install_command(
        ["gem", "install", "x"], False, "unknown-tool"
    )

    refused = ip.route_install(
        request, ip.EnvOptions(), providers=["apt"], context=EXPLICIT
    )

    assert isinstance(refused, ip.Refused)
    assert "facet has no apt row for unknown-tool" in refused.text


def test_the_nix_provider_refuses_an_exact_pin_and_an_interpreter_request(monkeypatch):
    exact = ip.classify_install_command(
        ["uv", "tool", "install", "checkov==3.2.1"], False, "checkov"
    )
    ranged = _tool()

    refused_pin = ip.route_install(
        exact, ip.EnvOptions(), providers=["nix"], context=EXPLICIT
    )
    refused_runtime = ip.route_install(
        ranged, ip.EnvOptions(), providers=["nix"], context=EXPLICIT
    )

    assert (
        "nix does not support binary pinning (an exact version pin" in refused_pin.text
    )
    assert "nix does not support interpreter requests" in refused_runtime.text


def test_the_nix_provider_realizes_the_flake_once_per_run(monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setattr(
        subprocess_utils,
        "find_executable",
        lambda c: "/nix/bin/nix" if c == "nix" else None,
    )
    monkeypatch.setenv("ASH_NIX_FLAKE_REF", "github:example/flake")
    plain = ip.classify_install_command(
        ["uv", "tool", "install", "bandit"], False, "bandit"
    )

    route = ip.route_install(
        plain, ip.EnvOptions(), providers=["nix"], context=EXPLICIT
    )

    assert _argvs(route) == [
        [
            "/nix/bin/nix",
            "--extra-experimental-features",
            "nix-command flakes",
            "develop",
            "github:example/flake",
            "--command",
            "python3",
            "-c",
            "pass",
        ]
    ]
    assert route.run_once_key == "nix:github:example/flake"


def test_the_release_download_provider_serves_a_downloadable_tool_from_a_uv_declaration():
    request = ip.classify_install_command(
        ["uv", "tool", "install", "opengrep"], False, "opengrep"
    )

    route = ip.route_install(
        request, ip.EnvOptions(), providers=["release-download"], context=EXPLICIT
    )

    assert isinstance(route, ip.Route), route
    assert route.commands[0][0] == sys.executable
    assert route.commands[0][1] == "-c"
    assert route.commands[0][3] == "opengrep"


def test_pip_installs_into_the_named_venv_and_refuses_an_interpreter_request_without_one():
    venv_env = ip.EnvOptions(virtualenv_path=Path("/v"))
    plain = ip.route_install(
        _tool(), ip.EnvOptions(), providers=["pip"], context=EXPLICIT
    )
    into_venv = ip.route_install(_tool(), venv_env, providers=["pip"], context=EXPLICIT)

    assert isinstance(plain, ip.Refused)
    assert "pip does not support interpreter requests" in plain.text
    assert _argvs(into_venv) == [
        [
            str(ip.venv_python(Path("/v"))),
            "-m",
            "pip",
            "install",
            "checkov>=3,<4",
            "dep>=1",
        ]
    ]


def test_uv_routes_tool_installs_into_a_venv_and_keeps_env_installs_on_ash():
    venv_env = ip.EnvOptions(virtualenv_path=Path("/v"))
    env_install = ip.classify_install_command(
        [sys.executable, "-m", "pip", "install", "a"], False, None
    )

    tool = ip.route_install(_tool(), venv_env, providers=["uv"], context=EXPLICIT)
    env = ip.route_install(env_install, venv_env, providers=["uv"], context=EXPLICIT)

    python = str(ip.venv_python(Path("/v")))
    assert _argvs(tool) == [
        [
            "uv",
            "pip",
            "install",
            "--no-config",
            "--python",
            python,
            "checkov>=3,<4",
            "dep>=1",
        ]
    ]
    # A PYTHON_ENV install is "into the environment running ASH" (cdk-nag declares
    # aws-cdk-lib so ASH's own process can import it) and never follows the venv:
    # rerouted, the install read INSTALLED while the next scan read MISSING, and a
    # uv-vended venv has no pip at all for the pip form.
    assert _argvs(env) == [
        ["uv", "pip", "install", "--no-config", "--python", sys.executable, "a"]
    ]


def test_a_python_env_install_never_follows_the_venv():
    venv_env = ip.EnvOptions(virtualenv_path=Path("/v"))
    declared = [sys.executable, "-m", "pip", "install", "aws-cdk-lib>=2"]
    env_install = ip.classify_install_command(list(declared), False, None)

    native = ip.route_install(env_install, venv_env, providers=None, context=DEFAULT)
    pip_routed = ip.route_install(
        env_install, venv_env, providers=["pip"], context=EXPLICIT
    )

    assert _argvs(native) == [declared], _argvs(native)
    assert _argvs(pip_routed) == [declared], _argvs(pip_routed)
    assert str(ip.venv_python(Path("/v"))) not in repr(
        _argvs(native) + _argvs(pip_routed)
    )


def test_a_system_manager_route_names_what_it_drops_from_the_declared_install():
    route = ip.route_install(
        _tool(), ip.EnvOptions(), providers=["brew"], context=EXPLICIT
    )

    assert isinstance(route, ip.Route), route
    assert _argvs(route) == [["brew", "install", "checkov"]]
    dropped = [c for c in route.caveats if "does not honor" in c]
    assert dropped, route.caveats
    assert "interpreter request ('>=3.10,<3.14')" in dropped[0], dropped
    assert "dep>=1" in dropped[0], dropped


def test_a_stub_provider_refuses_as_not_implemented_and_still_runs_its_own_declaration():
    refused = ip.route_install(
        _tool(), ip.EnvOptions(), providers=["go"], context=EXPLICIT
    )
    own = ip.classify_install_command(["go", "install", "x@latest"], False, "x")
    route = ip.route_install(own, ip.EnvOptions(), providers=["go"], context=EXPLICIT)

    assert "go is not implemented" in refused.text
    assert _argvs(route) == [["go", "install", "x@latest"]]


def test_every_registered_provider_declares_what_it_is():
    assert set(ip.KNOWN_PROVIDERS) == set(ip.INSTALL_PROVIDERS)
    for name, provider in ip.INSTALL_PROVIDERS.items():
        assert provider.name == name
        assert provider.description, name
        if provider.implemented:
            assert provider.capabilities(), name
        else:
            assert provider.capabilities() == frozenset(), name


def test_parse_providers_accepts_a_list_and_names_the_known_set_on_error():
    assert ip.parse_providers("uv, Pipx,uv") == (["uv", "pipx"], None)
    assert ip.parse_providers(None) == (None, None)
    names, error = ip.parse_providers("uv,nope")
    assert names is None
    assert "Unknown provider(s) in --providers: nope" in error
    assert "Known providers: " + ", ".join(ip.KNOWN_PROVIDERS) in error
    assert ip.parse_providers("uv,,pipx")[0] is None
    assert ip.parse_providers("  ")[0] is None


@pytest.mark.parametrize(
    "request_text, version, expected",
    [
        (">=3.10,<3.14", "3.12.3", True),
        (">=3.10,<3.12", "3.12.3", False),
        ("3.12", "3.12.3", True),
        ("3.11", "3.12.3", False),
        ("cpython@3.12", "3.12.3", None),
    ],
)
def test_a_runtime_request_is_judged_against_a_version_string(
    request_text, version, expected
):
    assert ip.request_satisfied(request_text, version) is expected


def test_runtime_requests_join_without_dropping_one():
    assert ip.joined_runtime_request([">=3.10,<3.15", ">=3.10,<3.14", None]) == (
        ">=3.10,<3.15,>=3.10,<3.14",
        None,
    )
    assert ip.joined_runtime_request(["3.12", "3.12"]) == ("3.12", None)
    assert ip.joined_runtime_request([None]) == (None, None)
    assert ip.joined_runtime_request(["3.12", ">=3.10"])[1] is not None


def test_a_virtualenv_is_read_from_its_cfg_and_nothing_is_executed(tmp_path):
    venv = tmp_path / "v"
    venv.mkdir()
    assert not ip.is_virtualenv(venv)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\nversion_info = 3.12.4.final.0\n")
    assert ip.is_virtualenv(venv)
    assert ip.pyvenv_cfg_version(venv) == "3.12.4.final.0"
    (venv / "pyvenv.cfg").write_text("version = 3.11.9\n")
    assert ip.pyvenv_cfg_version(venv) == "3.11.9"
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
    assert ip.pyvenv_cfg_version(venv) is None


@pytest.fixture
def executable(tmp_path):
    marker = tmp_path / "RAN"
    tool_dir = tmp_path / "tool-dir"
    tool_dir.mkdir()
    return _marker_program(tool_dir, "checkov", marker), marker


def test_a_forced_binary_is_hashed_never_executed(executable):
    import hashlib

    path, marker = executable

    result = ip.validate_forced_binary("checkov", str(path), Path("/no/such/tree"))

    assert isinstance(result, ip.ForcedBinary)
    assert result.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert not marker.exists()
    assert ip.forced_binary_still_usable(result)


def test_a_forced_binary_whose_content_changed_is_no_longer_usable(executable):
    """The recorded SHA-256 is re-checked where a decision rests on the force: a
    regular, executable file at the same path whose bytes changed is not the
    validated binary (and is still never executed)."""
    path, marker = executable
    result = ip.validate_forced_binary("checkov", str(path), Path("/no/such/tree"))
    assert ip.forced_binary_still_usable(result)

    path.write_text("#!/bin/sh\necho other\n")
    path.chmod(0o755)

    assert not ip.forced_binary_still_usable(result)
    assert not marker.exists()


def test_forced_binary_refusals_name_the_key_and_the_path(tmp_path, executable):
    path, _ = executable
    plain = path.parent / "plain"
    plain.write_text("x")
    plain.chmod(0o644)
    link = path.parent / "link"
    link.symlink_to(path)

    cases = {
        "bin/checkov": "the path is not absolute",
        str(path.parent / "missing"): "the path does not exist",
        str(plain): "the file is not executable",
        str(link): "the path is a symlink",
        str(path.parent): "the path is not a regular file",
    }

    for text, reason in cases.items():
        refusal = ip.validate_forced_binary("checkov", text)
        assert isinstance(refusal, str), text
        assert refusal.startswith(f"--binary-path checkov={text}: "), refusal
        assert reason in refusal, (text, refusal)


@pytest.mark.parametrize(
    "name, admitted",
    [
        ("checkov.exe", True),
        ("checkov.com", True),
        ("checkov.bat", True),
        ("checkov.cmd", True),
        ("CHECKOV.EXE", True),
        ("checkov", False),
        ("checkov.sh", False),
        ("checkov.py", False),
        ("checkov.ps1", False),
    ],
)
def test_on_windows_a_forced_binary_is_a_name_windows_starts(
    tmp_path, monkeypatch, name, admitted
):
    """Windows keeps no execute permission a check can read (``os.access(X_OK)`` is
    true of every file, a descriptor's stat has no execute bits), so there a forced
    binary is a program by its name: an image ``CreateProcess`` runs or a batch file
    cmd.exe runs. The mode bits are the opposite of the answer on purpose: a shell
    script with every execute bit set is no program on Windows, and a ``.cmd`` with
    none is one. The file check behind a recorded force answers the same way."""
    import hashlib

    tools = tmp_path / "tools"
    tools.mkdir()
    candidate = tools / name
    candidate.write_text("#!/bin/sh\nexit 0\n")
    candidate.chmod(0o644 if admitted else 0o755)
    recorded = ip.ForcedBinary(
        scanner_key="checkov",
        path=candidate,
        sha256=hashlib.sha256(candidate.read_bytes()).hexdigest(),
    )

    with monkeypatch.context() as host:
        host.setattr(sys, "platform", "win32")
        result = ip.validate_forced_binary("checkov", str(candidate))
        usable = ip.forced_binary_still_usable(recorded)

    if admitted:
        assert result == recorded, result
    else:
        assert result == (
            f"--binary-path checkov={candidate}: the file is not executable"
        ), result
    assert usable is admitted


def test_a_directory_the_open_refuses_is_named_as_not_a_regular_file(
    tmp_path, monkeypatch
):
    """Windows opens no directory with ``os.open`` (it answers EACCES), so there a
    directory reaches the open's error branch rather than the regular-file check on
    the descriptor. The refusal still names it for what it is."""
    directory = tmp_path / "tool-dir"
    directory.mkdir()
    real_open = os.open

    def open_as_windows_does(path, flags, *args, **kwargs):
        if os.fspath(path) == os.fspath(directory):
            raise PermissionError(errno.EACCES, "Permission denied", os.fspath(path))
        return real_open(path, flags, *args, **kwargs)

    with monkeypatch.context() as host:
        host.setattr(os, "open", open_as_windows_does)
        refusal = ip.validate_forced_binary("checkov", str(directory))

    assert refusal == (
        f"--binary-path checkov={directory}: the path is not a regular file"
    ), refusal


def test_an_in_tree_forced_binary_needs_the_existing_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_ALLOW_IN_TREE_TOOLS", raising=False)
    tree = tmp_path / "tree"
    tree.mkdir()
    inside = _marker_program(tree, "checkov", tmp_path / "RAN")

    refused = ip.validate_forced_binary("checkov", str(inside), tree)
    monkeypatch.setenv("ASH_ALLOW_IN_TREE_TOOLS", "1")
    allowed = ip.validate_forced_binary("checkov", str(inside), tree)

    assert "inside the scanned source tree" in refused
    assert isinstance(allowed, ip.ForcedBinary)


def test_binary_path_entries_are_split_on_the_first_equals_and_checked_for_shape():
    parsed, errors = ip.parse_binary_path_entries(["a=/x=y", "b=", "bad", "=x", "a=/z"])

    assert parsed == {"a": "/x=y", "b": ""}
    assert len(errors) == 3
    assert any("more than once" in e for e in errors)


def test_a_forced_binary_is_recorded_atomically_and_erased_on_request(
    tmp_path, monkeypatch, executable
):
    monkeypatch.setenv("HOME", str(tmp_path))
    path, _ = executable
    forced = ip.validate_forced_binary("checkov", str(path))

    ip.record_forced_binaries([forced])
    assert set(ip.read_forced_binaries()) == {"checkov"}
    ip.record_forced_binaries([], erase=["checkov"])
    assert ip.read_forced_binaries() == {}
