# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scripts/setup-nerdctl-linux.sh`` fails early, loudly, and without side effects first.

Why this file exists
--------------------
The script needs root and systemd, so it cannot be executed in a unit test. These are
text and ordering assertions over the script's *code*, in the idiom of the sibling files
``test_nerdctl_buildkitd_*.py``. Every assertion reads the script with its comment lines
removed, because prose that explains a defect also names the thing the assertion looks
for, and an assertion a comment can satisfy measures the prose and not the script.

What is pinned, one class per behavior:

* Docker is stopped only after the download, the checksum, the unpack, the CNI copy and the
  buildkitd config have completed, and the stop does not depend on ``is-active``.
* An empty CNI directory is refused with the script's own diagnostic, and the CNI copy
  overwrites instead of keeping, so its exit status does not depend on the coreutils
  release and a stale plugin cannot survive in ``/opt/cni/bin``.
* An existing buildkitd configuration that this script did not write is copied aside.
* A unit that fails to restart prints its status and journal before the script exits.
* The containerd unit is checked to run the bundle's binary.
* The namespace diagnostic is bounded by ``timeout``.
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SETUP = REPO_ROOT / "scripts" / "setup-nerdctl-linux.sh"

DOCKER_LOOP_HEAD = "for unit in docker.socket docker.service; do"


@pytest.fixture(scope="module")
def raw() -> str:
    return SETUP.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def code(raw: str) -> str:
    """The script without its comment-only lines."""
    return "\n".join(
        line for line in raw.splitlines() if not line.lstrip().startswith("#")
    )


@pytest.fixture(scope="module")
def docker_loop(code: str) -> str:
    """The body of the loop that stops the Docker units."""
    match = re.search(
        re.escape(DOCKER_LOOP_HEAD) + r"\n(.*?)\ndone\n", code, flags=re.DOTALL
    )
    assert match is not None, (
        "no `for unit in docker.socket docker.service; do ... done` loop found; every "
        "assertion about the Docker stop would pass vacuously without this guard"
    )
    return match.group(1)


class TestDockerIsStoppedOnlyWhenTheInstallCanSucceed:
    def test_docker_is_stopped_after_the_download_is_verified(self, code: str):
        """A failed download or checksum mismatch must leave Docker running."""
        assert code.index("curl -fsSL") < code.index(DOCKER_LOOP_HEAD)
        assert code.index("sha256sum -c -") < code.index(DOCKER_LOOP_HEAD), (
            "Docker is stopped before the tarball's checksum is checked, so a bad "
            "download leaves the host with Docker stopped and nothing installed"
        )

    def test_docker_is_stopped_after_the_bundle_is_unpacked_and_configured(
        self, code: str
    ):
        loop = code.index(DOCKER_LOOP_HEAD)
        assert code.index("tar -C /usr/local -xzf") < loop
        assert code.index("cp -f --preserve=mode") < loop
        assert code.index("cat > /etc/buildkit/buildkitd.toml <<") < loop

    def test_docker_is_stopped_before_containerd_is_restarted(self, code: str):
        loop = code.index(DOCKER_LOOP_HEAD)
        # Anchored to a whole line: the printed undo text also names daemon-reload.
        assert loop < code.index("\nsystemctl daemon-reload\n")
        assert loop < code.index("if ! systemctl restart containerd")

    def test_the_stop_does_not_depend_on_the_unit_being_active(self, docker_loop: str):
        """`is-active` is false for a unit that is activating or waiting to restart.

        Such a Docker service was left alone and came back to contend for containerd.
        """
        assert "is-active" not in docker_loop
        assert "LoadState" in docker_loop
        assert "not-found" in docker_loop
        assert "systemctl stop" in docker_loop

    def test_the_printed_undo_takes_the_bundles_units_out_of_the_way(self, code: str):
        """Starting Docker after only a daemon-reload leaves it on the bundle's containerd."""
        head = code.index('echo "=== Stopping Docker')
        undo = code[head : code.index(DOCKER_LOOP_HEAD)]
        assert "/usr/local/lib/systemd/system/containerd.service" in undo
        assert "buildkit.service" in undo
        assert undo.index("daemon-reload") < undo.index("systemctl start docker.socket")


class TestTheCniCopy:
    def test_an_empty_source_directory_gets_the_scripts_own_diagnostic(self, code: str):
        """With an empty directory the unexpanded glob made cp fail with its bare error."""
        assert "shopt -s nullglob" in code
        assert '"${#cni_plugins[@]}" -eq 0' in code
        assert "exists but is empty" in code
        assert code.index('"${#cni_plugins[@]}" -eq 0') < code.index(
            "cp -f --preserve=mode"
        )
        assert re.search(r'^\s*cp [^\n]*"\$\{CNI_SRC\}"/\*', code, re.MULTILINE) is None

    def test_the_copy_overwrites_rather_than_keeps(self, code: str):
        """`cp -n` kept stale plugins and exits non-zero on skips in coreutils 9.2 to 9.4."""
        copies = [
            line
            for line in code.splitlines()
            if re.match(r"\s*cp\s", line) and "/opt/cni/bin/" in line
        ]
        assert len(copies) == 1, copies
        assert " -n " not in copies[0]
        assert " -f " in copies[0]
        assert "--preserve=mode" in copies[0]


class TestAnExistingBuildkitdConfigIsNotDestroyed:
    def test_a_foreign_config_is_copied_aside_before_it_is_overwritten(self, code: str):
        write = code.index("cat > /etc/buildkit/buildkitd.toml <<")
        backup = code.index("--backup=numbered")
        assert backup < write, "the backup must precede the overwrite"
        guard = code[code.index("if [ -f /etc/buildkit/buildkitd.toml ]") : backup]
        assert "! grep -q '^# Written by scripts/setup-nerdctl-linux.sh'" in guard

    def test_the_guard_marker_is_the_first_line_the_script_writes(self, raw: str):
        """A file written by an earlier run must carry the marker, or it is backed up forever."""
        match = re.search(
            r"cat > /etc/buildkit/buildkitd\.toml <<'EOF'\n(.*?)\nEOF\n",
            raw,
            re.DOTALL,
        )
        assert match is not None
        assert match.group(1).startswith("# Written by scripts/setup-nerdctl-linux.sh")


class TestAFailedStartPrintsItsDiagnostics:
    def test_a_restart_failure_is_tested_not_left_to_set_e(self, code: str):
        assert re.search(r"^systemctl restart ", code, re.MULTILINE) is None, (
            "a bare `systemctl restart` under `set -e` exits the script before the "
            "status and journal dump can run"
        )
        for unit in ("containerd", "buildkit"):
            test = f"if ! systemctl restart {unit}; then"
            assert test in code
            body = code[code.index(test) :].split("\nfi\n", 1)[0]
            assert f"dump_unit_diagnostics {unit}" in body
            assert "exit 1" in body

    def test_the_diagnostics_helper_prints_status_and_journal(self, code: str):
        match = re.search(r"dump_unit_diagnostics\(\) \{\n(.*?)\n\}\n", code, re.DOTALL)
        assert match is not None
        assert "systemctl status" in match.group(1)
        assert "journalctl -u" in match.group(1)
        assert code.index("dump_unit_diagnostics()") < code.index(
            "if ! systemctl restart containerd"
        )


class TestTheBundlesContainerdIsTheOneRunning:
    def test_the_unit_is_checked_to_run_the_bundles_binary(self, code: str):
        probe = "systemctl show --property=ExecStart --value containerd"
        assert probe in code
        assert "path=/usr/local/bin/containerd" in code
        # After the wait for an active unit, before the first nerdctl command.
        assert code.index("did not become active") < code.index(probe)
        assert code.index(probe) < code.index("nerdctl --version")
        tail = code[code.index(probe) :]
        assert "does not run /usr/local/bin/containerd" in tail.split("esac", 1)[0]


class TestTheNamespaceProbeIsBounded:
    def test_nerdctl_namespace_ls_runs_under_timeout(self, code: str):
        lines = [line for line in code.splitlines() if "nerdctl namespace ls" in line]
        assert len(lines) == 1, lines
        assert re.search(r"\$\(timeout \d+ nerdctl namespace ls", lines[0]), lines[0]
