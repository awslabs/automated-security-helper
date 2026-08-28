"""The buildspec's SSM read of the base ASH config, against a real moto server.

WHAT IS UNDER TEST
------------------
The `pre_build` command every project of `AshDistributedPipeline` shares, taken
from the committed template:

    if [ -n "${ASH_BASE_CONFIG_SSM_PARAMETER:-}" ]; then
      mkdir -p "$(dirname "$ASH_CONFIG")"
      python3 -c "... get_parameter(..., WithDecryption=True) ..." > "$ASH_CONFIG"
    else
      echo "No ASH base configuration supplied; ..."
    fi

WHY BYTE-EXACTNESS IS THE POINT
-------------------------------
This replaced `aws ssm get-parameter --output text`, which appends a newline that
`sys.stdout.write` does not. The output is a YAML file ASH parses, so a stray
byte is not obviously harmful -- which is exactly why it needs a test rather than
an eyeball. The assertions below compare against the parameter value byte for
byte, and one of them states the `--output text` difference explicitly so the
regression has a named shape.

WHY THIS CAN BE TESTED AT ALL
-----------------------------
moto server mode implements SSM `get_parameter` with `WithDecryption=True` on a
`SecureString` and returns the plaintext. It also gives a free positive control:
with `WithDecryption=False` moto returns the marker string
`kms:alias/aws/ssm:<value>` rather than real ciphertext. Unrealistic as a value,
but it means a test can prove the code passed `WithDecryption=True` instead of
merely receiving something that looked like a config.

A LATENT PATH THIS FILE PINS
----------------------------
The shell creates `$ASH_CONFIG` by redirection BEFORE python runs, so a failed
SSM read leaves an empty file where a config should be, and the phase's non-zero
exit is the only signal. `test_a_failed_read_leaves_an_empty_config_behind`
records that.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
from collections.abc import Callable

import pytest

from tests.unit.deploy.buildspec_extraction import (
    DISTRIBUTED_PIPELINE_TEMPLATE,
    joined_buildspec_text,
    load_template,
    projects_containing,
    sole_command_containing,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="executes a POSIX buildspec command destined for a Linux build container",
)

SSM_MARKER = "get_parameter"
HELPER_MARKER = "ash-s3-sync.py"

# A realistic base config: multi-line, no trailing newline, and containing the
# `$`, `{` and `:` characters that a heredoc or a shell expansion would mangle.
CONFIG_YAML = "\n".join(
    [
        "project_name: acme-${env}",
        "global_settings:",
        "  severity_threshold: MEDIUM",
        "reporters:",
        "  markdown:",
        "    enabled: true",
    ]
)


def ssm_command() -> str:
    """The committed pre_build SSM command from a shard project."""
    template = load_template(DISTRIBUTED_PIPELINE_TEMPLATE)
    projects = projects_containing(template, HELPER_MARKER)
    assert len(projects) == 5, sorted(projects)
    shard_ids = sorted(i for i in projects if "Shard" in i)
    assert len(shard_ids) == 4, shard_ids
    return sole_command_containing(projects[shard_ids[0]], "pre_build", SSM_MARKER)


def run_ssm_command(
    child_env: dict[str, str], config_path: pathlib.Path, parameter_name: str | None
) -> subprocess.CompletedProcess:
    """Execute the committed command with the environment CodeBuild would set."""
    env = dict(child_env)
    env["ASH_CONFIG"] = str(config_path)
    if parameter_name is None:
        env.pop("ASH_BASE_CONFIG_SSM_PARAMETER", None)
    else:
        env["ASH_BASE_CONFIG_SSM_PARAMETER"] = parameter_name
    return subprocess.run(
        ["sh", "-c", ssm_command()],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


@pytest.fixture
def secure_parameter(ssm, unique_name) -> Callable[[str], str]:
    """Put a SecureString parameter in moto and return its name."""

    def _put(value: str) -> str:
        name = f"/{unique_name('ash/base-config')}"
        ssm.put_parameter(Name=name, Value=value, Type="SecureString", Overwrite=True)
        return name

    return _put


class TestByteExactness:
    def test_written_config_is_byte_identical_to_the_parameter(
        self, child_env: dict[str, str], secure_parameter, tmp_path: pathlib.Path
    ):
        """The file on disk equals the parameter value, byte for byte."""
        name = secure_parameter(CONFIG_YAML)
        config = tmp_path / "ash-config" / ".ash.yaml"

        result = run_ssm_command(child_env, config, name)

        assert result.returncode == 0, result.stderr
        assert config.read_bytes() == CONFIG_YAML.encode("utf-8")

    def test_no_trailing_newline_is_appended(
        self, child_env: dict[str, str], secure_parameter, tmp_path: pathlib.Path
    ):
        """The regression `--output text` would reintroduce.

        `aws ssm get-parameter --output text` appends a newline;
        `sys.stdout.write` does not. Stated as its own test with the wrong value
        named, because the byte-identity test above would also fail for a dozen
        unrelated reasons and would not tell the next reader which one this is.
        """
        name = secure_parameter(CONFIG_YAML)
        config = tmp_path / "ash-config" / ".ash.yaml"

        assert run_ssm_command(child_env, config, name).returncode == 0

        written = config.read_bytes()
        assert not written.endswith(b"\n"), (
            "a trailing newline was appended; the parameter value has none. This is "
            "the `--output text` behavior the boto3 read exists to avoid."
        )
        assert written != CONFIG_YAML.encode("utf-8") + b"\n"

    def test_a_value_that_does_end_in_a_newline_keeps_exactly_one(
        self, child_env: dict[str, str], secure_parameter, tmp_path: pathlib.Path
    ):
        """The complement: a real trailing newline is preserved, not doubled."""
        name = secure_parameter(CONFIG_YAML + "\n")
        config = tmp_path / "ash-config" / ".ash.yaml"

        assert run_ssm_command(child_env, config, name).returncode == 0
        assert config.read_bytes() == (CONFIG_YAML + "\n").encode("utf-8")

    def test_multiline_structure_survives(
        self, child_env: dict[str, str], secure_parameter, tmp_path: pathlib.Path
    ):
        """Line count and indentation are preserved, so the YAML still parses."""
        name = secure_parameter(CONFIG_YAML)
        config = tmp_path / "ash-config" / ".ash.yaml"

        assert run_ssm_command(child_env, config, name).returncode == 0

        lines = config.read_text(encoding="utf-8").splitlines()
        assert lines == CONFIG_YAML.splitlines()
        assert lines[2] == "  severity_threshold: MEDIUM", lines


class TestDecryption:
    def test_the_value_is_decrypted_and_not_the_ciphertext_marker(
        self, child_env: dict[str, str], secure_parameter, ssm, tmp_path: pathlib.Path
    ):
        """Proves `WithDecryption=True` was actually passed.

        moto returns `kms:alias/aws/ssm:<value>` when decryption is NOT requested.
        So the assertion is not merely "we got the value" -- it is "we did not get
        the shape that omitting the flag produces". The undecrypted form is read
        here through the client so the test states the difference rather than
        hard-coding moto's marker format.
        """
        name = secure_parameter(CONFIG_YAML)
        undecrypted = ssm.get_parameter(Name=name, WithDecryption=False)["Parameter"][
            "Value"
        ]
        assert undecrypted != CONFIG_YAML, (
            "moto returned identical values with and without decryption, so this "
            "test can no longer distinguish the two and needs a different control"
        )

        config = tmp_path / "ash-config" / ".ash.yaml"
        assert run_ssm_command(child_env, config, name).returncode == 0

        written = config.read_text(encoding="utf-8")
        assert written == CONFIG_YAML
        assert written != undecrypted

    def test_a_customer_managed_key_is_also_read(
        self, child_env: dict[str, str], ssm, moto_endpoint: str, unique_name, tmp_path
    ):
        """A SecureString encrypted with a customer KMS key, not the default alias.

        Adopters who supply their own key are the ones most likely to hit an IAM
        or key-policy problem, so the read is exercised against that shape too.
        """
        import boto3

        kms = boto3.client("kms", endpoint_url=moto_endpoint, region_name="us-east-1")
        key_id = kms.create_key(Description="ash base config")["KeyMetadata"]["KeyId"]

        name = f"/{unique_name('ash/base-config-cmk')}"
        ssm.put_parameter(
            Name=name,
            Value=CONFIG_YAML,
            Type="SecureString",
            KeyId=key_id,
            Overwrite=True,
        )

        config = tmp_path / "ash-config" / ".ash.yaml"
        assert run_ssm_command(child_env, config, name).returncode == 0
        assert config.read_bytes() == CONFIG_YAML.encode("utf-8")


class TestBranches:
    def test_no_parameter_supplied_writes_no_config(
        self, child_env: dict[str, str], tmp_path: pathlib.Path
    ):
        """The else branch. AshBaseConfigYaml defaults empty, so this is the
        path almost every adopter takes, and it must not create a config file --
        ASH falls through to its built-in defaults instead."""
        config = tmp_path / "ash-config" / ".ash.yaml"

        result = run_ssm_command(child_env, config, parameter_name=None)

        assert result.returncode == 0, result.stderr
        assert "built-in defaults" in result.stdout, result.stdout
        assert not config.exists(), "the else branch must not create a config file"

    def test_an_empty_parameter_name_takes_the_else_branch(
        self, child_env: dict[str, str], tmp_path: pathlib.Path
    ):
        """An empty string is not a parameter name.

        `[ -n "${VAR:-}" ]` treats unset and empty alike. CloudFormation renders an
        unsupplied parameter as an empty string rather than omitting the variable,
        so this is the shape the default actually produces at runtime.
        """
        config = tmp_path / "ash-config" / ".ash.yaml"

        result = run_ssm_command(child_env, config, parameter_name="")

        assert result.returncode == 0, result.stderr
        assert "built-in defaults" in result.stdout
        assert not config.exists()

    def test_the_parent_directory_is_created(
        self, child_env: dict[str, str], secure_parameter, tmp_path: pathlib.Path
    ):
        """`mkdir -p "$(dirname ...)"` must run before the redirection.

        The default path is /tmp/ash-config/.ash.yaml, a directory that does not
        exist in a fresh container. Without the mkdir the redirect fails with
        "No such file or directory" and nothing is written.
        """
        name = secure_parameter(CONFIG_YAML)
        config = tmp_path / "deep" / "nested" / "ash-config" / ".ash.yaml"
        assert not config.parent.exists()

        result = run_ssm_command(child_env, config, name)

        assert result.returncode == 0, result.stderr
        assert config.read_bytes() == CONFIG_YAML.encode("utf-8")

    def test_a_failed_read_leaves_an_empty_config_behind(
        self, child_env: dict[str, str], tmp_path: pathlib.Path, unique_name
    ):
        """DOCUMENTS A LATENT PATH, does not endorse it.

        The shell opens `> "$ASH_CONFIG"` before python runs, so a parameter that
        does not exist leaves a zero-byte file where a config belongs. The phase
        does exit non-zero, which is what saves it -- but any future change that
        tolerated the failure would hand ASH an empty `.ash.yaml`. Pinned so that
        the ordering is visible rather than discovered.
        """
        config = tmp_path / "ash-config" / ".ash.yaml"

        result = run_ssm_command(child_env, config, f"/{unique_name('absent')}")

        assert result.returncode != 0, (
            "a missing parameter must fail the phase; exiting 0 here would let the "
            "build continue with an empty config"
        )
        assert "ParameterNotFound" in result.stderr, result.stderr
        assert config.exists(), "redirection creates the file before python runs"
        assert config.read_bytes() == b"", "the failed read leaves it empty"


class TestOneReadEverywhere:
    def test_the_buildspec_and_the_mcp_entrypoint_use_the_same_read(self):
        """A config materialized by a buildspec cannot differ from one the
        container entrypoint materializes.

        Both are supposed to be the same `python3 -c` one-liner. If they drift,
        two deployment targets parse different config for the same parameter and
        the difference shows up as a scan that behaves differently depending on
        which target ran it.

        WHAT IS COMPARED, AND WHY NOT THE WHOLE LINE: the entrypoint script is a
        JSON string nested inside the image build's own JSON buildspec, so its
        double quotes arrive as `\\"` and its newlines as literal `\\n`. The
        `python3 -c "` wrapper therefore cannot match verbatim even when the two
        are identical -- verified during design, and the reason this compares the
        payload instead. The payload is written entirely with single quotes, so it
        survives both nestings unescaped, and it is the part that carries the
        meaning: the client, the operation, the parameter name, the decryption
        flag, and the `sys.stdout.write` that makes the value byte-exact.
        """
        template = load_template(DISTRIBUTED_PIPELINE_TEMPLATE)

        buildspec_command = ssm_command()
        entrypoint_text = joined_buildspec_text(template, "get_parameter")

        payload = (
            "sys.stdout.write(boto3.client('ssm').get_parameter("
            "Name=os.environ['ASH_BASE_CONFIG_SSM_PARAMETER'], "
            "WithDecryption=True)['Parameter']['Value'])"
        )
        assert '"' not in payload, (
            "the compared payload must be free of double quotes, or it cannot "
            "survive the entrypoint's JSON nesting and this test degenerates into "
            "an assertion about escaping"
        )

        assert payload in buildspec_command, (
            f"the buildspec's SSM read is no longer the expected one-liner.\n"
            f"expected payload: {payload!r}\nactual command: {buildspec_command!r}"
        )
        assert payload in entrypoint_text, (
            "the MCP entrypoint's SSM read has drifted from the buildspec's, so the "
            "two can now produce different configs for the same parameter.\n"
            f"expected payload: {payload!r}"
        )

        # `print()` would append a newline where `sys.stdout.write` does not, and
        # `--output text` is the CLI form with the same defect.
        assert "print(" not in payload
        assert "--output text" not in buildspec_command
        assert "--output text" not in entrypoint_text
