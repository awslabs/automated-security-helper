"""The MCP entrypoint's Secrets Manager read, against a real moto server.

WHAT IS UNDER TEST
------------------
One line of the container entrypoint, taken from every committed template under
`deploy/cdk/templates/` that actually emits it:

    ASH_AUTH_VALUE=$(python3 -c "... get_secret_value(...)['SecretString'] ...")

It resolves the MCP shared secret from its ARN at container start. The ARN travels
in the environment; the value never does, so it stays out of the template, the task
definition and the runtime's environment-variable map. That design only holds if
the read itself works, which is what this measures.

WHY THIS IS A SEPARATE MODULE FROM THE SSM TESTS
------------------------------------------------
Different extraction path, and the path is the interesting part. The SSM read sits
in a plain-string buildspec. This one is a shell script, inside a quoted heredoc,
inside a command string, inside an `Fn::Join` buildspec -- three nestings, each with
its own quoting. `joined_buildspec_document` decodes it properly rather than
guessing at escaping levels, and if that decoding ever breaks these tests fail
loudly instead of matching nothing.

WHY EVERY EMITTING TEMPLATE, RATHER THAN ONE NAMED FILE
------------------------------------------------------
These tests originally named AshDistributedPipeline. Then the flavor gating landed:
each stack now receives only the scripts for the flavors it actually builds, and
since that stack declares `flavors: ['cli']` the MCP entrypoint correctly left it.
Six tests went red asserting true things about a template that no longer carried
the subject.

So the template is discovered by content, the same way resources are discovered by
content rather than by CDK logical id. `templates_with_joined_buildspec_marker`
returns every template that emits the entrypoint and the tests are parametrized
across all of them -- which is strictly stronger than naming one: the scripts are
supposed to be identical in every stack that gets them, and a refactor that
distributes them per-flavor is exactly the change that could leave one stale. The
count therefore varies with how many stacks build the mcp flavor, by design.

WHAT IS NOT COVERED HERE, AND WHY
---------------------------------
The entrypoint's refuse-to-start guard -- `McpAuthHeaderName` set but no secret
resolved, which exits 64 rather than serving unauthenticated -- is shell logic, not
an AWS call. Reaching it means running the entrypoint to completion, and the
entrypoint ends in `exec ash mcp ...`, so a test would need a stand-in `ash` on
PATH. That is worth having and it is not a moto question; it belongs with whoever
owns ash-container-scripts.ts. Recorded here so the gap is visible rather than
implied.

MEASURED moto BEHAVIOR THIS RELIES ON
-------------------------------------
moto server mode implements `get_secret_value` for both a bare name and a full
ARN, returns the SecretString byte-exact including embedded newlines, and raises
ResourceNotFoundException for an absent secret.
"""

from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

from tests.unit.deploy.buildspec_extraction import (
    MCP_ENTRYPOINT_MARKER,
    heredoc_body,
    joined_buildspec_document,
    posix_shell,
    sole_command_containing,
    templates_with_joined_buildspec_marker,
)

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="executes a POSIX entrypoint line destined for a Linux container",
)

SECRET_MARKER = "get_secret_value"
ENTRYPOINT_HEREDOC_DELIMITER = "ASH_CDK_EOF"

# The image build writes TWO scripts with heredocs sharing the ASH_CDK_EOF
# delimiter -- this entrypoint and the CodeCommit gate handler. Selecting on the
# delimiter alone matches both, so the marker is the destination filename. Found by
# the extraction guard refusing an ambiguous match rather than picking the first.
ENTRYPOINT_DESTINATION = "ash-src/ash-mcp-entrypoint.sh"

# The secret an adopter would store: no trailing newline, and containing the
# characters a heredoc or a shell expansion would mangle if the quoting were wrong.
SECRET_VALUE = "hdr-${not-expanded}-`not-run`-a1b2c3"


def emitting_templates() -> dict[str, dict]:
    """Every committed template that writes the MCP entrypoint into its image."""
    return templates_with_joined_buildspec_marker(MCP_ENTRYPOINT_MARKER)


@pytest.fixture(params=sorted(emitting_templates()))
def stack(request) -> str:
    """The name of one stack that emits the MCP entrypoint."""
    return request.param


def entrypoint_script(stack: str) -> str:
    """The MCP entrypoint shell script, as `stack`'s image build writes it."""
    template = emitting_templates()[stack]
    buildspec = joined_buildspec_document(template, MCP_ENTRYPOINT_MARKER)
    command = sole_command_containing(
        buildspec,
        "build",
        f"{ENTRYPOINT_DESTINATION} <<'{ENTRYPOINT_HEREDOC_DELIMITER}'",
    )
    body = heredoc_body(command, delimiter=ENTRYPOINT_HEREDOC_DELIMITER)
    assert "ash mcp" in body, (
        f"{stack}: the extracted heredoc body does not invoke `ash mcp`, so the "
        f"extraction matched a different heredoc than the MCP entrypoint"
    )
    return body


def secret_read_line(stack: str) -> str:
    """The single line of `stack`'s entrypoint that resolves the secret."""
    matches = [
        ln for ln in entrypoint_script(stack).splitlines() if SECRET_MARKER in ln
    ]
    assert len(matches) == 1, (
        f"{stack}: expected exactly one entrypoint line reading the secret, found "
        f"{len(matches)}: {matches}"
    )
    return matches[0].strip()


def run_secret_read(
    stack: str,
    child_env: dict[str, str],
    secret_id: str | None,
    captured: pathlib.Path,
) -> subprocess.CompletedProcess:
    """Run `stack`'s committed assignment, then write what it captured.

    The `printf` is this test's, not the deployment's -- the entrypoint keeps the
    value in a shell variable and passes it to `ash` as an argument, so observing
    it needs one added line. `printf '%s'` rather than `echo`, which would append a
    newline and make byte-exactness unmeasurable.
    """
    env = dict(child_env)
    if secret_id is None:
        env.pop("ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN", None)
    else:
        env["ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN"] = secret_id

    script = (
        f"set -eu\n{secret_read_line(stack)}\n"
        f"printf '%s' \"$ASH_AUTH_VALUE\" > {captured}\n"
    )
    return subprocess.run(
        [posix_shell(env), "-c", script],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


@pytest.fixture
def secretsmanager(moto_endpoint: str):
    import boto3

    return boto3.client(
        "secretsmanager", endpoint_url=moto_endpoint, region_name="us-east-1"
    )


class TestSecretRead:
    def test_the_secret_value_is_read_byte_exact(
        self, stack, child_env, secretsmanager, unique_name, tmp_path: pathlib.Path
    ):
        """The captured value equals the SecretString exactly."""
        created = secretsmanager.create_secret(
            Name=unique_name("ash/mcp/auth"), SecretString=SECRET_VALUE
        )
        captured = tmp_path / "captured"

        result = run_secret_read(stack, child_env, created["ARN"], captured)

        assert result.returncode == 0, result.stderr
        assert captured.read_bytes() == SECRET_VALUE.encode("utf-8")

    def test_the_arn_comes_from_the_environment(
        self, stack, child_env, secretsmanager, unique_name, tmp_path: pathlib.Path
    ):
        """An ARN, not a name, because that is what the template passes.

        Two secrets exist so that reading the right one is a real discrimination
        rather than the only thing the backend could have returned.
        """
        wanted = secretsmanager.create_secret(
            Name=unique_name("ash/mcp/wanted"), SecretString="the-right-secret"
        )
        secretsmanager.create_secret(
            Name=unique_name("ash/mcp/other"), SecretString="the-wrong-secret"
        )
        captured = tmp_path / "captured"

        assert wanted["ARN"].startswith("arn:aws:secretsmanager:"), wanted["ARN"]
        assert (
            run_secret_read(stack, child_env, wanted["ARN"], captured).returncode == 0
        )
        assert captured.read_text(encoding="utf-8") == "the-right-secret"

    def test_an_absent_secret_fails_the_entrypoint(
        self, stack, child_env, unique_name, tmp_path: pathlib.Path
    ):
        """A missing secret must not resolve to an empty value.

        Silently continuing with an empty ASH_AUTH_VALUE is the dangerous outcome:
        the entrypoint would compare an incoming header against nothing. The read
        exits non-zero, and `set -eu` in the entrypoint stops the container.
        """
        captured = tmp_path / "captured"

        result = run_secret_read(
            stack, child_env, f"ash/mcp/{unique_name('absent')}", captured
        )

        assert result.returncode != 0, (
            f"a missing secret resolved without error; captured "
            f"{captured.read_bytes() if captured.exists() else b'<nothing>'!r}"
        )
        assert "ResourceNotFoundException" in result.stderr, result.stderr
        assert not captured.exists(), "nothing should have been captured"

    def test_command_substitution_strips_a_trailing_newline(
        self, stack, child_env, secretsmanager, unique_name, tmp_path: pathlib.Path
    ):
        """DOCUMENTS A BEHAVIOR, does not endorse it.

        `$(...)` strips trailing newlines, so a secret stored with one arrives
        without it. Harmless for a header value and arguably desirable, but it
        means the entrypoint is NOT byte-transparent the way the SSM read is -- the
        SSM path redirects to a file and preserves the bytes, this one does not.
        Pinned so the difference between the two is a recorded fact.
        """
        created = secretsmanager.create_secret(
            Name=unique_name("ash/mcp/newline"), SecretString="value-with-newline\n"
        )
        captured = tmp_path / "captured"

        assert (
            run_secret_read(stack, child_env, created["ARN"], captured).returncode == 0
        )
        assert captured.read_bytes() == b"value-with-newline"


class TestReadShape:
    def test_at_least_one_stack_emits_the_entrypoint(self):
        """The parametrization must not be able to cover nothing.

        Every other test here is parametrized over the templates that emit the
        entrypoint. An empty set would generate no tests at all rather than failing
        any, so "green" would mean "checked nothing".

        WHAT ACTUALLY HAPPENS IF THE SET EMPTIES, measured by renaming the marker in
        all five templates: the module fails to IMPORT, because the parametrization
        is computed at import time and the lookup raises. That is a collection error
        naming the marker and listing where it now lives -- redder and harder to miss
        than a single failing test, so it is left as is rather than softened into a
        tolerant empty list.

        This test is therefore the belt to that braces. It is what names the
        condition if the lookup is ever made lenient, and it prints the covered
        stacks on every run so a reviewer can see which ones were exercised.

        It is not a count: how many stacks build the mcp flavor is a deployment
        decision, and pinning the number would make every flavor change a false
        failure. Only "at least one" is invariant.
        """
        emitting = sorted(emitting_templates())
        assert emitting, "no committed template emits the MCP entrypoint"
        # Named in the output so a reviewer can see WHICH stacks were covered, and
        # notice if one they expected is missing.
        print(f"stacks emitting the MCP entrypoint: {emitting}")

    def test_the_read_uses_boto3_and_writes_without_a_newline(self, stack):
        """The same shape as the SSM read, for the same reason.

        The ASH image ships no AWS CLI, so `aws secretsmanager get-secret-value`
        would exit 127 at container start. `sys.stdout.write` rather than `print`
        because print appends a newline, which `--output text` also does.
        """
        line = secret_read_line(stack)

        payload = (
            "sys.stdout.write(boto3.client('secretsmanager').get_secret_value("
            "SecretId=os.environ['ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN'])['SecretString'])"
        )
        assert payload in line, (
            f"{stack}: the entrypoint's secret read is no longer the expected "
            f"one-liner.\nexpected: {payload!r}\nactual:   {line!r}"
        )
        assert "print(" not in line, line
        assert "aws secretsmanager" not in line, line

    def test_every_stack_emits_the_identical_entrypoint(self):
        """The script must not drift between the stacks that write it.

        The flavor gating distributes these scripts per-stack. That is the change
        most likely to leave one stack with a stale copy, and a per-stack test
        cannot see it -- each would pass against its own version. Comparing the
        extracted text across stacks is what catches it.
        """
        scripts = {
            name: entrypoint_script(name) for name in sorted(emitting_templates())
        }
        distinct = set(scripts.values())
        assert len(distinct) == 1, (
            f"the MCP entrypoint differs between stacks that emit it, so at least "
            f"one carries a stale copy. Lengths per stack: "
            f"{ {n: len(s) for n, s in scripts.items()} }"
        )

    def test_the_entrypoint_never_shells_out_to_the_aws_cli(self, stack):
        """No `aws` anywhere in the script, not just on the secret line.

        The entrypoint runs at container start in the ASH image. A single `aws`
        invocation there means the container never serves, and the symptom is a
        task that starts and dies rather than an obvious error.
        """
        offenders = [
            line.strip()
            for line in entrypoint_script(stack).splitlines()
            if not line.strip().startswith("#")
            and (line.strip().startswith("aws ") or " aws " in f" {line.strip()} ")
        ]
        assert offenders == [], (
            f"{stack}: the ASH image ships no AWS CLI, so these exit 127 at "
            f"container start: {offenders}"
        )
