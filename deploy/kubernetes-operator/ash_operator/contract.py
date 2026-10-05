"""Build the ``ash scan`` and ``ash merge`` command lines.

ASH exposes no Python interface for remote execution -- no ABC, no plugin hook,
no registry of execution targets. A backend implements a *command line* and a
*directory layout*, and that is the whole surface. This module is this backend's
half of it, built from the contract directly.

It deliberately shares nothing with the two CDK backends. Those two do not share
command construction with each other either: ``deploy/cdk/lib/ash-distributed-
pipeline-stack.ts`` imports nothing from ``deploy/cdk-constructs/``, and
``cdk-constructs/src/private/commands.ts`` scopes itself to "every ASH command
line *this package* emits". Assuming a repo-wide builder existed would have been
wrong, and porting TypeScript into Python would have created a third copy to keep
in step. The argv is rebuilt here from the contract, and the tests in
``tests/test_contract.py`` pin every property the contract requires.

Two properties are load-bearing and are asserted rather than assumed:

*Verdict ownership.* A shard runs only its slice of the scanner list, so a shard
that finds nothing exits 0 no matter what the other shards found. Gating on shard
exit codes would pass whenever each individual slice happened to be clean. So
``--fail-on-findings``, ``--no-fail-on-findings``, ``--min-severity`` and
``--fail-on-incomplete-scanners`` are refused on the worker argv and belong to
``ash merge`` alone. ``--no-fail-on-findings`` *is* passed to workers, by the
builder rather than by an adopter, which is why it is also a reserved word in
``extraScanArguments``-equivalent input.

*Provenance.* The worker runs ``ash scan`` unmodified, so ``ScanPhase`` stamps
``candidate_scanners`` onto the results. That field is the only check that can see
a split-brain scanner roster: with it, a coverage hole is refused; without it, the
same hole merges to a clean report with no refusal anywhere. Nothing here
synthesizes a ``ShardAssignment`` or rewrites the results, so the stamping happens
for free -- which is exactly why nothing here may grow a "faster path" that skips
the real CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ash_operator.constants import (
    ASH_CLI,
    MAX_SHARD_COUNT,
    MIN_SHARD_COUNT,
    SEVERITY_LEVELS,
)


class ContractError(ValueError):
    """An argv was asked for that the contract forbids."""


# Flags whose only effect is on an exit code, passed to ``ash merge`` and refused
# on a worker. Kept as a frozenset so the membership test cannot drift from the
# error message.
VERDICT_OWNING_FLAGS = frozenset(
    {
        "--fail-on-findings",
        "--no-fail-on-findings",
        "--fail-on-incomplete-scanners",
        "--no-fail-on-incomplete-scanners",
        "--min-severity",
    }
)

# Flags an adopter may never supply through ``extraScanArguments``, because the
# operator computes them and a second copy would either contradict the first or
# silently win. Superset of VERDICT_OWNING_FLAGS: the two shard integers are here
# too, since overriding them breaks the partition rather than the verdict.
RESERVED_SCAN_ARGUMENTS = VERDICT_OWNING_FLAGS | {
    "--shard-index",
    "--shard-count",
    "--source-dir",
    "--output-dir",
}

# Characters that have no business in a path, a scanner name or a flag. Mirrors the
# ``shellArg`` guard in the CDK constructs package and uses the same character set.
_SHELL_UNSAFE = set("\"'`$\\\n\r;&|<>*?()[]{}!~#")


def shell_arg(value: str) -> str:
    """Return *value* unchanged, or raise if it is not an ordinary path or name.

    **This is defence in depth, not protection against shell re-parsing, and the
    difference matters.** An earlier version of this docstring claimed "the shard
    entrypoint renders arguments into a shell command", and that claim was wrong:
    ``build_shard_job`` emits ``command: [/bin/sh, <script>]`` with ``args: scan_argv``
    and the script runs ``"$@"``. There is no ``sh -c`` and no ``eval`` anywhere on
    that path, so a positional parameter's *value* is never re-parsed by the shell.
    A semicolon in a path would reach ``ash scan`` as part of a path, not as a command
    separator.

    That wrong belief is not harmless trivia -- it is the same misreading of ``sh -c``
    positional parameters that produced an auth bypass in the MCP path, where
    ``${ASH_MCP_AUTH_HEADER_VALUE}`` was passed as an argv element on the assumption
    the shell would expand it. It does not, and ``ash`` received the literal as the
    expected credential. So the rationale is corrected here rather than left to be
    rediscovered, and this guard is deliberately **kept**: it stops a path containing
    a newline from corrupting the entrypoint's own log lines, it keeps the operator
    from constructing arguments no ASH invocation should receive, and it means a
    future change that *does* introduce a ``-c`` wrapper does not silently become
    exploitable. Do not relax it on the grounds that nothing re-parses argv today.

    Quoting instead of rejecting was considered and declined: a value needing quotes
    to be safe is a value an adopter did not mean to write, and accepting it quietly
    means the failure surfaces later as a scan of the wrong tree.
    """
    if not isinstance(value, str) or value == "":
        raise ContractError(f"expected a non-empty string, got {value!r}")
    bad = sorted(_SHELL_UNSAFE & set(value))
    if bad:
        raise ContractError(
            f"{value!r} contains {''.join(bad)!r}, which does not belong in a path, a "
            f"scanner name or a flag. Nothing on this path re-parses argv as shell -- "
            f"see shell_arg's docstring -- so this is a refusal to construct an "
            f"argument no ASH invocation should receive, not an injection fix."
        )
    return value


def validate_shard_selection(shard_index: int | None, shard_count: int | None) -> None:
    """Reject a shard selection ``ash scan`` would reject, before scheduling it.

    Duplicates ``automated_security_helper.core.sharding.validate_shard_selection``
    on purpose rather than importing it: this runs in the *controller*, which must
    refuse a bad CR at admission without an ASH import, and the controller and the
    scanner image can legitimately carry different ASH versions.
    ``tests/test_contract.py`` runs both against the same table so the two cannot
    disagree about what is acceptable.
    """
    if shard_index is None and shard_count is None:
        return
    if shard_index is None or shard_count is None:
        given, missing = (
            ("shardCount", "shardIndex") if shard_index is None else ("shardIndex", "shardCount")
        )
        raise ContractError(
            f"{given} requires {missing} as well. A shard is only meaningful as "
            f"'index of count'; acting on {given} alone would scan part of the "
            f"tree and report it as a whole scan."
        )
    if shard_count < MIN_SHARD_COUNT:
        raise ContractError(f"shardCount must be at least 1, got {shard_count}.")
    if shard_count > MAX_SHARD_COUNT:
        raise ContractError(
            f"shardCount must be at most {MAX_SHARD_COUNT}, got {shard_count}. "
            f"Shards beyond the scanner count receive an empty assignment and "
            f"still cost a pod, so the ceiling turns a typo into a rejection "
            f"rather than a bill."
        )
    if not 0 <= shard_index < shard_count:
        raise ContractError(
            f"shardIndex must satisfy 0 <= index < shardCount, got "
            f"index={shard_index} with count={shard_count}."
        )


def _check_extra_arguments(extra: list[str]) -> None:
    for token in extra:
        flag = token.split("=", 1)[0]
        if flag in RESERVED_SCAN_ARGUMENTS:
            raise ContractError(
                f"{flag} is computed by the operator and may not be supplied in "
                f"extraScanArguments. "
                + (
                    "It decides the run's verdict, which belongs to the merge and "
                    "not to any one shard."
                    if flag in VERDICT_OWNING_FLAGS
                    else "Overriding it would break the partition or the volume layout."
                )
            )
        shell_arg(token)


@dataclass(frozen=True)
class ScanInvocation:
    """The worker argv, and the environment that has to accompany it."""

    argv: list[str]
    env: dict[str, str] = field(default_factory=dict)


def build_scan_argv(
    *,
    source_dir: str,
    output_dir: str,
    shard_index: int | None = None,
    shard_count: int | None = None,
    scanners: list[str] | None = None,
    exclude_scanners: list[str] | None = None,
    extra_arguments: list[str] | None = None,
    ash_binary: str = ASH_CLI,
) -> list[str]:
    """Return the ``ash scan`` argv for one worker.

    ``--no-progress`` and ``--simple`` are unconditional: a pod has no terminal,
    and the live progress renderer writes control sequences into the pod log,
    which makes the log unreadable to anyone diagnosing a refusal.
    """
    validate_shard_selection(shard_index, shard_count)
    extra = list(extra_arguments or [])
    _check_extra_arguments(extra)

    argv = [
        ash_binary,
        "scan",
        "--source-dir",
        shell_arg(source_dir),
        "--output-dir",
        shell_arg(output_dir),
    ]
    for name in scanners or []:
        argv += ["--scanners", shell_arg(name)]
    for name in exclude_scanners or []:
        argv += ["--exclude-scanners", shell_arg(name)]
    if shard_index is not None and shard_count is not None:
        argv += [
            "--shard-index",
            str(shard_index),
            "--shard-count",
            str(shard_count),
        ]
    # A shard never owns the verdict, so it must not exit non-zero for findings:
    # a non-zero exit makes the Job controller retry a perfectly good shard.
    argv += ["--no-fail-on-findings", "--no-progress", "--simple"]
    argv += extra
    return argv


def build_merge_argv(
    *,
    results_dirs: list[str] | None,
    output_dir: str | None,
    min_severity: str | None = None,
    fail_on_findings: bool | None = None,
    fail_on_incomplete_scanners: bool | None = None,
    output_formats: list[str] | None = None,
    ash_binary: str = ASH_CLI,
) -> list[str]:
    """Return the ``ash merge`` argv for the collector.

    One ``--results`` per shard directory, never the shared parent.
    ``resolve_results_file`` searches a directory recursively and requires exactly
    one candidate, so pointing at a parent holding every shard is refused -- which
    is the right behaviour, since picking one of several would silently drop
    shards. ``results_dirs`` is therefore positional-by-index and must already be
    one directory per shard.

    ``results_dirs=None`` and ``output_dir=None`` mean "the collector appends
    these". The controller must not decide which shards exist: it would have to
    glob or trust its own bookkeeping, and the index walk inside the collector is
    the thing that turns a short set into a refusal. Passing ``[]`` is a different
    request -- merge over nothing -- and is refused.
    """
    if results_dirs is not None:
        if not results_dirs:
            raise ContractError(
                "ash merge over an empty result set would exit 0, and an empty "
                "report is indistinguishable from a clean scan. Refuse before "
                "merging."
            )
        if len(set(results_dirs)) != len(results_dirs):
            raise ContractError(
                f"duplicate --results entries: {results_dirs!r}. Merging does not "
                f"deduplicate, so the same shard's findings would be counted twice."
            )
    if min_severity is not None and min_severity not in SEVERITY_LEVELS:
        raise ContractError(f"minSeverity must be one of {SEVERITY_LEVELS}, got {min_severity!r}.")

    argv = [ash_binary, "merge"]
    for directory in results_dirs or []:
        argv += ["--results", shell_arg(directory)]
    if output_dir is not None:
        argv += ["--output-dir", shell_arg(output_dir)]
    if output_formats:
        argv += ["--output-format", shell_arg(",".join(output_formats))]
    if min_severity is not None:
        argv += ["--min-severity", min_severity]
    if fail_on_findings is not None:
        argv.append("--fail-on-findings" if fail_on_findings else "--no-fail-on-findings")
    if fail_on_incomplete_scanners is not None:
        argv.append(
            "--fail-on-incomplete-scanners"
            if fail_on_incomplete_scanners
            else "--no-fail-on-incomplete-scanners"
        )
    return argv


def build_mcp_argv(
    *,
    transport: str = "streamable-http",
    host: str = "0.0.0.0",  # noqa: S104 - a Service-backed pod must bind all interfaces
    port: int = 8000,
    mount_path: str = "/mcp",
    stateless_http: bool = False,
    allowed_hosts: list[str] | None = None,
    auth_header_name: str | None = None,
    auth_value_from_environment: bool = False,
    ash_binary: str = ASH_CLI,
) -> list[str]:
    """Return the ``ash mcp`` argv for a long-lived server pod.

    **``--auth-header-value`` is not in this argv, and must never be.** It is
    appended by the pod's entrypoint script, which reads the value out of the
    environment at run time. The two reasons are different and both matter.

    The secret must not be in the manifest: argv is visible in
    ``kubectl describe pod``, in the container runtime's process list, and in every
    audit record of the pod spec.

    And the obvious-looking way to avoid that does not work. This function used to
    emit the literal string ``${ASH_MCP_AUTH_HEADER_VALUE}`` as an argv element, with
    the pod running ``sh -c 'exec "$0" "$@"' <argv>``. A positional parameter's
    *value* is never re-expanded by the shell, so ``ash`` received the placeholder
    verbatim and ``hmac.compare_digest``'d incoming headers against those 28
    characters. That inverts the auth model: anyone sending the literal
    ``${ASH_MCP_AUTH_HEADER_VALUE}`` -- a constant in a public repository, also
    readable with ``kubectl get deploy -o yaml`` -- authenticates, and the holder of
    the real secret gets 401. Measured directly, with the variable set in the
    environment, ``sh -c 'exec "$0" "$@"' … '${ASH_MCP_AUTH_HEADER_VALUE}'`` passes
    the literal through unchanged.

    Nothing upstream rescues it either: ``ash mcp``'s ``--auth-header-value`` option
    declares no ``envvar=``, so setting the variable alone supplies no value.

    ``auth_value_from_environment`` therefore says only *that* a value will be
    supplied by the entrypoint. It is still validated against ``auth_header_name``
    here, because a header name with no value source accepts every request that
    sends the header.

    ``--allowed-host`` values are lower-cased. A load balancer lower-cases the
    ``Host`` header while the MCP SDK matches it case-sensitively, so a
    mixed-case allowed host yields 421 on every request.
    """
    if transport not in ("stdio", "streamable-http", "sse"):
        raise ContractError(f"transport must be stdio, streamable-http or sse, got {transport!r}.")
    if stateless_http and transport != "streamable-http":
        raise ContractError(
            "statelessHttp only applies to transport streamable-http. On any other "
            "transport there are no sessions to skip, so setting it would read as "
            "a behaviour change that does not happen."
        )
    if transport == "stdio":
        raise ContractError(
            "transport stdio cannot back a Service: there is no socket to route to. "
            "An AshMcpServer is a long-lived HTTP endpoint; use streamable-http or "
            "sse."
        )
    if bool(auth_header_name) != bool(auth_value_from_environment):
        raise ContractError(
            "authHeaderName and a source for its value must be set together; a header "
            "name with no expected value accepts every request that sends the header."
        )

    if not mount_path.startswith("/"):
        raise ContractError(
            f"mountPath must be absolute, got {mount_path!r}. A relative path is "
            f"accepted by the CLI and produces an endpoint nobody can route to."
        )
    # Path separators are legitimate here, so the generic guard would reject every
    # valid value. Check the remaining metacharacters instead.
    unsafe = sorted((_SHELL_UNSAFE - {"/"}) & set(mount_path))
    if unsafe:
        raise ContractError(
            f"mountPath {mount_path!r} contains {''.join(unsafe)!r}, which the "
            f"entrypoint's shell would interpret."
        )

    argv = [
        ash_binary,
        "mcp",
        "--transport",
        transport,
        "--host",
        shell_arg(host),
        "--port",
        str(int(port)),
        "--mount-path",
        mount_path,
    ]
    argv.append("--stateless-http" if stateless_http else "--no-stateless-http")
    for host_value in allowed_hosts or []:
        argv += ["--allowed-host", shell_arg(host_value).lower()]
    if auth_header_name:
        argv += ["--auth-header-name", shell_arg(auth_header_name)]
        # --auth-header-value is deliberately absent. See the docstring: putting a
        # placeholder here produced an auth bypass, because a positional parameter's
        # value is never re-expanded. The entrypoint appends the flag and reads the
        # value from the environment.
    return argv
