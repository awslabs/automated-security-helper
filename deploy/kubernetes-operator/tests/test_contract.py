"""The CLI contract: what the argv must contain, and what it must refuse."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from ash_operator import contract
from ash_operator.constants import ASH_CLI, MAX_SHARD_COUNT


class TestScanArgv:
    def test_a_sharded_worker_carries_both_integers(self):
        argv = contract.build_scan_argv(
            source_dir="/workspace/src",
            output_dir="/workspace/out",
            shard_index=2,
            shard_count=4,
        )
        assert argv[:2] == [ASH_CLI, "scan"]
        i = argv.index("--shard-index")
        assert argv[i + 1] == "2"
        j = argv.index("--shard-count")
        assert argv[j + 1] == "4"

    def test_a_worker_never_fails_on_findings(self):
        # A shard that exits non-zero for findings makes the Job controller retry a
        # shard that succeeded, and there is nothing wrong with the shard to fix.
        argv = contract.build_scan_argv(
            source_dir="/s", output_dir="/o", shard_index=0, shard_count=1
        )
        assert "--no-fail-on-findings" in argv
        assert "--fail-on-findings" not in argv

    def test_a_worker_is_never_given_a_severity_floor(self):
        # On `ash scan` --min-severity changes only that scan's exit code, and a
        # shard's exit code is discarded. Passing it would read as setting a floor
        # while having no effect.
        argv = contract.build_scan_argv(
            source_dir="/s", output_dir="/o", shard_index=0, shard_count=2
        )
        assert "--min-severity" not in argv

    def test_progress_and_simple_are_unconditional(self):
        argv = contract.build_scan_argv(source_dir="/s", output_dir="/o")
        assert "--no-progress" in argv
        assert "--simple" in argv

    @pytest.mark.parametrize(
        "flag",
        [
            "--shard-index",
            "--shard-count",
            "--min-severity",
            "--fail-on-findings",
            "--no-fail-on-findings",
            "--fail-on-incomplete-scanners",
            "--source-dir",
            "--output-dir",
        ],
    )
    def test_reserved_flags_are_refused_in_extra_arguments(self, flag):
        with pytest.raises(contract.ContractError, match="may not be supplied"):
            contract.build_scan_argv(source_dir="/s", output_dir="/o", extra_arguments=[flag, "x"])

    def test_a_reserved_flag_is_refused_in_equals_form_too(self):
        with pytest.raises(contract.ContractError, match="may not be supplied"):
            contract.build_scan_argv(
                source_dir="/s", output_dir="/o", extra_arguments=["--min-severity=LOW"]
            )

    def test_an_unreserved_extra_argument_survives(self):
        argv = contract.build_scan_argv(
            source_dir="/s", output_dir="/o", extra_arguments=["--offline"]
        )
        assert argv[-1] == "--offline"

    @pytest.mark.parametrize("flag", ["--debug", "--verbose"])
    def test_a_log_level_flag_reaches_the_shard_argv(self, flag):
        """extraScanArguments is how a Scan asks for debug or verbose output.

        ASH also reads ASH_DEBUG/ASH_VERBOSE, but the shard pod's environment is
        built from a fixed list in manifests.build_shard_job and the CRD has no env
        field, so the flag is the one route. Reserving either flag would leave a
        Scan no way to get the log a hung scanner needs.
        """
        argv = contract.build_scan_argv(source_dir="/s", output_dir="/o", extra_arguments=[flag])
        assert argv[-1] == flag

    @pytest.mark.parametrize(
        "bad", ["/s; rm -rf /", "/s$(id)", "/s`id`", "/s\nrm", "/s|cat", "/s&", "/s*"]
    )
    def test_a_path_that_is_not_an_ordinary_path_is_refused(self, bad):
        # Named for what the guard does, not for injection. Nothing on the shard path
        # re-parses argv as shell -- `command: [/bin/sh, <script>]` with `args:` and a
        # script that runs `"$@"` -- so this refuses to construct an argument no ASH
        # invocation should receive. The previous name claimed these "could become a
        # command", which was the same misreading of `sh -c` positionals that produced
        # an auth bypass in the MCP path.
        with pytest.raises(contract.ContractError, match="does not belong in a path"):
            contract.build_scan_argv(source_dir=bad, output_dir="/o")

    def test_scanner_names_go_through_the_same_guard(self):
        with pytest.raises(contract.ContractError, match="does not belong in a path"):
            contract.build_scan_argv(source_dir="/s", output_dir="/o", scanners=["bandit;id"])

    def test_the_guard_says_it_is_not_an_injection_fix(self):
        """Pin the corrected rationale in the message itself.

        A future reader who believes the old story would "fix" this guard by relaxing
        it, on the grounds that nothing re-parses argv. The message has to carry the
        reason the guard is kept anyway.
        """
        with pytest.raises(contract.ContractError) as err:
            contract.shell_arg("/s;id")
        assert "not an injection fix" in str(err.value)

    def test_every_selected_and_excluded_scanner_reaches_the_argv(self):
        argv = contract.build_scan_argv(
            source_dir="/s",
            output_dir="/o",
            scanners=["bandit", "detect-secrets"],
            exclude_scanners=["syft"],
        )
        assert argv.count("--scanners") == 2
        assert "bandit" in argv and "detect-secrets" in argv
        assert argv.count("--exclude-scanners") == 1
        assert "syft" in argv


class TestShardSelection:
    @pytest.mark.parametrize(
        "index,count",
        [(0, None), (None, 1), (0, 0), (0, -1), (1, 1), (4, 4), (-1, 2)],
    )
    def test_unusable_pairs_are_refused(self, index, count):
        with pytest.raises(contract.ContractError):
            contract.validate_shard_selection(index, count)

    @pytest.mark.parametrize("index,count", [(None, None), (0, 1), (0, 2), (1, 2), (49, 50)])
    def test_usable_pairs_are_accepted(self, index, count):
        contract.validate_shard_selection(index, count)

    def test_the_ceiling_is_enforced(self):
        contract.validate_shard_selection(0, MAX_SHARD_COUNT)
        with pytest.raises(contract.ContractError, match="at most"):
            contract.validate_shard_selection(0, MAX_SHARD_COUNT + 1)

    def test_agrees_with_ash_on_what_is_acceptable(self):
        """The controller's copy must not be stricter or looser than ASH's.

        The duplication is deliberate -- the controller refuses a bad CR at
        admission without an ASH import, and the controller and the scanner image
        can carry different ASH versions -- so the two are run against one table
        rather than trusted to agree.
        """
        ash_sharding = pytest.importorskip(
            "automated_security_helper.core.sharding",
            reason=(
                "ASH is not importable in this environment, so the two "
                "implementations cannot be compared. This is a real gap in "
                "coverage, not a pass."
            ),
        )
        table = [
            (None, None),
            (0, 1),
            (0, 2),
            (1, 2),
            (3, 4),
            (0, None),
            (None, 2),
            (0, 0),
            (2, 2),
            (-1, 3),
            (5, 3),
        ]
        outcomes = []
        for index, count in table:
            ours = _raises(contract.validate_shard_selection, index, count)
            theirs = _raises(ash_sharding.validate_shard_selection, index, count)
            outcomes.append(ours)
            assert ours == theirs, (
                f"disagreement on (index={index}, count={count}): operator "
                f"{'refused' if ours else 'accepted'}, ASH "
                f"{'refused' if theirs else 'accepted'}"
            )
        # Positive control. Without it, two functions that refused everything --
        # or accepted everything -- would agree on every row and pass.
        assert any(outcomes), "the table produced no refusals; it is not discriminating"
        assert not all(outcomes), "the table produced no acceptances; it is not discriminating"


def _raises(fn, *args) -> bool:
    try:
        fn(*args)
    except Exception:
        return True
    return False


class TestMergeArgv:
    def test_one_results_flag_per_shard(self):
        argv = contract.build_merge_argv(
            results_dirs=["/r/shard-0", "/r/shard-1", "/r/shard-2"], output_dir="/m"
        )
        assert argv.count("--results") == 3
        # Never the shared parent: resolve_results_file searches a directory
        # recursively and requires exactly one candidate, so a parent holding every
        # shard is refused.
        assert "/r" not in argv

    def test_merging_over_nothing_is_refused(self):
        with pytest.raises(contract.ContractError, match="indistinguishable from a clean scan"):
            contract.build_merge_argv(results_dirs=[], output_dir="/m")

    def test_a_duplicate_results_entry_is_refused(self):
        with pytest.raises(contract.ContractError, match="does not deduplicate"):
            contract.build_merge_argv(results_dirs=["/r/shard-0", "/r/shard-0"], output_dir="/m")

    def test_none_means_the_collector_appends_them(self):
        argv = contract.build_merge_argv(results_dirs=None, output_dir=None, min_severity="HIGH")
        assert "--results" not in argv
        assert "--output-dir" not in argv
        assert argv[-2:] == ["--min-severity", "HIGH"]

    def test_the_verdict_flags_live_here(self):
        argv = contract.build_merge_argv(
            results_dirs=["/r/0"],
            output_dir="/m",
            min_severity="MEDIUM",
            fail_on_findings=True,
            fail_on_incomplete_scanners=True,
        )
        assert "--min-severity" in argv
        assert "--fail-on-findings" in argv
        assert "--fail-on-incomplete-scanners" in argv

    def test_false_is_not_the_same_as_unset(self):
        explicit = contract.build_merge_argv(
            results_dirs=["/r/0"], output_dir="/m", fail_on_incomplete_scanners=False
        )
        assert "--no-fail-on-incomplete-scanners" in explicit
        unset = contract.build_merge_argv(results_dirs=["/r/0"], output_dir="/m")
        assert not [t for t in unset if "incomplete" in t]

    def test_an_off_table_severity_is_refused(self):
        with pytest.raises(contract.ContractError, match="minSeverity must be one of"):
            contract.build_merge_argv(results_dirs=["/r/0"], output_dir="/m", min_severity="SEVERE")


class TestMcpArgv:
    def test_stdio_cannot_back_a_service(self):
        with pytest.raises(contract.ContractError, match="no socket to route to"):
            contract.build_mcp_argv(transport="stdio")

    def test_stateless_http_only_on_streamable(self):
        with pytest.raises(contract.ContractError, match="only applies to"):
            contract.build_mcp_argv(transport="sse", stateless_http=True)

    def test_allowed_hosts_are_lower_cased(self):
        # A load balancer lower-cases Host while the MCP SDK matches it
        # case-sensitively, so a mixed-case value yields 421 on every request.
        argv = contract.build_mcp_argv(allowed_hosts=["Ash.Example.Internal"])
        assert "ash.example.internal" in argv
        assert "Ash.Example.Internal" not in argv

    def test_the_auth_value_never_appears_in_argv(self):
        """Neither the value nor a placeholder for it.

        This test replaces one that asserted ``"${ASH_TOKEN}" in argv``, which pinned
        an auth bypass: a positional parameter's value is never re-expanded, so the
        placeholder reached ``ash`` verbatim and became the expected credential. Any
        occurrence of ``--auth-header-value`` here is the bug returning, whatever the
        value beside it looks like.
        """
        argv = contract.build_mcp_argv(
            auth_header_name="X-Ash-Token", auth_value_from_environment=True
        )
        assert "--auth-header-name" in argv
        assert "X-Ash-Token" in argv
        assert "--auth-header-value" not in argv
        assert not [token for token in argv if "${" in token], (
            f"argv contains a shell placeholder: {argv!r}. Positional parameters are "
            f"not re-expanded, so this reaches ash as a literal."
        )

    def test_a_header_name_without_a_value_source_is_refused(self):
        with pytest.raises(contract.ContractError, match="set together"):
            contract.build_mcp_argv(auth_header_name="X-Ash-Token")

    def test_a_value_source_without_a_header_name_is_refused(self):
        with pytest.raises(contract.ContractError, match="set together"):
            contract.build_mcp_argv(auth_value_from_environment=True)

    def test_no_auth_means_no_auth_flags(self):
        argv = contract.build_mcp_argv()
        assert not [token for token in argv if token.startswith("--auth-")]

    def test_the_stateless_choice_is_always_explicit(self):
        on = contract.build_mcp_argv(stateless_http=True)
        off = contract.build_mcp_argv(stateless_http=False)
        assert "--stateless-http" in on and "--no-stateless-http" not in on
        assert "--no-stateless-http" in off

    def test_a_relative_mount_path_is_refused(self):
        with pytest.raises(contract.ContractError, match="must be absolute"):
            contract.build_mcp_argv(mount_path="mcp")

    def test_a_mount_path_that_could_become_a_command_is_refused(self):
        with pytest.raises(contract.ContractError, match="entrypoint's shell"):
            contract.build_mcp_argv(mount_path="/mcp;id")


class TestTheCliNameLivesInOneConstant:
    """Renaming the ASH binary must be a one-line change in constants.py."""

    PACKAGE = Path(contract.__file__).resolve().parent

    def test_every_argv_builder_uses_the_constant(self):
        assert contract.build_scan_argv(source_dir="/s", output_dir="/o")[0] == ASH_CLI
        assert contract.build_merge_argv(results_dirs=None, output_dir=None)[0] == ASH_CLI
        assert contract.build_mcp_argv()[0] == ASH_CLI

    def test_no_module_spells_the_binary_name_itself(self):
        """No code names the program; prose about ``ash merge`` is allowed.

        Two shapes are code. A string constant that is exactly the program name, and
        a line of shell -- in an entrypoint script, or in a multi-line string such as
        the MCP capability probe -- that invokes it. Docstrings, comments and the
        ``log`` lines of a script describe the command rather than run it.
        """
        invocation = re.compile(r"(?:^|[\s(;|&`])ash\s+(?:scan|merge|mcp)\b")

        def shell_offenders(label: str, text: str, first_line: int) -> list[str]:
            found = []
            for offset, line in enumerate(text.splitlines()):
                code = line.strip()
                if not code or code.startswith(("#", "log ")):
                    continue
                if invocation.search(code):
                    found.append(f"{label}:{first_line + offset}: {code}")
            return found

        offenders: list[str] = []
        for path in sorted(self.PACKAGE.rglob("*.py")):
            if path.name == "constants.py":
                continue
            label = str(path.relative_to(self.PACKAGE))
            tree = ast.parse(path.read_text())
            docstrings = {
                id(node.body[0].value)
                for node in ast.walk(tree)
                if isinstance(
                    node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
                )
                and node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
            }
            for node in ast.walk(tree):
                if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
                    continue
                if id(node) in docstrings:
                    continue
                if node.value == "ash":
                    offenders.append(f"{label}:{node.lineno}: {node.value!r}")
                elif "\n" in node.value:
                    offenders += shell_offenders(label, node.value, node.lineno)
        for path in sorted(self.PACKAGE.rglob("*.sh")):
            offenders += shell_offenders(str(path.relative_to(self.PACKAGE)), path.read_text(), 1)
        assert not offenders, "the CLI name is spelled outside ASH_CLI:\n" + "\n".join(offenders)
