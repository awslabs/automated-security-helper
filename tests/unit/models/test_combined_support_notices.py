"""Several runs' support notices as one list: each id once, holding what every run read.

Why this exists
---------------
The two outputs that combine runs, the workspace results file (its projects) and
``ash merge`` (its shards), each have to say what every run met. The runs can be on
different hosts, and a notice records what its own host read: the processor flags that
were missing, the level the processor is at. Two hosts that meet the same row do not
read the same of it, so a list that kept the first run's record would publish one
host's flags and facts as if they were the scan's. The paths a notice offers are the
register's for the host that wrote it, and the register does not offer every path on
every host: the compatibility runtime is offered to a uv tool and not to a Homebrew
install, nor to a processor below that runtime. A list that kept the first run's paths
would offer a path to a scan one of whose hosts the register never offers it to, and
would offer a different list of paths when the runs came in another order. Both
outputs build the combined list with ``combined_support_notices``, which this file
pins on its own so each output's own test can say only what it adds.

The rule: one record per notice id, the first run's in every field the row declares,
except that what the runs read, and what the register offered them, is only what every
run recorded. ``facts`` holds the pairs every run recorded, ``found`` is kept when
every run recorded the same text and is None when they did not, and ``paths`` holds the
paths every run was offered, compared by path id, in the first run's order. Nothing
else is added to the record.

A record that leaves something out says so, so that the omission is not silent: one
warning for each notice that more than one run recorded and the runs did not read
alike. It names the notice, the runs that recorded it (by the names the caller gives
them, and by position when it gives none) and what the record leaves out, ``found``,
``facts.<name>`` and ``paths.<id>``, and it does not repeat what a run read.
"""

import logging

import pytest

from automated_security_helper.models.asharp_model import (
    SupportNotice,
    combined_support_notices,
)
from tests.unit.models._support_notice_helpers import (
    AGREED_CPU_FACTS,
    BELOW_COMPAT,
    COMPAT_RUNTIME,
    CPU_ID,
    DOCS_PAGE,
    HOMEBREW,
    OFFERED_EVERYWHERE,
    POLYFILL_ID,
    SANDBOX_ID,
    UV_TOOL,
    cpu_notice,
    cpu_notice_of_two_hosts,
    cpu_notice_on,
    cpu_notices_of_two_installs,
    polyfill_notice,
    sandbox_notice,
)

pytestmark = pytest.mark.unit

AVX2 = "avx2 is missing (polars-runtime-32 1.44.2)."
AVX2_AND_FMA = "avx2 and fma are missing (polars-runtime-32 1.44.2)."


def _ids(notices) -> list[str]:
    return [notice.id for notice in notices]


def _said(capture) -> list[str]:
    """What the combined list told the operator, one string for each warning."""
    return [record.getMessage() for record in capture.records]


def _the_one_said(capture) -> str:
    said = _said(capture)
    assert len(said) == 1, said
    return said[0]


def test_every_runs_notice_is_kept():
    united = combined_support_notices(
        [[cpu_notice()], [sandbox_notice(), polyfill_notice()]]
    )

    assert _ids(united) == [CPU_ID, SANDBOX_ID, POLYFILL_ID]


def test_a_notice_two_runs_met_differently_is_listed_once_holding_what_both_read():
    near, far = cpu_notice_of_two_hosts()

    united = combined_support_notices([[near], [far, sandbox_notice()]])

    assert _ids(united) == [CPU_ID, SANDBOX_ID]
    record = united[0]
    # The runs read other flags and another level, so the record says neither run's.
    assert record.found is None, record
    assert record.facts == AGREED_CPU_FACTS, record


def test_control_runs_that_met_a_notice_the_same_way_give_the_record_they_read():
    near, _ = cpu_notice_of_two_hosts()

    united = combined_support_notices(
        [[near], [near.model_copy(deep=True)], [near.model_copy(deep=True)]]
    )

    assert united == [near]


@pytest.mark.parametrize(
    ("per_run", "expected"),
    [
        pytest.param([AVX2, AVX2], AVX2, id="the same text in two runs"),
        pytest.param([AVX2, AVX2, AVX2], AVX2, id="the same text in three runs"),
        pytest.param([AVX2, AVX2_AND_FMA], None, id="different text in two runs"),
        pytest.param([AVX2, AVX2, AVX2_AND_FMA], None, id="the last of three differs"),
        pytest.param([AVX2, AVX2_AND_FMA, AVX2], None, id="the middle one differs"),
        pytest.param([AVX2, None], None, id="read by the first and not the second"),
        pytest.param([None, AVX2], None, id="read by the second and not the first"),
        pytest.param([None, None], None, id="read by neither"),
    ],
)
def test_found_is_kept_only_when_every_run_recorded_the_same_text(per_run, expected):
    united = combined_support_notices([[cpu_notice(found=found)] for found in per_run])

    assert united[0].found == expected


GLIBC = {"arch": "amd64", "libc": "glibc"}


@pytest.mark.parametrize(
    ("per_run", "expected"),
    [
        pytest.param([GLIBC, GLIBC], GLIBC, id="the same facts in two runs"),
        pytest.param(
            [GLIBC, {"arch": "amd64", "libc": "musl"}],
            {"arch": "amd64"},
            id="a fact with another token in the second run",
        ),
        pytest.param(
            [GLIBC, {"arch": "amd64"}],
            {"arch": "amd64"},
            id="a fact only the first run read",
        ),
        pytest.param(
            [{"arch": "amd64"}, GLIBC],
            {"arch": "amd64"},
            id="a fact only the second run read",
        ),
        pytest.param(
            [{"arch": "amd64"}, {"libc": "glibc"}], {}, id="no fact in common"
        ),
        pytest.param([{"arch": "amd64"}, {}], {}, id="a run that read no fact"),
        pytest.param(
            [GLIBC, GLIBC, {"arch": "amd64", "libc": "musl"}],
            {"arch": "amd64"},
            id="a fact two of three runs read the same",
        ),
        pytest.param(
            [GLIBC, {"arch": "arm64", "libc": "glibc"}, GLIBC],
            {"libc": "glibc"},
            id="a fact the middle of three runs read otherwise",
        ),
    ],
)
def test_a_fact_is_kept_only_when_every_run_read_the_same_token(per_run, expected):
    united = combined_support_notices([[cpu_notice(facts=facts)] for facts in per_run])

    assert united[0].facts == expected


def test_the_facts_kept_stay_in_the_order_of_the_first_run():
    first = cpu_notice(facts={"libc": "glibc", "arch": "amd64", "wsl": "no"})
    second = cpu_notice(facts={"wsl": "no", "arch": "amd64", "libc": "glibc"})

    united = combined_support_notices([[first], [second]])

    assert list(united[0].facts) == ["libc", "arch", "wsl"]


def _path_ids(notice) -> list[str]:
    return [path.id for path in notice.paths]


def test_control_the_compat_runtime_is_offered_to_a_uv_tool_and_not_to_the_others():
    """What the tests of the paths rest on. If the register offered other paths on these
    hosts, this fails first and says so."""
    uv_tool, homebrew = cpu_notices_of_two_installs()
    below_compat = cpu_notice_on(BELOW_COMPAT, found=AVX2_AND_FMA)

    assert _path_ids(uv_tool) == [COMPAT_RUNTIME, *OFFERED_EVERYWHERE]
    assert _path_ids(homebrew) == OFFERED_EVERYWHERE
    assert _path_ids(below_compat) == OFFERED_EVERYWHERE
    # The paths are all that sets the first two apart.
    assert (uv_tool.facts, uv_tool.found) == (homebrew.facts, homebrew.found)


def test_a_path_only_some_runs_were_offered_is_left_out_of_the_record():
    uv_tool, homebrew = cpu_notices_of_two_installs()

    united = combined_support_notices([[uv_tool], [homebrew]])

    assert _path_ids(united[0]) == OFFERED_EVERYWHERE


def test_the_paths_are_the_same_whichever_run_comes_first():
    uv_tool, homebrew = cpu_notices_of_two_installs()

    uv_tool_first = combined_support_notices([[uv_tool], [homebrew]])
    homebrew_first = combined_support_notices([[homebrew], [uv_tool]])

    assert uv_tool_first[0].paths == homebrew_first[0].paths
    assert _path_ids(uv_tool_first[0]) == OFFERED_EVERYWHERE


@pytest.mark.parametrize(
    "hosts",
    [
        pytest.param([UV_TOOL, UV_TOOL, HOMEBREW], id="the last run lacks it"),
        pytest.param([UV_TOOL, HOMEBREW, UV_TOOL], id="the middle run lacks it"),
        pytest.param([HOMEBREW, UV_TOOL, UV_TOOL], id="the first run lacks it"),
    ],
)
def test_a_path_one_of_three_runs_was_not_offered_is_left_out(hosts):
    runs = [[cpu_notice_on(host, found=AVX2)] for host in hosts]

    united = combined_support_notices(runs)

    assert _path_ids(united[0]) == OFFERED_EVERYWHERE


def test_the_paths_kept_stay_in_the_order_of_the_first_run():
    first = cpu_notice()
    second = cpu_notice(paths=[first.paths[3], first.paths[1]])

    united = combined_support_notices([[first], [second]])

    assert _path_ids(first) == [COMPAT_RUNTIME, *OFFERED_EVERYWHERE]
    assert _path_ids(united[0]) == ["x86-host-with-features", "ci-runner"]


def test_a_level_and_an_offer_that_differ_are_both_left_out(capture):
    compat_only = cpu_notice_on(UV_TOOL, found=AVX2)
    below_compat = cpu_notice_on(BELOW_COMPAT, found=AVX2_AND_FMA)

    united = combined_support_notices([[compat_only], [below_compat]])

    record = united[0]
    assert record.found is None
    assert record.facts == AGREED_CPU_FACTS
    assert _path_ids(record) == OFFERED_EVERYWHERE
    said = _the_one_said(capture)
    assert "found" in said
    assert "facts.cpu_level" in said
    assert f"paths.{COMPAT_RUNTIME}" in said


def test_control_the_same_paths_in_another_order_say_nothing(capture):
    first = cpu_notice()
    second = cpu_notice(paths=list(reversed(first.paths)))

    united = combined_support_notices([[first], [second]])

    assert _path_ids(united[0]) == _path_ids(first)
    assert _said(capture) == []


def test_control_a_path_worded_differently_keeps_the_first_runs_wording(capture):
    first = cpu_notice()
    reworded = [
        path.model_copy(update={"summary": "Another wording of the same path."})
        for path in first.paths
    ]
    second = cpu_notice(paths=reworded)

    united = combined_support_notices([[first], [second]])

    assert united[0].paths == first.paths
    assert _said(capture) == []


def test_a_record_that_left_paths_out_shares_no_object_with_a_run():
    uv_tool, homebrew = cpu_notices_of_two_installs()

    united = combined_support_notices([[uv_tool], [homebrew]])
    united[0].paths[0].summary = "changed"

    assert uv_tool == cpu_notices_of_two_installs()[0]
    assert homebrew == cpu_notices_of_two_installs()[1]


def test_every_other_field_is_the_first_runs():
    """What the register declares of a row is the same in every run of one ASH: its id,
    scope, dimension, level, behavior, polyfill, moment, sentence and docs anchor. A run
    of another version may word it otherwise, and the record then says it as the first
    run does. The three fields that hold what a run read or was offered, the facts, the
    found text and the paths, are the exception, and hold what every run recorded."""
    first = cpu_notice()
    second = cpu_notice(
        message="Another wording of the same row.",
        docs=f"{DOCS_PAGE}#another-anchor",
        paths=[],
    )

    united = combined_support_notices([[first], [second]])

    assert united[0].message == first.message
    assert united[0].docs == first.docs
    # The second run was offered no path, so no path is one both were offered: the
    # paths are not the first run's.
    assert united[0].paths == []


def test_the_order_is_the_order_the_runs_are_given_and_each_runs_own_order():
    united = combined_support_notices(
        [[polyfill_notice(), cpu_notice()], [sandbox_notice()]]
    )

    assert _ids(united) == [POLYFILL_ID, CPU_ID, SANDBOX_ID]


def test_a_run_with_no_notices_adds_none():
    united = combined_support_notices([None, [], [cpu_notice()], None])

    assert _ids(united) == [CPU_ID]


def test_no_notice_in_any_run_gives_none_which_is_how_a_supported_run_writes_it():
    assert combined_support_notices([]) is None
    assert combined_support_notices([None, []]) is None
    assert combined_support_notices(iter(())) is None


def test_the_runs_may_be_given_as_a_generator():
    united = combined_support_notices(
        notices for notices in ([cpu_notice()], [sandbox_notice()])
    )

    assert _ids(united) == [CPU_ID, SANDBOX_ID]


def test_the_list_shares_no_object_with_a_run_it_came_from():
    run = [cpu_notice()]

    united = combined_support_notices([run])
    united[0].message = "changed"
    united[0].paths[0].summary = "changed"

    assert run[0].message == cpu_notice().message
    assert run[0].paths[0].summary == cpu_notice().paths[0].summary


def test_combining_runs_that_met_a_notice_differently_leaves_every_run_as_it_was():
    near, far = cpu_notice_of_two_hosts()

    united = combined_support_notices([[near], [far]])
    united[0].facts["arch"] = "arm64"
    united[0].paths[0].summary = "changed"

    assert near == cpu_notice_of_two_hosts()[0]
    assert far == cpu_notice_of_two_hosts()[1]


def test_a_record_read_from_a_results_file_is_taken_as_a_notice():
    record = sandbox_notice().model_dump(mode="json")

    united = combined_support_notices([[record]])

    assert united == [sandbox_notice()]
    assert all(isinstance(notice, SupportNotice) for notice in united)


def test_records_read_from_results_files_are_combined_as_notices_are():
    near, far = cpu_notice_of_two_hosts()

    united = combined_support_notices(
        [[near.model_dump(mode="json")], [far.model_dump(mode="json")]]
    )

    assert united[0].found is None
    assert united[0].facts == AGREED_CPU_FACTS


def test_a_malformed_record_is_refused_not_dropped():
    with pytest.raises(ValueError):
        combined_support_notices([[{"id": CPU_ID}]])


# What the list says when a record leaves something out ----------------------------


def test_a_notice_met_differently_is_named_with_its_runs_and_what_it_lost(capture):
    near, far = cpu_notice_of_two_hosts()

    combined_support_notices([[near], [far]], labels=["shard 1", "shard 3"])

    said = _the_one_said(capture)
    assert capture.records[0].levelno == logging.WARNING
    assert CPU_ID in said
    assert "shard 1 and shard 3" in said
    assert "found" in said
    assert "facts.cpu_level" in said
    # The two hosts were offered the same paths, so the record keeps them all.
    assert "paths" not in said


def test_the_warning_names_what_differed_and_never_what_the_runs_read(capture):
    near, far = cpu_notice_of_two_hosts()

    combined_support_notices([[near], [far]])

    said = _the_one_said(capture)
    # The architecture and the runtime are what both runs read and the record holds, so
    # they are not named. The flags and the level are what each host read, and a log
    # does not repeat a read.
    assert "facts.arch" not in said
    assert "facts.polars_runtime" not in said
    for read in ("avx2", "bmi2", "compat-only", "below-compat"):
        assert read not in said


def test_only_the_found_text_is_named_when_only_it_differed(capture):
    combined_support_notices(
        [[cpu_notice(found=AVX2)], [cpu_notice(found=AVX2_AND_FMA)]]
    )

    said = _the_one_said(capture)
    assert "found" in said
    assert "facts." not in said
    assert "paths" not in said


@pytest.mark.parametrize(
    ("per_run", "named", "not_named"),
    [
        pytest.param(
            [GLIBC, {"arch": "amd64", "libc": "musl"}],
            ["libc"],
            ["arch"],
            id="a fact with another token in the second run",
        ),
        pytest.param(
            [GLIBC, {"arch": "amd64"}],
            ["libc"],
            ["arch"],
            id="a fact only the first run read",
        ),
        pytest.param(
            [{"arch": "amd64"}, GLIBC],
            ["libc"],
            ["arch"],
            id="a fact only the second run read",
        ),
        pytest.param(
            [{"arch": "amd64"}, {"libc": "glibc"}],
            ["arch", "libc"],
            [],
            id="no fact in common",
        ),
        pytest.param(
            [GLIBC, GLIBC, {"arch": "amd64", "libc": "musl"}],
            ["libc"],
            ["arch"],
            id="a fact the last of three runs read otherwise",
        ),
        pytest.param(
            [GLIBC, {"arch": "arm64", "libc": "glibc"}, GLIBC],
            ["arch"],
            ["libc"],
            id="a fact the middle of three runs read otherwise",
        ),
    ],
)
def test_only_the_facts_that_differed_are_named(capture, per_run, named, not_named):
    combined_support_notices([[cpu_notice(facts=facts)] for facts in per_run])

    said = _the_one_said(capture)
    assert all(f"facts.{name}" in said for name in named), said
    assert not any(f"facts.{name}" in said for name in not_named), said
    assert "found" not in said
    assert "paths" not in said


@pytest.mark.parametrize(
    "uv_tool_first", [True, False], ids=["uv tool first", "homebrew first"]
)
def test_a_path_not_every_run_was_offered_is_named_in_the_log(capture, uv_tool_first):
    uv_tool, homebrew = cpu_notices_of_two_installs()
    runs = [[uv_tool], [homebrew]] if uv_tool_first else [[homebrew], [uv_tool]]

    combined_support_notices(runs, labels=["shard 0", "shard 1"])

    said = _the_one_said(capture)
    assert CPU_ID in said
    assert "shard 0 and shard 1" in said
    assert f"paths.{COMPAT_RUNTIME}" in said
    # The runs recorded the same facts and the same text, and the paths both were
    # offered stay in the record, so none of those is named.
    assert "found" not in said
    assert "facts." not in said
    assert not any(path in said for path in OFFERED_EVERYWHERE)


def test_each_path_left_out_is_named_and_none_that_is_kept(capture):
    first = cpu_notice()
    second = cpu_notice(paths=[first.paths[3], first.paths[1]])

    combined_support_notices([[first], [second]])

    said = _the_one_said(capture)
    assert f"paths.{COMPAT_RUNTIME}" in said
    assert "paths.arm64-host" in said
    assert "paths.x86-host-with-features" not in said
    assert "paths.ci-runner" not in said


def test_each_notice_that_lost_something_is_named_once_and_no_other_is(capture):
    near, far = cpu_notice_of_two_hosts()
    other_polyfill = polyfill_notice(facts={"tool_sandbox": "native"})

    combined_support_notices(
        [
            [near, sandbox_notice(), polyfill_notice()],
            [far, sandbox_notice(), other_polyfill],
        ]
    )

    said = _said(capture)
    assert len(said) == 2, said
    assert CPU_ID in said[0] and POLYFILL_ID not in said[0]
    assert POLYFILL_ID in said[1] and CPU_ID not in said[1]
    assert not any(SANDBOX_ID in message for message in said)


def test_control_runs_that_read_a_notice_alike_say_nothing(capture):
    near, _ = cpu_notice_of_two_hosts()

    combined_support_notices(
        [[near], [near.model_copy(deep=True)], [near.model_copy(deep=True)]]
    )

    assert _said(capture) == []


def test_control_a_notice_only_one_run_recorded_says_nothing(capture):
    combined_support_notices([[cpu_notice()], [sandbox_notice()], None])

    assert _said(capture) == []


def test_control_the_same_facts_in_another_order_say_nothing(capture):
    first = cpu_notice(facts={"libc": "glibc", "arch": "amd64"})
    second = cpu_notice(facts={"arch": "amd64", "libc": "glibc"})

    combined_support_notices([[first], [second]])

    assert _said(capture) == []


def test_runs_with_no_names_are_named_by_their_position(capture):
    near, far = cpu_notice_of_two_hosts()

    combined_support_notices([None, [near], [far]])

    said = _the_one_said(capture)
    assert "run 2 and run 3" in said
    assert "run 1" not in said


def test_a_run_beyond_the_names_given_is_named_by_its_position(capture):
    near, far = cpu_notice_of_two_hosts()

    combined_support_notices([[near], [far]], labels=["shard 4"])

    assert "shard 4 and run 2" in _the_one_said(capture)


def test_three_runs_are_named_as_a_list(capture):
    near, far = cpu_notice_of_two_hosts()

    combined_support_notices([[near], [far], [far.model_copy(deep=True)]])

    assert "run 1, run 2, and run 3" in _the_one_said(capture)


def test_the_warning_is_not_read_as_markup(capture):
    near, far = cpu_notice_of_two_hosts()

    combined_support_notices([[near], [far]], labels=["[bold]a", "[/]b"])

    record = capture.records[0]
    assert record.markup is False
    assert "[bold]a and [/]b" in record.getMessage()
