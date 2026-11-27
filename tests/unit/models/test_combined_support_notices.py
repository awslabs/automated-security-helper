"""Several runs' support notices as one list: each id once, holding what every run read.

Why this exists
---------------
The two outputs that combine runs, the workspace results file (its projects) and
``ash merge`` (its shards), each have to say what every run met. The runs can be on
different hosts, and a notice records what its own host read: the processor flags that
were missing, the level the processor is at. Two hosts that meet the same row do not
read the same of it, so a list that kept the first run's record would publish one
host's flags and facts as if they were the scan's. Both outputs build the combined
list with ``combined_support_notices``, which this file pins on its own so each
output's own test can say only what it adds.

The rule: one record per notice id, the first run's in every field the row declares,
except that what the runs read is only what every run read. ``facts`` holds the pairs
every run recorded, ``found`` is kept when every run recorded the same text and is
None when they did not, and nothing else is added to the record.
"""

import pytest

from automated_security_helper.models.asharp_model import (
    SupportNotice,
    combined_support_notices,
)
from tests.unit.models._support_notice_helpers import (
    AGREED_CPU_FACTS,
    CPU_ID,
    DOCS_PAGE,
    POLYFILL_ID,
    SANDBOX_ID,
    cpu_notice,
    cpu_notice_of_two_hosts,
    polyfill_notice,
    sandbox_notice,
)

pytestmark = pytest.mark.unit

AVX2 = "avx2 is missing (polars-runtime-32 1.44.2)."
AVX2_AND_FMA = "avx2 and fma are missing (polars-runtime-32 1.44.2)."


def _ids(notices) -> list[str]:
    return [notice.id for notice in notices]


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


def test_every_other_field_is_the_first_runs():
    """A row says the same of itself in every run of one ASH. A run of another version
    may word it otherwise, and the record is then the first run's, whole."""
    first = cpu_notice()
    second = cpu_notice(
        message="Another wording of the same row.",
        docs=f"{DOCS_PAGE}#another-anchor",
        paths=[],
    )

    united = combined_support_notices([[first], [second]])

    assert united[0].message == first.message
    assert united[0].docs == first.docs
    assert united[0].paths == first.paths


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
