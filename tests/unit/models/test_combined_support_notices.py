"""Several runs' support notices as one list: each notice id once, first record kept.

Why this exists
---------------
The two outputs that combine runs, the workspace results file (its projects) and
``ash merge`` (its shards), each have to say what every run met. The runs can be on
different hosts, so the first run's list alone would describe one host only. Both
outputs build the combined list with ``combined_support_notices``, which this file
pins on its own so each output's own test can say only what it adds.
"""

import pytest

from automated_security_helper.models.asharp_model import (
    SupportNotice,
    combined_support_notices,
)
from tests.unit.models._support_notice_helpers import (
    CPU_ID,
    POLYFILL_ID,
    SANDBOX_ID,
    cpu_notice,
    polyfill_notice,
    sandbox_notice,
)

pytestmark = pytest.mark.unit


def _ids(notices) -> list[str]:
    return [notice.id for notice in notices]


def test_every_runs_notice_is_kept():
    united = combined_support_notices(
        [[cpu_notice()], [sandbox_notice(), polyfill_notice()]]
    )

    assert _ids(united) == [CPU_ID, SANDBOX_ID, POLYFILL_ID]


def test_a_notice_two_runs_share_is_listed_once_with_the_first_runs_record():
    first = cpu_notice(found="avx2 is missing (polars-runtime-32 1.44.2).")
    second = cpu_notice(found="avx2 and fma are missing (polars-runtime-32 1.44.2).")

    united = combined_support_notices([[first], [second, sandbox_notice()]])

    assert _ids(united) == [CPU_ID, SANDBOX_ID]
    assert united[0].found == first.found


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


def test_a_record_read_from_a_results_file_is_taken_as_a_notice():
    record = sandbox_notice().model_dump(mode="json")

    united = combined_support_notices([[record]])

    assert united == [sandbox_notice()]
    assert all(isinstance(notice, SupportNotice) for notice in united)


def test_a_malformed_record_is_refused_not_dropped():
    with pytest.raises(ValueError):
        combined_support_notices([[{"id": CPU_ID}]])
