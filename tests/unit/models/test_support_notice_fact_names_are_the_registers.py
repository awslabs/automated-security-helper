"""A support notice's facts carry the names the support register declares, and no others.

Why this exists
---------------
A notice says which facts of the host a row matched (``arch amd64``, ``cpu_level
compat-only``), so a reader can see what ASH read. The register declares the facts a
host reader fills and nothing else (``base.support_register.FIELDS``). A notice that
took any name for a fact would take ``host`` or ``user`` as readily as ``arch``, and
results are shared: uploaded as CI artifacts, merged across machines, attached to
tickets. So the names are a closed list, the register's own, and a name outside it is
refused whatever value goes with it. The refusal names the field and quotes neither
the name nor the value it was given.

The tests are in three groups. A name the register does not declare is refused,
among them the names that say a host or a user and names that are one (the must-flag
side). Every name the register declares is accepted, with every token it can read (the
must-not-flag side, so a list that refused everything would fail). And the schema
lists the names, so a reader of the schema sees the closed list.
"""

import pytest
from pydantic import ValidationError

from automated_security_helper.base.support_register import FIELDS, VOCABULARY
from automated_security_helper.models.asharp_model import SupportNotice
from tests.unit.models._support_notice_helpers import cpu_notice

pytestmark = pytest.mark.unit

#: Names no host reader fills. The last four are not names of a fact at all: they are
#: what a fact would hold, put where the name goes.
UNDECLARED_NAMES = {
    "a host": "host",
    "a user": "user",
    "a host name": "hostname",
    "a user name": "username",
    "a home": "home",
    "a machine": "machine",
    "a host name as the name": "build-07.corp.example.com",
    "a user name as the name": "alice",
    "a user at a host as the name": "alice@build-07",
    "an instance name as the name": "ip-10-0-12-34",
}

#: What the writer would have put as the value, so the refusal can be checked not to
#: repeat it.
VALUE = "build-07"


@pytest.mark.parametrize("name", UNDECLARED_NAMES.values(), ids=list(UNDECLARED_NAMES))
def test_a_fact_the_register_does_not_declare_is_refused(name):
    with pytest.raises(ValidationError) as refused:
        cpu_notice(facts={**cpu_notice().facts, name: VALUE})

    message = str(refused.value)
    # The refusal names the field and quotes nothing it was given.
    assert "facts" in message
    assert name not in message
    assert VALUE not in message


def test_a_notice_read_from_a_results_file_is_refused_the_same_way():
    record = cpu_notice().model_dump(mode="json")
    record["facts"]["user"] = "alice"

    with pytest.raises(ValidationError) as refused:
        SupportNotice.model_validate(record)

    assert "alice" not in str(refused.value)


@pytest.mark.parametrize("name", FIELDS)
def test_control_every_fact_the_register_declares_is_accepted(name):
    notice = cpu_notice(facts={name: "probe"})

    assert notice.facts == {name: "probe"}


def test_control_every_token_the_register_can_read_is_accepted():
    """The names are closed and the tokens are not: a token is the value a reader
    wrote, and the register's vocabulary is what it can write."""
    tokens = [(name, token) for name, words in VOCABULARY.items() for token in words]

    assert len(tokens) > 40
    for name, token in tokens:
        assert cpu_notice(facts={name: token}).facts == {name: token}


def test_control_a_free_text_fact_is_accepted_as_the_register_declares_it():
    """``os_release`` is the one fact the register declares as free text, so that a
    notice can show what ASH read; it is a version string, never a path."""
    for text in ("6.12.115-140.210.amzn2023.x86_64", "Ubuntu 24.04.1 LTS", "14.7.1"):
        assert cpu_notice(facts={"os_release": text}).facts == {"os_release": text}


def test_the_schema_lists_the_names_a_fact_may_have():
    schema = SupportNotice.model_json_schema()

    names = schema["properties"]["facts"]["propertyNames"]["enum"]

    assert sorted(names) == sorted(FIELDS)
