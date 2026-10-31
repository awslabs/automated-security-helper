"""A failing assertion about an environment prints names, never the other values.

A mock's ``assert_called_once_with(..., env=...)``, or ``assert "K" not in
os.environ``, prints the whole environment when it fails, and a token in the
developer's or the CI runner's environment with it. The tests compare names, and
the values of the names they are about (tests/utils/env_assertions.py). This runs
each of those shapes failing on purpose, in a pytest process whose environment
holds a sentinel variable no assertion is about, and checks that no failure
prints the sentinel's value. The controls (``CONTROLS``) are plain-copy shapes
that do print it: each is one way a failing test holds, reaches or is handed
a copy of the environment, and the tuple is their list. They fail the same
way the shapes (``SHAPES``, the name and named-value forms that must print no
value) do, so the check is not blind. The child runs under a conftest that
does what the repository's root conftest does (``CHILD_CONFTEST``): it calls
``hide_environ_values``, so every shape is measured with ``os.environ``'s repr
already names-only to pytest's reporting, and its ``pytest_assertrepr_compare``
explains a comparison that involves an environment mapping by names. The
child's first cell checks that the ASH it imports is this checkout's. A second
child (``COMPARISONS``) compares environment mappings, a fixture's value among
them, in each of five configurations of the run, against plain-copy controls
that keep pytest's own diff; and this run's own hook order is measured in
process.
"""

from __future__ import annotations

import ast
import dataclasses
import enum
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import (
    Callable,
    Dict,
    Iterator,
    List,
    Mapping,
    NamedTuple,
    Optional,
    Sequence,
    Tuple,
)
from unittest import mock

import defusedxml.ElementTree as ET
import pytest

from tests.utils import env_assertions
from tests.utils.env_assertions import (
    NamesOnlyEnvironment,
    assertrepr_compare_order_problems,
    explain_environment_comparison,
)
from tests.utils.helpers import ASH_TEST_TEMP_ROOT, checkout_env

REPOSITORY = Path(__file__).resolve().parents[2]

SENTINEL = "ASH_TEST_SENTINEL_SECRET"
NAMED = "ASH_TEST_NAMED_VARIABLE"

CHILD = f"""\
import collections
import copy
import itertools
import json
import os
import subprocess
import types
from collections import OrderedDict
from os import environ as imported_environ
from os import environ as rebound_environ
from pathlib import Path
from typing import Any
from unittest import mock

import pydantic
import pytest

import automated_security_helper
from tests.utils.env_assertions import (
    NamesOnlyEnvironment,
    differing_names,
    environ_names,
    environ_value,
)
from tests.utils.helpers import checkout_env

SENTINEL = {SENTINEL!r}
NAMED = {NAMED!r}
CHECKOUT = Path({str(REPOSITORY)!r})

# An environ imported from os, then rebound to a plain copy: the name is a
# copy now, whatever it was imported as.
rebound_environ = {{SENTINEL: rebound_environ[SENTINEL], **rebound_environ}}

# A module name a helper rebinds to a copy through a global declaration.
global_env = os.environ

# An alias of the rebound environ above, a names-only module name a function
# rebinds locally, and one a helper's parameter shadows.
aliased_rebound_environ = rebound_environ
parent_env = os.environ
shadowed_env = os.environ


def test_the_ash_imported_is_this_checkout():
    imported = Path(automated_security_helper.__file__).resolve()
    assert imported.is_relative_to(CHECKOUT.resolve()), imported


def _run_with_the_environment():
    run = mock.Mock()
    run(["git", "diff"], cwd=None, env=dict(os.environ), stdin=subprocess.DEVNULL)
    return run


def test_control_a_whole_mapping():
    env = dict(os.environ)
    assert env == {{}}


def test_control_a_mocks_called_with():
    run = _run_with_the_environment()
    run.assert_called_once_with(["git", "diff"], cwd=None, env={{}})


def test_a_name_that_is_set():
    assert SENTINEL not in environ_names()


def test_a_named_value():
    assert environ_value(NAMED) == "expected"


def test_a_named_value_that_is_unset():
    assert environ_value("ASH_TEST_UNSET_VARIABLE") == "expected"


def test_the_names_that_differ():
    assert differing_names(dict(os.environ), {{}}) == []


def test_a_mocks_call_count():
    run = _run_with_the_environment()
    assert run.call_count == 2


def test_a_mocks_env_narrowed_to_its_names():
    run = _run_with_the_environment()
    _, kwargs = run.call_args
    names = set(kwargs["env"])
    assert SENTINEL not in names


def test_control_a_set_of_a_copy_inline():
    # Unlike the narrowed form above, the copy stays inside the assertion, so
    # pytest's "where" chain prints the copy's own repr, values and all.
    env = _sentinel_first()
    assert SENTINEL not in set(env)


def test_a_set_of_os_environ_inline():
    # The same inline shape over os.environ itself: the "where" chain prints
    # os.environ's repr, which the root conftest shows as names only.
    assert "ASH_TEST_UNSET_VARIABLE" in set(os.environ)


def test_a_mocks_env_narrowed_to_a_named_value():
    run = _run_with_the_environment()
    _, kwargs = run.call_args
    value = kwargs["env"].get(NAMED)
    assert value == "expected"


def _sentinel_first():
    # pytest cuts each argument it prints to about 240 characters, so the
    # sentinel goes first, where it would be shown.
    return {{SENTINEL: os.environ[SENTINEL], **os.environ}}


def _fails_given(env):
    assert 1 == 2


class _Carrier:
    # A helper object that keeps the environment it was built with, as a
    # runner or request object does. pytest prints a failing frame's arguments
    # with repr, and this __repr__ rebuilds the mapping's repr from the
    # carrier's own frame, not pytest's.
    def __init__(self, env):
        self.env = env

    def __repr__(self):
        return f"_Carrier(env={{self.env!r}})"


def test_control_a_helper_given_a_copy():
    _fails_given(_sentinel_first())


def test_control_a_pass_through_bound_to_a_copy():
    # The call sits at a binding, so only the later assertion prints: set()
    # shows the names, and its argument's repr shows the values.
    clone = lambda env: dict(env)  # noqa: E731
    copy = clone(_sentinel_first())
    assert "K" in set(copy)


def test_a_helper_given_checkout_env():
    _fails_given(checkout_env(_sentinel_first()))


def test_a_helper_given_a_carried_environment():
    _fails_given(_Carrier(checkout_env(_sentinel_first())))


def test_a_name_in_the_environments_keys():
    assert "ASH_TEST_UNSET_VARIABLE" in os.environ.keys()


def test_a_name_in_the_sorted_keys():
    assert "ASH_TEST_UNSET_VARIABLE" in sorted(os.environ.keys())


def test_a_set_name_not_in_the_sorted_keys():
    assert NAMED not in sorted(os.environ.keys())


def test_a_name_in_a_set_of_the_environments_keys():
    assert "ASH_TEST_UNSET_VARIABLE" in set(os.environ.keys())


def test_control_a_set_of_a_copys_keys():
    # pytest explains ``env.keys`` by printing its receiver: for a plain copy
    # that repr is the whole mapping, values and all.
    env = _sentinel_first()
    assert SENTINEL not in set(env.keys())


def test_a_set_of_an_alias_of_the_environment():
    env = os.environ
    assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_a_set_of_a_checkout_env_mapping():
    env = checkout_env(_sentinel_first())
    assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_control_a_copy_bound_in_one_branch():
    flag = True
    if flag:
        env = _sentinel_first()
    else:
        env = os.environ
    assert SENTINEL not in set(env)


def test_control_rebound_to_a_copy_after_the_assert():
    # The assert sits before the rebinding in the source, and runs after it.
    env = os.environ
    for attempt in range(2):
        if attempt:
            assert SENTINEL not in set(env)
        env = _sentinel_first()


def test_control_rebound_by_a_union():
    env = os.environ
    env = env | {{NAMED: "expected"}}
    assert SENTINEL not in set(env)


def test_control_an_imported_environ_rebound_to_a_copy():
    assert SENTINEL not in set(rebound_environ)


def test_control_a_copy_inside_a_names_only_wrapper():
    # pytest explains the wrapper call's argument: the copy, values and all.
    assert SENTINEL not in set(NamesOnlyEnvironment(_sentinel_first()))


def test_control_a_nonlocal_rebinding_to_a_copy():
    env = os.environ

    def rebind():
        nonlocal env
        env = _sentinel_first()

    rebind()
    assert SENTINEL not in set(env)


def test_control_a_nonlocal_through_a_non_binding_middle():
    env = os.environ

    def middle():
        def inner():
            nonlocal env
            env = _sentinel_first()

        inner()

    middle()
    assert SENTINEL not in set(env)


def test_control_a_nonlocal_from_a_method_across_a_class():
    env = os.environ

    class Holder:
        def rebind(self):
            nonlocal env
            env = _sentinel_first()

    Holder().rebind()
    assert SENTINEL not in set(env)


def _rebind_global_env():
    global global_env
    global_env = _sentinel_first()


def test_control_a_global_rebinding_to_a_copy():
    _rebind_global_env()
    assert SENTINEL not in set(global_env)


def test_a_nonlocal_rebinding_to_a_names_only_mapping():
    env = os.environ

    def rebind():
        nonlocal env
        env = checkout_env(_sentinel_first())

    rebind()
    assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_control_an_alias_of_a_rebound_imported_environ():
    assert SENTINEL not in set(aliased_rebound_environ)


def test_control_a_function_rebinds_a_names_only_module_name():
    parent_env = _sentinel_first()
    assert SENTINEL not in set(parent_env)


def _check_shadowed(shadowed_env):
    assert SENTINEL not in set(shadowed_env)


def test_control_a_parameter_shadows_a_names_only_module_name():
    _check_shadowed(_sentinel_first())


def test_control_a_lambda_returning_a_copy():
    get = lambda env=_sentinel_first(): env
    assert SENTINEL not in set(get())


def test_control_a_walrus_in_a_lambda_default():
    env = os.environ
    get = lambda value=(env := _sentinel_first()): value
    assert SENTINEL not in set(env)


def test_control_a_walrus_in_a_function_default():
    env = os.environ

    def helper(value=(env := _sentinel_first())):
        return value

    assert SENTINEL not in set(env)


def test_control_an_annotated_lambda_returning_a_copy():
    get: object = lambda env=_sentinel_first(): env
    assert SENTINEL not in set(get())


def test_control_an_inline_called_lambda_returning_a_copy():
    assert SENTINEL not in set((lambda env=_sentinel_first(): env)())


def test_control_a_lambda_bound_by_tuple_unpacking():
    get_t, _ = (lambda: _sentinel_first()), None
    assert SENTINEL not in set(get_t())


def test_control_a_lambda_bound_by_a_walrus():
    if (get_v := lambda: _sentinel_first()):
        assert SENTINEL not in set(get_v())


def test_control_a_lambda_whose_body_is_a_walrus():
    get = lambda: (env := _sentinel_first())
    assert SENTINEL not in set(get())


def test_a_walrus_of_the_environment_in_an_argument():
    assert "ASH_TEST_UNSET_VARIABLE" in set(env := os.environ)


def test_an_inline_called_lambda_reading_one_value():
    assert (lambda env=_sentinel_first(): env[NAMED])() == "expected"


def test_a_lambda_reading_one_value():
    env = _sentinel_first()
    get = lambda: env[NAMED]
    assert get() == "expected"


def test_control_a_class_body_copy():
    class Holder:
        env = _sentinel_first()
        assert SENTINEL not in set(env)


def test_a_class_body_alias_of_the_environment():
    class Holder:
        env = os.environ
        assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_a_class_body_imported_environ():
    class Holder:
        from os import environ

        assert "ASH_TEST_UNSET_VARIABLE" in set(environ)


def test_control_a_get_through_a_copy_in_an_argument():
    # pytest explains env.get by its receiver: the bound method's repr holds
    # the copy, values and all.
    env = _sentinel_first()
    assert SENTINEL in differing_names(env.get("ASH_TEST_UNSET_VARIABLE", {{}}), {{}})


def test_a_named_get_in_a_literal_argument():
    # A literal is shown by its value: the named value only.
    env = _sentinel_first()
    assert NAMED not in differing_names({{NAMED: env.get(NAMED)}}, {{NAMED: "expected"}})


def test_control_a_set_of_a_copy_of_an_alias_of_the_environment():
    # os.environ.copy() is a plain dict.
    env = os.environ
    assert SENTINEL not in set(env.copy())


def test_a_set_of_a_copy_of_a_checkout_env_mapping():
    # NamesOnlyEnvironment.copy keeps the type, and the bound method's repr
    # holds the names-only repr.
    env = checkout_env(_sentinel_first())
    assert "ASH_TEST_UNSET_VARIABLE" in set(env.copy())


def test_control_a_copy_inside_a_names_only_copy_receiver():
    # Unlike the bound name above, the receiver is built inside the assertion,
    # so the "where" chain prints checkout_env's argument, values and all.
    assert SENTINEL not in set(checkout_env(_sentinel_first()).copy())


def test_a_generator_over_a_copy_in_an_argument():
    env = _sentinel_first()
    assert SENTINEL not in differing_names(dict((k, "x") for k in env), {{}})


def test_a_comprehension_of_a_copys_names_in_an_argument():
    env = _sentinel_first()
    assert SENTINEL not in differing_names({{k: "x" for k in env}}, {{}})


def test_a_named_subscript_of_a_copy_in_a_literal_argument():
    env = _sentinel_first()
    assert NAMED not in differing_names({{NAMED: env[NAMED]}}, {{NAMED: "expected"}})


def test_a_named_subscript_of_a_copy_as_an_argument():
    # The copy holds a mapping under one name; the argument reads it by name.
    env = {{"nested": {{NAMED: "actual"}}, **_sentinel_first()}}
    assert NAMED not in differing_names(env["nested"], {{NAMED: "expected"}})


def test_a_set_of_checkout_env_given_a_literal():
    assert "ASH_TEST_UNSET_VARIABLE" in set(checkout_env({{NAMED: "expected"}}))


def test_a_set_of_names_only_bindings_in_both_branches():
    flag = False
    if flag:
        env = os.environ
    else:
        env = checkout_env(_sentinel_first())
    assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_control_a_copy_as_a_boolop_operand():
    # pytest explains each operand a call's argument was computed from, so the
    # copy inside ``env or {{}}`` is printed even though the argument node is
    # the BoolOp, not the copy.
    env = _sentinel_first()
    assert SENTINEL not in differing_names(env or {{}}, {{}})


def test_an_item_in_a_names_only_environments_items():
    env = checkout_env(_sentinel_first())
    assert (NAMED, "expected") in env.items()


def test_a_value_in_a_names_only_environments_values():
    env = checkout_env(_sentinel_first())
    assert "expected" in env.values()


def test_control_a_plain_start_rebound_to_a_copy_in_a_loop():
    env = {{}}
    for _ in range(2):
        assert SENTINEL not in set(env)
        env = _sentinel_first()


def _grow_global_env():
    global global_grown_env
    global_grown_env = _sentinel_first()


global_grown_env = {{}}


def test_control_a_global_rebinding_from_a_plain_start():
    _grow_global_env()
    assert SENTINEL not in set(global_grown_env)


def test_control_a_nonlocal_rebinding_from_a_plain_start():
    env = {{}}

    def _grow():
        nonlocal env
        env = _sentinel_first()

    _grow()
    assert SENTINEL not in set(env)


def _shadow_global_env():
    global shadowed_global_env
    snapshot_env = _sentinel_first()
    shadowed_global_env = snapshot_env


shadowed_global_env = os.environ
snapshot_env = os.environ


def test_control_a_cross_scope_shadow_of_a_names_only_name():
    _shadow_global_env()
    assert SENTINEL not in set(shadowed_global_env)


def test_control_a_bound_lambda_returning_an_enclosing_copy():
    env = _sentinel_first()
    get = lambda: env  # noqa: E731
    assert SENTINEL not in set(get())


def test_control_a_function_returning_an_enclosing_copy():
    env = _sentinel_first()

    def get():
        return env

    assert SENTINEL not in set(get())


below_env = _sentinel_first()


def test_control_a_module_copy_bound_below_the_tests():
    assert SENTINEL not in set(below_env)


def test_control_a_copy_bound_through_a_conditional_expression():
    flag = True
    env = _sentinel_first() if flag else {{}}
    assert SENTINEL not in set(env)


def test_control_a_copy_bound_through_an_or():
    env = _sentinel_first() or {{}}
    assert SENTINEL not in set(env)


def test_control_a_union_with_the_environment_bound():
    # dict | os.environ is a new plain dict, the sentinel first.
    env = {{SENTINEL: os.environ[SENTINEL]}} | os.environ
    assert SENTINEL not in set(env)


def test_control_a_recorded_calls_env_or_an_empty_dict():
    # The get is explained by its receiver, the env the call was given.
    run = mock.Mock()
    run(env=_sentinel_first())
    env = run.call_args.kwargs.get("env") or {{}}
    assert SENTINEL in str(env.get("ASH_TEST_UNSET_VARIABLE", ""))


def test_control_a_copy_bound_as_a_loop_target():
    for env in [_sentinel_first()]:
        assert SENTINEL not in set(env)


def test_control_a_lambda_bound_through_a_conditional_expression():
    flag = True
    get = (lambda: _sentinel_first()) if flag else None
    assert SENTINEL not in set(get())


def test_control_a_lambda_bound_as_a_loop_target():
    for get in [lambda: _sentinel_first()]:
        assert SENTINEL not in set(get())


@pytest.fixture
def conditional_env():
    flag = True
    return _sentinel_first() if flag else {{}}


def test_control_a_fixture_returning_a_conditional_copy(conditional_env):
    assert 1 == 2


def test_a_names_only_mapping_or_an_empty_literal_through_a_conditional():
    flag = True
    env = os.environ if flag else {{}}
    assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_a_union_of_names_only_operands_as_an_argument():
    # pytest explains each operand of the union, not its result.
    assert "ASH_TEST_UNSET_VARIABLE" in set(os.environ | {{NAMED: "x"}})


def test_a_names_only_call_of_a_copy_as_an_ifexp_branch():
    # The IfExp is shown by its value; nothing inside it is explained.
    flag = True
    assert "ASH_TEST_UNSET_VARIABLE" in set(
        checkout_env(_sentinel_first()) if flag else {{}}
    )


@pytest.fixture
def conditional_names_only_env():
    flag = True
    return checkout_env(_sentinel_first()) if flag else {{}}


def test_a_fixture_returning_a_conditional_names_only_mapping(
    conditional_names_only_env,
):
    assert 1 == 2


# One cell per loop item: the assertion fails on the first iteration, so a
# single loop over both would only ever measure what its first item prints.
def test_a_names_only_loop_target_of_the_environment():
    for env in [os.environ, checkout_env(_sentinel_first())]:
        assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_a_names_only_loop_target_of_a_checkout_env():
    for env in [checkout_env(_sentinel_first()), os.environ]:
        assert "ASH_TEST_UNSET_VARIABLE" in set(env)


def test_control_a_copy_as_an_ifexp_branch_in_an_argument():
    # pytest has no IfExp handler: the IfExp is shown by its value, the
    # chosen branch, as the call's argument.
    env = _sentinel_first()
    flag = True
    assert SENTINEL not in set(env if flag else {{}})


def _environ_itself():
    return os.environ


def _a_names_only_copy_source():
    return checkout_env(_sentinel_first())


def _environ_or_a_copy(flag):
    if flag:
        return os.environ
    return _sentinel_first()


def test_a_closure_returning_a_names_only_mapping():
    env = os.environ
    get = lambda: env  # noqa: E731
    assert "ASH_TEST_UNSET_VARIABLE" in set(get())


def test_a_function_returning_os_environ():
    assert "ASH_TEST_UNSET_VARIABLE" in set(_environ_itself())


def test_an_inline_lambda_returning_os_environ():
    assert "ASH_TEST_UNSET_VARIABLE" in set((lambda: os.environ)())


def test_a_copy_of_a_names_only_environment_a_function_returns():
    # NamesOnlyEnvironment.copy keeps the type.
    assert "ASH_TEST_UNSET_VARIABLE" in set(_a_names_only_copy_source().copy())


def test_control_a_function_returning_os_environ_or_a_copy():
    assert SENTINEL not in set(_environ_or_a_copy(False))


def test_control_a_copy_of_os_environ_a_function_returns():
    # os.environ.copy() is a plain dict.
    assert SENTINEL not in set(_environ_itself().copy())


def test_control_a_closure_over_a_names_only_name_rebound_to_a_copy():
    env = os.environ
    get = lambda: env  # noqa: E731
    env = _sentinel_first()
    assert SENTINEL not in set(get())


def test_control_a_copy_passed_through_a_parameter_shadowing_it():
    env = _sentinel_first()
    clone = lambda env: dict(env)  # noqa: E731
    assert SENTINEL not in set(clone(env))


def test_a_lambda_parameter_shadowing_an_enclosing_copy():
    # clone's value is its argument, a literal here.
    env = _sentinel_first()
    clone = lambda env: dict(env)  # noqa: E731
    assert "ASH_TEST_UNSET_VARIABLE" in set(clone({{NAMED: "x"}}))


def test_control_a_copys_values_as_an_ifexp_branch():
    # The IfExp's value, a list of every value, is shown.
    env = _sentinel_first()
    flag = True
    assert NAMED in set(list(env.values()) if flag else [])


def test_control_a_copys_values_as_an_ifexp_branch_in_the_assertion():
    env = _sentinel_first()
    flag = True
    assert (list(env.values()) if flag else []) == []


def test_a_get_with_a_default_as_an_ifexp_branch_in_an_argument():
    # Shown by its value, an empty dict here: the get is not explained by its
    # receiver.
    env = _sentinel_first()
    flag = True
    assert "ASH_TEST_UNSET_VARIABLE" in differing_names(
        env.get("ASH_TEST_UNSET_CHILD", {{}}) if flag else {{}}, {{NAMED: "x"}}
    )


def test_a_named_get_as_an_ifexp_branch_in_the_assertion():
    env = _sentinel_first()
    flag = True
    assert (env.get(NAMED) if flag else None) == "expected"


def test_an_ifexp_condition_inside_a_comprehension_result():
    env = _sentinel_first()
    assert {{k: ("set" if env.get(k) else "unset") for k in sorted(env)}} == {{}}


def test_a_copy_only_in_an_ifexp_condition_in_an_argument():
    # The condition's value is never shown; only the chosen branch is.
    env = _sentinel_first()
    assert "ASH_TEST_UNSET_VARIABLE" in set({{NAMED: "expected"}} if env else {{}})


def test_control_a_copy_as_an_ifexp_branch_in_a_literal_item():
    env = _sentinel_first()
    flag = True
    assert NAMED not in differing_names({{NAMED: env if flag else "x"}}, {{}})


def test_a_copy_only_in_an_ifexp_condition_in_a_literal_item():
    env = _sentinel_first()
    assert NAMED not in differing_names(
        {{NAMED: env[NAMED] if env else "x"}}, {{NAMED: "other"}}
    )


def test_control_a_copy_as_an_ifexp_branch_in_the_message():
    env = _sentinel_first()
    flag = True
    assert 1 == 2, (env if flag else {{}})


def test_a_copy_only_in_an_ifexp_condition_in_the_message():
    env = _sentinel_first()
    assert 1 == 2, ("yes" if env else "no")


fixture_env = _sentinel_first()


@pytest.fixture
def enclosing_env():
    return fixture_env


def test_control_a_fixture_returning_an_enclosing_copy(enclosing_env):
    assert 1 == 2


@pytest.fixture
def annotated_shadow_env():
    # Shadows the names-only module name parent_env with a copy.
    parent_env: dict = _sentinel_first()
    return parent_env


def test_control_a_fixtures_annotated_copy_shadowing_a_names_only_module_name(
    annotated_shadow_env,
):
    assert 1 == 2


method_fixture_env = _sentinel_first()
method_names_only_env = os.environ


class TestFixtureMethods:
    # A method reads the module's names, not these.
    method_fixture_env = os.environ
    method_names_only_env = _sentinel_first()

    @pytest.fixture
    def module_copy(self):
        return method_fixture_env

    @pytest.fixture
    def module_names_only(self):
        return method_names_only_env

    def test_control_a_fixture_method_returning_the_module_copy(self, module_copy):
        assert 1 == 2

    def test_a_fixture_method_returning_a_names_only_module_name(
        self, module_names_only
    ):
        assert 1 == 2


@pytest.fixture
def environ_itself():
    return os.environ


@pytest.fixture
def environ_through_a_local():
    env = os.environ
    return env


def test_a_fixture_returning_os_environ(environ_itself):
    assert 1 == 2


def test_a_fixture_returning_a_local_bound_to_os_environ(environ_through_a_local):
    assert 1 == 2


@pytest.fixture
def child_env():
    return checkout_env(_sentinel_first())


def test_a_fixture_giving_checkout_env(child_env):
    assert 1 == 2


def _copy_of(env):
    return dict(env)


def _copy_through_a_local(env):
    kept = dict(env)
    return kept


def _unpacked_copy_of(env):
    return {{**env}}


def _copy_method_of(env):
    return env.copy()


def _union_of(env):
    return env | {{NAMED: "x"}}


def _copy_in_one_branch(env, fresh):
    return dict(env) if fresh else env


def _same_through_a_local(env):
    kept = env
    return kept


def _wrapped_back(e, n):
    if n == 0:
        return NamesOnlyEnvironment(e)
    return _wrapped_back(dict(os.environ), n - 1)


def test_control_a_copying_pass_through_of_the_environment():
    # What the call hands back is a copy of os.environ, not os.environ.
    copy = _copy_of(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_copying_pass_through_through_a_local():
    copy = _copy_through_a_local(os.environ)
    assert SENTINEL not in set(copy)


def test_control_an_unpacking_pass_through_of_the_environment():
    copy = _unpacked_copy_of(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_copy_method_pass_through_of_the_environment():
    copy = _copy_method_of(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_union_pass_through_of_the_environment():
    copy = _union_of(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_bound_lambda_copying_the_environment():
    clone = lambda env: dict(env)  # noqa: E731
    copy = clone(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_bound_lambda_copying_a_checkout_env_mapping():
    clone = lambda env: dict(env)  # noqa: E731
    copy = clone(checkout_env(_sentinel_first()))
    assert SENTINEL not in set(copy)


def test_control_an_inline_lambda_copying_the_environment():
    copy = (lambda env: dict(env))(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_copying_pass_through_of_a_names_only_environment():
    copy = _copy_of(NamesOnlyEnvironment(_sentinel_first()))
    assert SENTINEL not in set(copy)


def test_control_a_copying_pass_through_of_a_checkout_env_mapping():
    copy = _copy_of(checkout_env(_sentinel_first()))
    assert SENTINEL not in set(copy)


def test_control_a_copying_pass_through_of_the_environment_in_the_assertion():
    assert SENTINEL not in set(_copy_of(os.environ))


def test_control_a_pass_through_copying_in_one_branch():
    copy = _copy_in_one_branch(os.environ, True)
    assert SENTINEL not in set(copy)


def test_a_pass_through_of_the_environment_through_a_local():
    same = _same_through_a_local(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_a_bound_lambda_pass_through_of_the_environment():
    same = lambda env: env  # noqa: E731
    kept = same(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(kept)


def test_a_copy_method_pass_through_of_a_names_only_environment():
    # NamesOnlyEnvironment.copy keeps the type.
    copy = _copy_method_of(NamesOnlyEnvironment(_sentinel_first()))
    assert "ASH_TEST_UNSET_VARIABLE" in set(copy)


def test_a_cycle_handing_back_a_names_only_wrapper_of_a_parameter():
    assert "ASH_TEST_UNSET_VARIABLE" in set(_wrapped_back({{NAMED: "x"}}, 1))


def _pick_a_copy(env, extra=_sentinel_first()):
    return extra


def _pick_the_environment(env, extra=os.environ):
    return extra


def test_control_a_pass_through_returning_a_parameter_whose_default_is_a_copy():
    copy = _pick_a_copy(os.environ)
    assert SENTINEL not in set(copy)


def test_a_pass_through_returning_a_parameter_whose_default_is_the_environment():
    same = _pick_the_environment(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


@pytest.fixture
def copied_through_a_pass_through():
    # A failing test's arguments are cut to about 240 characters each, so the
    # copied mapping is a names-only one with the sentinel first.
    return _copy_of(NamesOnlyEnvironment(_sentinel_first()))


def test_control_a_fixture_returning_a_copying_pass_through(
    copied_through_a_pass_through,
):
    assert 1 == 2


def _copy_by_keywords(env):
    return dict(**env)


def _yield_a_copy_of(env):
    yield dict(env)


def _yield_a_copy():
    yield dict(os.environ)


def test_control_a_copy_of_the_environment_by_keywords():
    copy = dict(**os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_copying_pass_through_by_keywords():
    copy = _copy_by_keywords(os.environ)
    assert SENTINEL not in set(copy)


# A copy reached through a generator, a lambda a dict holds, a container, a
# renamed constructor or another module's wrapper, here and from
# test_control_a_list_of_copies on: each prints the environment's values.
def test_control_a_generator_yielding_a_copy_of_its_parameter():
    copy = next(_yield_a_copy_of(os.environ))
    assert SENTINEL not in set(copy)


def test_control_a_generator_yielding_a_copy():
    copy = next(_yield_a_copy())
    assert SENTINEL not in set(copy)


def test_control_a_lambda_a_dict_holds_copying_its_parameter():
    fs = {{"c": lambda env: dict(env)}}
    copy = fs["c"](os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_lambda_a_dict_holds_returning_a_copy():
    fs = {{"c": lambda: dict(os.environ)}}
    copy = fs["c"]()
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_literal_and_the_environment_by_keywords():
    copy = dict({{}}, **os.environ)
    assert SENTINEL not in set(copy)


# A mapping built from the environment, or from an iterable of its pairs, by a
# comprehension, dict or a collections mapping type.
def test_control_a_dict_comprehension_copy_bound_to_a_name():
    copy = {{k: v for k, v in os.environ.items()}}
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_the_environments_items():
    copy = dict(os.environ.items())
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_list_of_its_items():
    copy = dict(list(os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_tuple_of_its_items():
    copy = dict(tuple(os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_its_sorted_items():
    copy = dict(sorted(os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_set_of_its_items():
    copy = dict(set(os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_frozenset_of_its_items():
    copy = dict(frozenset(os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_an_iterator_over_its_items():
    copy = dict(iter(os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_generator_of_its_pairs():
    copy = dict((k, v) for k, v in os.environ.items())
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_list_comprehension_of_its_pairs():
    copy = dict([(k, v) for k, v in os.environ.items()])
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_set_comprehension_of_its_pairs():
    copy = dict({{(k, v) for k, v in os.environ.items()}})
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_its_names_zipped_with_its_values():
    copy = dict(zip(os.environ, os.environ.values()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_its_items_mapped():
    copy = dict(map(tuple, os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_its_items_filtered():
    copy = dict(filter(lambda item: item[0] != "X", os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_its_names_mapped_to_their_values():
    copy = dict(map(lambda k: (k, os.environ[k]), os.environ))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_a_generator_reading_each_names_value():
    copy = dict((k, os.environ[k]) for k in os.environ)
    assert SENTINEL not in set(copy)


def test_control_an_ordered_dict_of_the_environment():
    copy = collections.OrderedDict(os.environ)
    assert SENTINEL not in set(copy)


def test_control_an_imported_ordered_dict_of_its_items():
    copy = OrderedDict(os.environ.items())
    assert SENTINEL not in set(copy)


def test_control_a_defaultdict_of_the_environment():
    copy = collections.defaultdict(str, os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_counter_of_the_environment():
    copy = collections.Counter(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_counter_of_its_values():
    copy = collections.Counter(os.environ.values())
    assert "ASH_TEST_UNSET_VARIABLE" in set(copy)


def test_control_a_user_dict_of_the_environment():
    copy = collections.UserDict(os.environ)
    assert SENTINEL not in set(copy)


def _ordered_copy_of(env):
    return collections.OrderedDict(env)


def _copy_of_the_items_of(env):
    return dict(env.items())


def test_control_a_pass_through_making_an_ordered_dict():
    copy = _ordered_copy_of(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_pass_through_copying_the_items():
    copy = _copy_of_the_items_of(os.environ)
    assert SENTINEL not in set(copy)


# More copies reached through a container, a renamed constructor or a wrapper.
def test_control_a_list_of_copies():
    envs = [dict(os.environ)]
    assert envs == []


def test_control_an_item_of_an_iterator_over_copies():
    copy = next(iter([dict(os.environ)]))
    assert SENTINEL not in set(copy)


def test_control_an_item_of_a_map_making_copies():
    copy = next(map(dict, [os.environ]))
    assert SENTINEL not in set(copy)


def test_control_a_copy_of_its_items_chained():
    copy = dict(itertools.chain(os.environ.items()))
    assert SENTINEL not in set(copy)


def test_control_a_copy_by_a_renamed_constructor():
    make = dict
    copy = make(os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_chainmap_of_a_copy():
    wrapped = collections.ChainMap(dict(os.environ))
    assert SENTINEL not in set(wrapped)


def test_control_a_mapping_proxy_of_a_copy():
    wrapped = types.MappingProxyType(dict(os.environ))
    assert SENTINEL not in set(wrapped)


def test_control_a_shallow_copy_of_a_copy():
    copied = copy.copy(dict(os.environ))
    assert SENTINEL not in set(copied)


def test_control_a_deep_copy_of_a_copy():
    copied = copy.deepcopy(dict(os.environ))
    assert SENTINEL not in set(copied)


def test_control_a_json_round_trip_of_a_copy():
    copied = json.loads(json.dumps(dict(os.environ)))
    assert SENTINEL not in set(copied)


def test_control_a_copy_of_a_chainmap_of_the_environment():
    # The wrapper of os.environ shows names alone; a plain copy of the
    # wrapper is an ordinary dict that shows values.
    copy = dict(collections.ChainMap(os.environ))
    assert SENTINEL not in set(copy)


# os.environ itself given to the same calls: each result's repr is
# os.environ's, so it prints the names alone.
def test_a_chainmap_of_the_environment():
    wrapped = collections.ChainMap(os.environ)
    assert SENTINEL not in set(wrapped)


def test_a_mapping_proxy_of_the_environment():
    wrapped = types.MappingProxyType(os.environ)
    assert SENTINEL not in set(wrapped)


def test_a_shallow_copy_of_the_environment():
    copied = copy.copy(os.environ)
    assert SENTINEL not in set(copied)


def test_a_deep_copy_of_the_environment():
    copied = copy.deepcopy(os.environ)
    assert SENTINEL not in set(copied)


# A map of a callable that mentions an environment mapping but reads only
# names or the length, and a parameter rebound to itself or updated in place:
# each prints no value.
_pair_names = lambda name: (name, name in os.environ)


def test_a_map_of_a_bound_lambda_reading_only_names():
    pairs = dict(map(_pair_names, os.environ))
    assert SENTINEL not in set(pairs)


def _pair_length(name):
    return (name, len(os.environ))


def test_a_map_of_a_def_reading_only_the_length():
    pairs = dict(map(_pair_length, os.environ))
    assert SENTINEL not in set(pairs)


def _pair_twice(name):
    return (name, os.environ[name])


def _pair_twice(name):
    return (name, "tag")


def test_a_map_of_the_later_of_two_same_named_defs_reading_no_environment():
    pairs = dict(map(_pair_twice, os.environ))
    assert SENTINEL not in set(pairs)


def _another_scope():
    def _pair_alike(name):
        return (name, os.environ[name])

    return _pair_alike


def _pair_alike(name):
    return (name, "tag")


def test_a_map_of_a_helper_another_scope_names_alike():
    pairs = dict(map(_pair_alike, os.environ))
    assert SENTINEL not in set(pairs)


def test_an_inline_lambda_map_reading_only_names():
    pairs = dict(map(lambda name: (name, name in os.environ), os.environ))
    assert SENTINEL not in set(pairs)


def _updated_in_place(base=os.environ):
    base |= {{}}
    return base


def test_a_default_updated_in_place():
    assert SENTINEL not in set(_updated_in_place())


def _rebound_to_itself(base=os.environ):
    base = base
    return base


def test_a_default_rebound_to_itself():
    assert SENTINEL not in set(_rebound_to_itself())


# A lambda's := binding a constant beside its default, or rebinding it to a
# NamesOnlyEnvironment; an iterable of names through a name, in a dict
# comprehension, or handed back by a helper. Each prints no value.
_constant_beside_default = lambda base=os.environ: base if [x := 1] else base


def test_a_lambda_walrus_binding_a_constant_beside_its_default():
    assert SENTINEL not in set(_constant_beside_default())


_names_only_rebinding = lambda base=os.environ: (
    base if [base := NamesOnlyEnvironment(base)] else base
)


def test_a_lambda_default_a_walrus_rebinds_to_a_names_only_environment():
    assert SENTINEL not in set(_names_only_rebinding())


def test_an_iterable_of_names_through_a_name_compared():
    names = sorted(os.environ.keys())
    assert names == []


def test_a_dict_comprehension_of_names_through_a_name():
    names = sorted(os.environ.keys())
    flags = {{k: 1 for k in names}}
    assert SENTINEL not in set(flags)


def _keep_names(names):
    return names


def test_an_argument_holding_an_iterable_of_names():
    assert SENTINEL not in set(_keep_names(sorted(os.environ.keys())))


# Names taken from an environment's items through a name: a list, a set and a
# dict comprehension keeping only the names. Each prints no value.
def test_names_of_items_through_a_name_compared():
    pairs = sorted(os.environ.items())
    names = [k for k, v in pairs]
    assert names == []


def test_a_set_of_names_of_items_through_a_name():
    pairs = sorted(os.environ.items())
    assert {{k for k, _ in pairs}} == set()


def test_a_dict_comprehension_of_names_of_items_through_a_name():
    pairs = sorted(os.environ.items())
    flags = {{k: 1 for k, v in pairs}}
    assert SENTINEL not in set(flags)


# A carrier whose repr formats its fields in a generator or in a list
# comprehension, and a pydantic model, whose repr formats its fields in a
# generator too: each shows pytest's reporting the environment's names only.
class _CarrierJoiningAGenerator:
    def __init__(self, **fields):
        self.fields = fields

    def __repr__(self):
        shown = ", ".join(f"{{name}}={{value!r}}" for name, value in self.fields.items())
        return f"Carrier({{shown}})"


class _CarrierJoiningAList:
    def __init__(self, **fields):
        self.fields = fields

    def __repr__(self):
        shown = ", ".join([f"{{name}}={{value!r}}" for name, value in self.fields.items()])
        return f"Carrier({{shown}})"


class _ModelHoldingTheEnvironment(pydantic.BaseModel):
    env: Any


def test_a_carrier_whose_repr_joins_a_generator():
    assert _CarrierJoiningAGenerator(env=os.environ) is None


def test_a_carrier_whose_repr_joins_a_list():
    assert _CarrierJoiningAList(env=os.environ) is None


def test_a_pydantic_model_holding_the_environment():
    assert _ModelHoldingTheEnvironment(env=os.environ) is None


def test_control_a_carrier_joining_a_generator_over_a_copy():
    assert _CarrierJoiningAGenerator(env=dict(os.environ)) is None


def test_control_a_pydantic_model_holding_a_copy():
    assert _ModelHoldingTheEnvironment(env=dict(os.environ)) is None


# A mapping splat by ** into a pass-through: a new plain dict, or a value.
def _keywords(**kw):
    return kw


def _the_sentinel({SENTINEL}=None, **rest):
    return {SENTINEL}


def _same_beside_flags(env, **flags):
    return env


def test_control_a_keyword_splat_into_a_pass_through():
    copy = _keywords(**os.environ)
    assert SENTINEL not in set(copy)


def test_control_a_keyword_splat_into_a_named_parameter():
    value = _the_sentinel(**os.environ)
    assert value is None


def test_control_a_keyword_splat_into_a_bound_lambda():
    keywords = lambda **kw: kw
    copy = keywords(**os.environ)
    assert SENTINEL not in set(copy)


@pytest.fixture
def keywords_of_the_environment():
    # A failing test's arguments are cut to about 240 characters each, so the
    # splat mapping has the sentinel first.
    return _keywords(**NamesOnlyEnvironment(_sentinel_first()))


def test_control_a_fixture_returning_a_keyword_splat_into_a_pass_through(
    keywords_of_the_environment,
):
    assert 1 == 2


def test_a_pass_through_of_the_environment_beside_a_keyword_splat_of_a_literal():
    same = _same_beside_flags(os.environ, **{{"flag": True}})
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_a_pass_through_of_the_environment_by_keyword_beside_a_constant():
    same = _same_beside_flags(env=os.environ, count=1)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


env_copy = dict(os.environ)
_ENVIRONMENT_ALIAS = os.environ


def _pick_a_module_default(env_copy, extra=env_copy):
    return extra


_pick_a_module_default_by_lambda = lambda env_copy, extra=env_copy: extra
_pick_a_module_default_or_none = lambda env_copy=None, extra=env_copy: extra


def _pick_a_names_only_module_default(env, extra=_ENVIRONMENT_ALIAS):
    return extra


_pick_a_names_only_module_default_by_lambda = (
    lambda env, extra=_ENVIRONMENT_ALIAS: extra
)


def _return_the_imported_environ(_x):
    return imported_environ


_ALIAS_COPY = dict(os.environ)


def _pick_a_default_it_rebinds(env, extra=_ALIAS_COPY):
    _ALIAS_COPY = os.environ
    return extra


_pick_a_shadowed_alias_or_none = (
    lambda _ENVIRONMENT_ALIAS=None, extra=_ENVIRONMENT_ALIAS: extra
)


# A call that gives a parameter no argument returns its default.
def _pick_a_default_copy(env=None, extra=_sentinel_first()):
    return extra


def _pick_the_environment_by_default(extra=os.environ):
    return extra


def _pick_a_names_only_copy_by_default(extra=NamesOnlyEnvironment(os.environ)):
    return extra.copy()


def test_control_a_function_whose_default_is_a_copy_called_with_no_mapping():
    same = _pick_a_default_copy()
    assert SENTINEL not in set(same)


def test_control_a_function_whose_default_is_a_copy_called_with_a_constant():
    same = _pick_a_default_copy(0)
    assert SENTINEL not in set(same)


def _pick_a_rebound_default(extra=_ALIAS_COPY):
    _ALIAS_COPY = os.environ
    return extra


def test_control_a_function_whose_default_names_a_copy_it_rebinds_called_with_no_mapping():
    same = _pick_a_rebound_default()
    assert SENTINEL not in set(same)


@pytest.fixture
def copied_by_default():
    return _pick_a_default_copy()


def test_control_a_fixture_returning_a_function_whose_default_is_a_copy(
    copied_by_default,
):
    assert 1 == 2


def _pick_an_alias_it_rebinds(env, extra=_ENVIRONMENT_ALIAS):
    _ENVIRONMENT_ALIAS = dict(env)
    return extra


def test_a_pass_through_whose_default_names_an_alias_it_rebinds_to_a_copy():
    same = _pick_an_alias_it_rebinds(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_a_function_whose_default_is_the_environment_called_with_no_mapping():
    same = _pick_the_environment_by_default()
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_a_function_whose_default_is_a_names_only_environment_called_with_no_mapping():
    same = _pick_a_names_only_copy_by_default()
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_control_a_pass_through_whose_default_names_a_copy_it_rebinds_in_its_body():
    same = _pick_a_default_it_rebinds(os.environ)
    assert SENTINEL not in set(same)


def test_control_an_inline_lambda_whose_default_is_a_copy_called_with_no_mapping():
    env = dict(os.environ)
    same = (lambda env=None, extra=env: extra)(0)
    assert SENTINEL not in set(same)


def test_a_lambda_whose_default_is_a_module_alias_it_shadows_called_with_no_mapping():
    same = _pick_a_shadowed_alias_or_none(0)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_an_inline_lambda_whose_default_is_an_alias_it_shadows():
    same = (lambda _ENVIRONMENT_ALIAS=None, extra=_ENVIRONMENT_ALIAS: extra)(0)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


# A default is the defining scope's value, whatever a parameter shadows.
def test_control_a_pass_through_whose_default_is_a_module_copy():
    same = _pick_a_module_default(os.environ)
    assert SENTINEL not in set(same)


def test_control_a_lambda_pass_through_whose_default_is_a_module_copy():
    same = _pick_a_module_default_by_lambda(os.environ)
    assert SENTINEL not in set(same)


def test_control_a_lambda_whose_default_is_a_module_copy_called_with_no_mapping():
    same = _pick_a_module_default_or_none(0)
    assert SENTINEL not in set(same)


def test_control_a_nested_pass_through_whose_default_is_an_enclosing_copy():
    env = dict(os.environ)

    def _pick(env, extra=env):
        return extra

    same = _pick(os.environ)
    assert SENTINEL not in set(same)


def _wrapped_argument_or_alias(env):
    return NamesOnlyEnvironment(env) if env else _ENVIRONMENT_ALIAS


def test_a_pass_through_wrapping_its_argument_or_returning_a_module_alias():
    same = _wrapped_argument_or_alias(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_a_pass_through_returning_an_imported_environ():
    same = _return_the_imported_environ(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_a_pass_through_whose_default_is_a_module_alias_of_the_environment():
    same = _pick_a_names_only_module_default(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


def test_a_lambda_pass_through_whose_default_is_a_module_alias_of_the_environment():
    same = _pick_a_names_only_module_default_by_lambda(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(same)


# A mapping type built from the environment's names alone.
def test_a_dict_of_the_environments_names_alone():
    names = dict((k, 1) for k in os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(names)


def test_a_dict_from_the_environments_names():
    names = dict.fromkeys(os.environ)
    assert "ASH_TEST_UNSET_VARIABLE" in set(names)


def test_a_counter_of_the_environments_names():
    names = collections.Counter(os.environ.keys())
    assert "ASH_TEST_UNSET_VARIABLE" in set(names)


def test_a_dict_of_the_environments_names_zipped():
    names = dict(zip(os.environ, os.environ))
    assert "ASH_TEST_UNSET_VARIABLE" in set(names)


def test_a_dict_of_the_environments_names_mapped():
    names = dict(map(lambda k: (k, 1), os.environ))
    assert "ASH_TEST_UNSET_VARIABLE" in set(names)


if os.supports_bytes_environ:

    def test_control_a_copy_of_os_environb():
        # os.environb is os.environ's bytes view: a copy shows its values.
        assert SENTINEL.encode() not in set(dict(os.environb))

    def test_a_set_of_os_environb_inline():
        # An instance of os.environ's type, whose repr is names only.
        assert b"ASH_TEST_UNSET_VARIABLE" in set(os.environb)

    from os import environb as imported_environb

    def test_a_set_of_an_imported_environb():
        assert b"ASH_TEST_UNSET_VARIABLE" in set(imported_environb)

import pytest

# The suite collection hook requires one tier per test (tests/NAMING_CONVENTIONS.md);
# under its own rootdir the child's conftest registers the mark.
pytestmark = pytest.mark.unit
"""

#: The child's first cell, which passes: the ASH the child imported is this
#: checkout's.
IMPORTS_THIS_CHECKOUT = "test_the_ash_imported_is_this_checkout"


def _tests_in(source: str) -> Tuple[str, ...]:
    """The tests the child module *source* runs, by name, in source order:
    its test functions, the test methods of its Test classes, and those an
    ``if os.supports_bytes_environ:`` block defines where that holds, which
    is where the child runs too. Any other module-level condition is refused,
    since which of its tests run cannot be read from here."""
    names: List[str] = []

    def read(body: Sequence[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("test"):
                    names.append(node.name)
            elif isinstance(node, ast.ClassDef):
                if node.name.startswith("Test"):
                    read(node.body)
            elif isinstance(node, ast.If):
                condition = ast.unparse(node.test)
                if condition != "os.supports_bytes_environ":
                    raise ValueError(
                        f"cannot tell which tests run under: if {condition}"
                    )
                read(node.body if os.supports_bytes_environ else node.orelse)

    read(ast.parse(source).body)
    return tuple(names)


#: The child's tests, read from CHILD itself. A control (``test_control_*``)
#: asserts on a plain copy, so its failure prints the sentinel and a value
#: that leaks would be seen; every other test but the first is a shape the
#: tests use, whose failure must print none. CHILD's comments group them.
_CHILD_TESTS = _tests_in(CHILD)
CONTROLS: Tuple[str, ...] = tuple(
    name for name in _CHILD_TESTS if name.startswith("test_control_")
)
SHAPES: Tuple[str, ...] = tuple(
    name
    for name in _CHILD_TESTS
    if not name.startswith("test_control_") and name != IMPORTS_THIS_CHECKOUT
)


@pytest.mark.unit
def test_the_child_tests_are_read_from_its_source() -> None:
    """_tests_in reads a module's tests as pytest collects them: test
    functions and the test methods of Test classes, not helpers or another
    class's methods, and the tests of the ``os.supports_bytes_environ``
    branch that holds here; a condition it cannot evaluate is refused."""
    source = (
        "import os\n"
        "def test_a(): pass\n"
        "def helper(): pass\n"
        "class TestGroup:\n"
        "    def test_b(self): pass\n"
        "    def helper(self): pass\n"
        "class _NotCollected:\n"
        "    def test_c(self): pass\n"
        "if os.supports_bytes_environ:\n"
        "    def test_d(): pass\n"
        "else:\n"
        "    def test_e(): pass\n"
    )
    branch = "test_d" if os.supports_bytes_environ else "test_e"
    assert _tests_in(source) == ("test_a", "test_b", branch)
    with pytest.raises(ValueError, match="cannot tell which tests run"):
        _tests_in("import sys\nif sys.platform == 'x':\n    def test_f(): pass\n")


#: The child's root conftest does what the repository's does: os.environ's repr
#: gives pytest's reporting the names only (test_a_set_of_os_environ_inline
#: relies on it), and a comparison that involves an environment mapping is
#: explained by names (COMPARISONS' shapes rely on it), by the hook function
#: the repository's conftest registers, imported, not a copy of it.
CHILD_CONFTEST = """\
from tests.utils.env_assertions import (
    explain_comparisons_by_names as pytest_assertrepr_compare,
    hide_environ_values,
)

hide_environ_values()


def pytest_configure(config):
    # The child carries the suite's tier marker (tests/NAMING_CONVENTIONS.md); under
    # this rootdir the suite's pytest.ini is not read, so the mark is registered here.
    config.addinivalue_line("markers", "unit: the unit tier, as the suite marks it")
"""


def _run_the_child(
    tmp_path: Path,
    source: str,
    sentinel: str,
    options: Sequence[str] = (),
    extra_environment: Optional[Mapping[str, str]] = None,
    under_the_suites_conftest: bool = False,
    conftest: str = CHILD_CONFTEST,
) -> Tuple[Dict[str, str], List[str], int]:
    """Run *source* as a test module in a child pytest whose environment
    holds *sentinel*, under *conftest* (CHILD_CONFTEST), and give what each
    failure printed (its message and its report) by test name, with the names
    of every test that ran, and the child's exit code. The child's output is
    not given: the controls' failures hold its environment.
    *under_the_suites_conftest* runs it under the repository's own conftest
    instead, report backstop included, from a directory of its own under
    ASH_TEST_TEMP_ROOT."""
    if under_the_suites_conftest:
        ASH_TEST_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
        holder = Path(tempfile.mkdtemp(prefix="shapes-", dir=ASH_TEST_TEMP_ROOT))
        module = holder / "test_zz_shapes_probe.py"
        rootdir = REPOSITORY
        clear_options: Tuple[str, ...] = ("-o", "addopts=")
    else:
        holder = None
        module = tmp_path / "test_shapes.py"
        (tmp_path / "conftest.py").write_text(conftest, encoding="utf-8")
        rootdir = tmp_path
        clear_options = ()
    module.write_text(source, encoding="utf-8")
    report = tmp_path / "report.xml"
    # Only what the child pytest needs, the sentinel and the one named value: so
    # the controls print this mapping, not the environment of the run. Windows
    # needs SYSTEMROOT to start Python; nothing else is taken from this process.
    scratch = {
        name: os.environ[name]
        for name in ("SYSTEMROOT", "COMSPEC", "PATHEXT")
        if name in os.environ
    }
    scratch.update(
        {
            "PATH": str(Path(sys.executable).parent),
            "HOME": str(tmp_path),
            "USERPROFILE": str(tmp_path),
            "TMPDIR": str(tmp_path),
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
            SENTINEL: sentinel,
            NAMED: "actual",
            # No __pycache__ beside the module, so its holder empties.
            "PYTHONDONTWRITEBYTECODE": "1",
            **(extra_environment or {}),
        }
    )
    # The child imports ASH from this checkout: it runs without -I, which would
    # ignore PYTHONPATH, and checkout_env puts the checkout first on it. Its first
    # cell checks that.
    env = checkout_env(scratch)
    try:
        run = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "-n",
                "0",
                *clear_options,
                *options,
                f"--rootdir={rootdir}",
                f"--basetemp={tmp_path / 'child'}",
                f"--junitxml={report}",
                str(module),
            ],
            cwd=REPOSITORY,
            env=env,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
    finally:
        if holder is not None:
            module.unlink()
            holder.rmdir()
    failures = {}
    ran = []
    for case in ET.parse(report).getroot().iter("testcase"):
        ran.append(case.get("name"))
        failure = case.find("failure")
        if failure is not None:
            failures[case.get("name")] = failure.get("message", "") + (
                failure.text or ""
            )
    return failures, ran, run.returncode


@pytest.mark.integration
def test_a_failing_environment_assertion_prints_no_other_value(tmp_path):
    sentinel = "sentinel-" + secrets.token_hex(16)
    # The most verbose: no explanation is cut short.
    failures, ran, returncode = _run_the_child(
        tmp_path, CHILD, sentinel, options=("-vv",)
    )
    # The child's ASH is this checkout's, and every shape and every control ran
    # and failed.
    assert IMPORTS_THIS_CHECKOUT in ran, f"the child exited {returncode}"
    failed = sorted(failures)
    assert failed == sorted(CONTROLS + SHAPES), f"the child exited {returncode}"
    # The controls print the mapping, so a value that leaks is seen.
    blind = [name for name in CONTROLS if sentinel not in failures[name]]
    assert blind == [], "a control did not print the sentinel, so this check is blind"
    # No shape the tests use prints it.
    leaked = [name for name in SHAPES if sentinel in failures[name]]
    assert leaked == [], "these failures printed a value the assertion is not about"


@pytest.mark.integration
def test_under_the_suites_conftest_no_failure_prints_the_value(
    tmp_path: Path,
) -> None:
    """The same child run under the repository's own conftest, whose report
    backstop redacts each environment value of MIN_REDACTED_LENGTH characters
    or more: no failure prints the sentinel, the controls' included, each of
    which shows the marker where its value was. So every shape a control
    measures to print is caught, whether or not the static check
    (test_no_assertion_names_an_environment_mapping.py) still refuses it."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    failures, ran, returncode = _run_the_child(
        tmp_path, CHILD, sentinel, options=("-vv",), under_the_suites_conftest=True
    )
    assert IMPORTS_THIS_CHECKOUT in ran, f"the child exited {returncode}"
    assert sorted(failures) == sorted(CONTROLS + SHAPES), (
        f"the child exited {returncode}"
    )
    printed = [name for name, text in failures.items() if sentinel in text]
    assert printed == [], "these failures printed the value under the backstop"
    unmarked = [name for name in CONTROLS if "<value>" not in failures[name]]
    assert unmarked == [], "these controls show no marker, so the run may be blind"


@pytest.mark.unit
def test_the_child_carries_its_tier_and_its_conftest_registers_the_mark():
    """The child runs both ways: under the suite's conftest, whose collection hook
    refuses a test with no tier marker, and under its own rootdir, where the suite's
    pytest.ini is not read. So it carries the marker and CHILD_CONFTEST registers it,
    and no warning filter hides an unknown mark."""
    assert "pytestmark = pytest.mark.unit" in CHILD
    assert "catch_warnings" not in CHILD and "simplefilter" not in CHILD
    assert 'config.addinivalue_line("markers", "unit:' in CHILD_CONFTEST


COMPARISONS_CHILD = f"""\
import dataclasses
import os
from pathlib import Path

import pytest

from tests.utils import env_assertions
from tests.utils.env_assertions import NamesOnlyEnvironment
from tests.utils.helpers import checkout_env

SENTINEL = {SENTINEL!r}
NAMED = {NAMED!r}
CHECKOUT = Path({str(REPOSITORY)!r})


@dataclasses.dataclass
class Run:
    env: object


def test_the_helpers_imported_are_this_checkouts():
    imported = Path(env_assertions.__file__).resolve()
    assert imported.is_relative_to(CHECKOUT.resolve()), imported


@pytest.fixture
def given():
    return os.environ


@pytest.fixture
def child_env():
    return checkout_env({{SENTINEL: os.environ[SENTINEL], NAMED: os.environ[NAMED]}})


@pytest.fixture
def names_only_env():
    return NamesOnlyEnvironment(os.environ)


@pytest.fixture
def wide_env():
    # Enough names that pytest's default cut (8 lines or 640 characters)
    # shortens the explanation.
    padding = {{f"ASH_TEST_PADDING_VARIABLE_{{index:02d}}": "v" for index in range(40)}}
    return NamesOnlyEnvironment({{**padding, **os.environ}})


def test_a_wide_names_only_environment_compared_with_a_dict(wide_env):
    assert wide_env == {{NAMED: "x"}}


def test_os_environ_compared_with_a_dict(given):
    assert given == {{NAMED: "x"}}


def test_os_environ_compared_on_the_sentinel(given):
    assert given == {{SENTINEL: "x"}}


def test_a_dict_compared_with_os_environ(given):
    assert {{NAMED: "x"}} == given


def test_checkout_env_compared_with_a_dict(child_env):
    assert child_env == {{NAMED: "x"}}


def test_a_names_only_environment_compared_with_a_dict(names_only_env):
    assert names_only_env == {{NAMED: "x"}}


def test_a_dataclass_holding_os_environ(given):
    assert Run(given) == Run({{NAMED: "x"}})


def test_os_environ_compared_with_a_snapshot(given, snapshot):
    assert given == snapshot


def test_control_a_copy_compared_with_a_dict():
    assert dict(os.environ) == {{NAMED: "x"}}


def test_control_a_dataclass_holding_a_copy():
    # The sentinel first, where an explanation cut short still shows it.
    assert Run({{SENTINEL: os.environ[SENTINEL], **os.environ}}) == Run({{NAMED: "x"}})
"""

#: The comparisons' child's first cell, which passes: the helpers it imports,
#: the comparison hook's among them, are this checkout's.
IMPORTS_THIS_CHECKOUTS_HELPERS = "test_the_helpers_imported_are_this_checkouts"
#: Each shape, with a line its failure must show: a label and a name the line
#: holds. A frame's argument shows the names as well (``given =
#: environ(names=[...])``), so the label is what tells the explanation's line.
COMPARISONS = {
    "test_os_environ_compared_with_a_dict": ("Names whose values differ", NAMED),
    "test_os_environ_compared_on_the_sentinel": ("Names whose values differ", SENTINEL),
    "test_a_dict_compared_with_os_environ": ("Names only on the right", SENTINEL),
    "test_checkout_env_compared_with_a_dict": ("Names only on the left", SENTINEL),
    "test_a_names_only_environment_compared_with_a_dict": (
        "Names whose values differ",
        NAMED,
    ),
    "test_a_dataclass_holding_os_environ": ("Names whose values differ", NAMED),
    "test_os_environ_compared_with_a_snapshot": ("Names on the left", SENTINEL),
    "test_a_wide_names_only_environment_compared_with_a_dict": (
        "Names whose values differ",
        NAMED,
    ),
}
#: The notice each explanation carries, whole, however pytest cuts it short.
VALUES_NOT_SHOWN = (
    "Values are not shown: a comparison that involves an environment mapping"
    " is explained by its names."
)
#: Plain copies, which pytest explains as it always does: by the items, values
#: included. The first must show pytest's own label for them.
COMPARISON_CONTROLS = (
    "test_control_a_copy_compared_with_a_dict",
    "test_control_a_dataclass_holding_a_copy",
)
PYTESTS_OWN_DIFF = ("test_control_a_copy_compared_with_a_dict", "Differing items:")


@pytest.mark.integration
@pytest.mark.parametrize(
    ("options", "extra_environment"),
    [
        pytest.param(("-vv",), {}, id="most-verbose"),
        pytest.param((), {}, id="default"),
        pytest.param(("--showlocals",), {}, id="showlocals"),
        pytest.param(("--tb=long",), {}, id="tb-long"),
        # On CI pytest neither cuts an explanation short nor asks for -v.
        pytest.param((), {"CI": "true"}, id="ci"),
    ],
)
def test_a_comparison_with_an_environment_mapping_prints_its_names(
    tmp_path: Path, options: Tuple[str, ...], extra_environment: Dict[str, str]
) -> None:
    """pytest explains ``mapping == mapping`` by printing plain dicts of the
    items, never the mapping's repr, and so does a snapshot's diff: each shape
    compares an environment mapping, a fixture's value among them, and must
    show the names it is about and none of the values, however the run is
    configured. The controls compare a plain copy, which pytest explains as
    usual, values included."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    failures, ran, returncode = _run_the_child(
        tmp_path, COMPARISONS_CHILD, sentinel, options, extra_environment
    )
    assert IMPORTS_THIS_CHECKOUTS_HELPERS in ran, f"the child exited {returncode}"
    failed = sorted(failures)
    expected = sorted([*COMPARISONS, *COMPARISON_CONTROLS])
    assert failed == expected, f"the child exited {returncode}"
    blind = [name for name in COMPARISON_CONTROLS if sentinel not in failures[name]]
    assert blind == [], "a control did not print the sentinel, so this check is blind"
    control, label = PYTESTS_OWN_DIFF
    assert label in failures[control], "pytest's own diff of a plain copy is gone"
    leaked = [name for name in COMPARISONS if sentinel in failures[name]]
    assert leaked == [], "these failures printed a value the comparison is not about"
    unnamed = [
        name
        for name, (label, variable) in COMPARISONS.items()
        if not any(
            label in line and repr(variable) in line
            for line in failures[name].splitlines()
        )
    ]
    assert unnamed == [], "these failures do not name the names they are about"
    unnoticed = [name for name in COMPARISONS if VALUES_NOT_SHOWN not in failures[name]]
    assert unnoticed == [], "these failures do not say the values are not shown"


@dataclasses.dataclass
class _Run:
    env: object


class _Carried(NamedTuple):
    env: object


class _UnreadableEnvironment(NamesOnlyEnvironment):
    def __iter__(self) -> Iterator[str]:
        raise RuntimeError("names cannot be read")


def _holds(lines: Optional[Sequence[str]], text: str) -> bool:
    """Whether the explanation *lines* hold *text*. The cells that check an
    explanation assert on this, never on the explanation: pytest prints an
    assertion's operands and, under ``-l``, a failing test's locals, and an
    explanation holds the run's values exactly when such a check fails."""
    return text in "\n".join(lines or ())


def _holds_line(lines: Optional[Sequence[str]], line: str) -> bool:
    """Whether one of the explanation *lines*' lines is *line*, as _holds."""
    return line in "\n".join(lines or ()).splitlines()


@pytest.mark.unit
def test_a_comparison_with_an_environment_mapping_is_explained_by_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """explain_environment_comparison names the names a comparison with an
    environment mapping is about, at the top or inside attributes pytest
    compares one by one, and shows none of its values; one whose names cannot
    be read is still not left to pytest's diff."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)
    monkeypatch.setenv(NAMED, "actual")
    expected = {NAMED: "x"}
    differ = f"Names whose values differ: [{NAMED!r}]"

    def facts(left: object, right: object, *texts: str) -> Tuple[bool, ...]:
        lines = explain_environment_comparison("==", left, right)
        return tuple(_holds(lines, text) for text in texts)

    shown = {
        "os.environ": facts(os.environ, expected, sentinel, differ),
        "a names-only environment": facts(
            NamesOnlyEnvironment(os.environ), expected, sentinel, differ
        ),
        "a dataclass": facts(_Run(os.environ), _Run(expected), sentinel, differ),
        "a namedtuple": facts(
            _Carried(os.environ), _Carried(expected), sentinel, differ
        ),
    }
    leaked = [kind for kind, (value, _) in shown.items() if value]
    assert leaked == [], "these explanations show a value"
    unnamed = [kind for kind, (_, named) in shown.items() if not named]
    assert unnamed == [], "these explanations do not name the differing name"
    says_unread, unreadable_leaks, gives_notice = facts(
        _UnreadableEnvironment(os.environ),
        expected,
        "The names could not be read.",
        sentinel,
        VALUES_NOT_SHOWN,
    )
    assert says_unread, "the fallback explanation does not say the names are unread"
    assert not unreadable_leaks, "the fallback explanation shows a value"
    assert gives_notice, "the fallback explanation does not say values are not shown"


@dataclasses.dataclass
class _Result:
    env: object
    returncode: int
    stdout: str
    extra: object


@dataclasses.dataclass
class _ResultEnvironmentLast:
    returncode: int
    env: object


@pytest.mark.unit
def test_a_differing_attribute_beside_an_environment_is_shown_as_the_summary_shows_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Beside an attribute that holds an environment mapping, a differing one
    that holds none is drilled into as pytest would, each side shown as the
    explanation's first line shows a value: a short number by its repr, a
    mapping by how many names it holds, and anything else, text included, by
    its type (the next cell measures which numbers are short). At this level
    the environment's drill-down comes first, whether the environment is
    declared before the other attributes or after them, so a cut from the end
    keeps it (a later cell measures nested values). No value of a mapping or
    of text is shown."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)
    monkeypatch.setenv(NAMED, "actual")
    expected = _Result({NAMED: "x"}, 1, "other", {})

    def environment_first(lines: Optional[Sequence[str]]) -> bool:
        text = "\n".join(lines or ())
        env_at = text.find("Drill down into differing attribute env:")
        returncode_at = text.find("Drill down into differing attribute returncode:")
        return 0 <= env_at < returncode_at

    def facts() -> Tuple[bool, bool, bool, bool, bool, bool]:
        lines = explain_environment_comparison(
            "==",
            _Result(os.environ, 0, f"out {sentinel}", {SENTINEL: sentinel}),
            expected,
        )
        declared_last = explain_environment_comparison(
            "==",
            _ResultEnvironmentLast(0, os.environ),
            _ResultEnvironmentLast(1, {NAMED: "x"}),
        )
        return (
            _holds_line(lines, "  returncode: 0 != 1"),
            _holds_line(lines, "  stdout: <str> != <str>"),
            _holds_line(lines, "  extra: dict(1 name) != dict(0 names)"),
            sentinel in "\n".join(lines or ()),
            environment_first(lines),
            environment_first(declared_last),
        )

    returncode, stdout, extra, leaked, env_first, env_last_first = facts()
    assert returncode, "a differing number is not shown by its repr"
    assert stdout, "differing text is not shown by its type"
    assert extra, "a differing mapping is not shown by how many names it holds"
    assert not leaked, "the explanation shows a value"
    assert env_first, "the environment's drill-down does not come first"
    assert env_last_first, (
        "an environment declared after the other attributes is not drilled into first"
    )


#: Variables the cells below read numbers from, as a test reads a port or a
#: count: one of six digits, a decimal, and one of one digit.
NUMBER = "ASH_TEST_NUMBER"
DECIMAL = "ASH_TEST_DECIMAL"
DIGIT = "ASH_TEST_DIGIT"


@dataclasses.dataclass
class _Read:
    env: object
    other: object


@dataclasses.dataclass
class _ReadEnvironmentLast:
    other: object
    env: object


class _ReadCarried(NamedTuple):
    env: object
    other: object


class _Port(int):
    """An int whose repr is its own code, as a subclass's may be: here it
    reads the sentinel's value."""

    def __repr__(self) -> str:
        return f"_Port({os.environ[SENTINEL]})"


class _ShortInt(int):
    """An int subclass whose repr is short text its own code reads."""

    def __repr__(self) -> str:
        return os.environ[DIGIT]


class _ShortFloat(float):
    """A float subclass whose repr is short text its own code reads."""

    def __repr__(self) -> str:
        return os.environ[DIGIT]


class _Level(enum.IntEnum):
    LOW = 1


@pytest.mark.unit
def test_a_number_beside_an_environment_is_shown_by_its_repr_only_when_short(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Beside an attribute that holds an environment mapping, a differing
    pair whose reprs hold a compared value, or that the content rule (the
    cell above) does not reach, falls back to each side on its own: None, a
    bool, or an int or float of exactly that type whose repr is shorter than
    ``MIN_REDACTED_LENGTH`` by that repr, and anything else by its type -- in
    a dataclass, in one that declares the environment last, and in a
    namedtuple. A number read from the environment is shown when it is that
    short, which is what the rule lets through, and hides its pair when it is
    longer, as is an int subclass, whose repr runs its own code, an IntEnum,
    and an int too long to print."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    number = str(100000 + secrets.randbelow(900000))
    decimal = f"{number}.25"
    monkeypatch.setenv(SENTINEL, sentinel)
    monkeypatch.setenv(NAMED, "actual")
    monkeypatch.setenv(NUMBER, number)
    monkeypatch.setenv(DECIMAL, decimal)
    monkeypatch.setenv(DIGIT, "7")
    expected = {NAMED: "x"}

    def read() -> int:
        return int(os.environ[NUMBER])

    shapes = {
        "a long int": (_Read(os.environ, read()), _Read(expected, 1), "<int> != 1"),
        "a long float": (
            _Read(os.environ, float(os.environ[DECIMAL])),
            _Read(expected, 1.5),
            "<float> != 1.5",
        ),
        "None against a long int": (
            _Read(os.environ, None),
            _Read(expected, read()),
            "None != <int>",
        ),
        "a namedtuple's long int": (
            _ReadCarried(os.environ, read()),
            _ReadCarried(expected, 1),
            "<int> != 1",
        ),
        "a long int declared before the environment": (
            _ReadEnvironmentLast(read(), os.environ),
            _ReadEnvironmentLast(1, expected),
            "<int> != 1",
        ),
        "an int subclass": (
            _Read(os.environ, _Port(5)),
            _Read(expected, 6),
            "<_Port> != 6",
        ),
        "an int subclass with a short repr": (
            _Read(os.environ, _ShortInt(5)),
            _Read(expected, 6),
            "<_ShortInt> != 6",
        ),
        "a float subclass with a short repr": (
            _Read(os.environ, _ShortFloat(5)),
            _Read(expected, 6),
            "<_ShortFloat> != 6",
        ),
        "an IntEnum": (
            _Read(os.environ, _Level.LOW),
            _Read(expected, 6),
            "<_Level> != 6",
        ),
        "an int too long to print": (
            _Read(os.environ, 10**5000),
            _Read(expected, 1),
            "<int> != 1",
        ),
        "a one-digit int read from the environment": (
            _Read(os.environ, int(os.environ[DIGIT])),
            _Read(expected, 1),
            "7 != 1",
        ),
        "a bool": (_Read(os.environ, True), _Read(expected, False), "True != False"),
        "a short int beside a hidden one": (
            _Read(os.environ, 999),
            _Read(expected, read()),
            "999 != <int>",
        ),
        "clean negative ints": (
            _Read(os.environ, -12),
            _Read(expected, -123),
            "-12 != -123",
        ),
        "a short float": (
            _Read(os.environ, 1.5),
            _Read(expected, 12.5),
            "1.5 != <float>",
        ),
    }

    def shown(left: object, right: object, line: str) -> Tuple[bool, bool]:
        lines = explain_environment_comparison("==", left, right)
        text = "\n".join(lines or ())
        leaked = any(value in text for value in (number, decimal, sentinel))
        return _holds_line(lines, f"  other: {line}"), leaked

    facts = {shape: shown(*arguments) for shape, arguments in shapes.items()}
    not_as_the_rule_says = [shape for shape, (held, _) in facts.items() if not held]
    assert not_as_the_rule_says == [], "these attributes are not shown as the rule says"
    leaked = [shape for shape, (_, leaked) in facts.items() if leaked]
    assert leaked == [], "these explanations show a value read from the environment"


def _free_of_environment_values(make: Callable[[], str]) -> str:
    """A value from *make* that no environment value of MIN_REDACTED_LENGTH
    characters or more appears in, the no-secrecy words aside, so a cell
    about what is shown does not turn on what this host's environment
    happens to hold."""
    for _ in range(32):
        candidate = make()
        folded = candidate.casefold()
        if not any(
            value.casefold() in folded
            for value in os.environ.values()
            if len(value) >= env_assertions.MIN_REDACTED_LENGTH
            and value.casefold() not in env_assertions._NO_SECRECY
        ):
            return candidate
    raise RuntimeError("no candidate was free of the environment's values")


@pytest.mark.unit
def test_text_and_numbers_beside_an_environment_are_shown_when_they_hold_no_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Beside an attribute that holds an environment mapping, a differing
    attribute of exactly str or int is shown by its bounded repr when neither
    side's repr holds a value of MIN_REDACTED_LENGTH characters or more that
    the compared mappings or the environment hold; when one side's repr holds
    one, both sides are shown by their types. The fixed words of the
    no-secrecy list hide nothing. A value derived from an environment value
    (``int(number) + 1``) is shown by design: it is not the environment's
    value, and the report backstop (redact_environment_values) is the second
    layer over what an explanation lets through."""
    sentinel = "sentinel-" + secrets.token_hex(16)

    # The derived values (clean_int + 7, int(number) + 1) are shown by
    # design, so each pair is drawn free TOGETHER: a host value such as a
    # port inside a derived number would otherwise hide the pair and turn
    # this cell red with nothing wrong.
    def _a_number_and_its_successor() -> str:
        drawn = 100000 + secrets.randbelow(900000)
        return f"{drawn} {drawn + 1}"

    def _an_int_and_its_offset() -> str:
        drawn = secrets.randbelow(10**7)
        return f"{drawn} {drawn + 7}"

    number = _free_of_environment_values(_a_number_and_its_successor).split()[0]
    monkeypatch.setenv(SENTINEL, sentinel)
    monkeypatch.setenv(NUMBER, number)
    monkeypatch.setenv("ASH_TEST_NO_SECRECY_WORD", "true")
    expected = {NAMED: "x"}
    clean_left = _free_of_environment_values(lambda: "left-" + secrets.token_hex(6))
    clean_right = _free_of_environment_values(lambda: "right-" + secrets.token_hex(6))
    clean_int = int(_free_of_environment_values(_an_int_and_its_offset).split()[0])
    word_left = _free_of_environment_values(lambda: "true-" + secrets.token_hex(6))
    word_right = _free_of_environment_values(lambda: "slow-" + secrets.token_hex(6))
    held = "held-" + secrets.token_hex(8)
    holder = NamesOnlyEnvironment({"K": held})
    quoted = _free_of_environment_values(lambda: "pa'ss-" + secrets.token_hex(8))
    monkeypatch.setenv("ASH_TEST_QUOTED_VALUE", quoted)
    spaced = _free_of_environment_values(lambda: "spaced-" + secrets.token_hex(6))
    monkeypatch.setenv("ASH_TEST_SPACED_VALUE", f"  {spaced}  ")
    digits = _free_of_environment_values(
        lambda: str(100000 + secrets.randbelow(900000))
    )
    monkeypatch.setenv("ASH_TEST_SPACED_NUMBER", f" {digits} ")
    monkeypatch.setenv("ASH_TEST_SIGNED_NUMBER", f"+{digits}")
    monkeypatch.setenv("ASH_TEST_ZERO_LED_NUMBER", f"0{digits}")
    long_value = _free_of_environment_values(lambda: "pfx-" + secrets.token_hex(16))
    monkeypatch.setenv("ASH_TEST_LONG_VALUE", long_value)

    shapes = {
        "clean text": (
            _Read(os.environ, clean_left),
            _Read(expected, clean_right),
            f"{clean_left!r} != {clean_right!r}",
        ),
        "clean long ints": (
            _Read(os.environ, clean_int),
            _Read(expected, clean_int + 7),
            f"{clean_int} != {clean_int + 7}",
        ),
        "text that is an environment value": (
            _Read(os.environ, sentinel),
            _Read(expected, sentinel + "-else"),
            "<str> != <str>",
        ),
        "a clean side beside a holding side": (
            _Read(os.environ, sentinel),
            _Read(expected, clean_right),
            "<str> != <str>",
        ),
        "text holding a compared mapping's value": (
            _Read(holder, "carried " + held),
            _Read(expected, clean_right),
            "<str> != <str>",
        ),
        "a number derived from an environment value": (
            _Read(os.environ, int(number) + 1),
            _Read(expected, 1),
            f"{int(number) + 1} != 1",
        ),
        "a no-secrecy word in the text": (
            _Read(os.environ, word_left),
            _Read(expected, word_right),
            f"{word_left!r} != {word_right!r}",
        ),
        # A repr escapes a quote inside text that also holds the other kind.
        # Two layers hide it: the product's quote-escaped printed forms, and
        # the display's raw-text check; this shape passes with either, and
        # the raw-text layer is pinned alone by its own cell below.
        "a value whose repr escapes its quote": (
            _Read(os.environ, 'say "hi" ' + quoted),
            _Read(expected, clean_right),
            "<str> != <str>",
        ),
        # The five derived shapes below are SHOWN by design: each prints
        # text the environment does not hold, derived from a value it does.
        # They are pinned so a change to that rule has to move these lines
        # and _shown_pair's docstring together.
        "the strip of a padded value, by design": (
            _Read(os.environ, os.environ["ASH_TEST_SPACED_VALUE"].strip()),
            _Read(expected, clean_right),
            f"{spaced!r} != {clean_right!r}",
        ),
        "the int of a padded numeric value, by design": (
            _Read(os.environ, int(os.environ["ASH_TEST_SPACED_NUMBER"])),
            _Read(expected, 1),
            f"{int(digits)} != 1",
        ),
        "the int of a plus-signed numeric value, by design": (
            _Read(os.environ, int(os.environ["ASH_TEST_SIGNED_NUMBER"])),
            _Read(expected, 1),
            f"{int(digits)} != 1",
        ),
        "the int of a zero-led numeric value, by design": (
            _Read(os.environ, int(os.environ["ASH_TEST_ZERO_LED_NUMBER"])),
            _Read(expected, 1),
            f"{int(digits)} != 1",
        ),
        "a long prefix of a longer value, by design": (
            _Read(os.environ, long_value[:20]),
            _Read(expected, clean_right),
            f"{long_value[:20]!r} != {clean_right!r}",
        ),
    }

    def shown(left: object, right: object, line: str) -> Tuple[bool, bool]:
        lines = explain_environment_comparison("==", left, right)
        text = "\n".join(lines or ())
        leaked = sentinel in text or held in text or quoted in text
        return _holds_line(lines, f"  other: {line}"), leaked

    facts = {shape: shown(*arguments) for shape, arguments in shapes.items()}
    not_as_the_rule_says = [shape for shape, (held_, _) in facts.items() if not held_]
    assert not_as_the_rule_says == [], "these attributes are not shown as the rule says"
    leaked = [shape for shape, (_, leaked_) in facts.items() if leaked_]
    assert leaked == [], "these explanations show a value"


@pytest.mark.unit
def test_the_raw_text_check_hides_a_quoting_value_on_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two layers hide a value whose quote a repr escapes: the product's
    quote-escaped printed forms, and the display's raw-text check beside the
    reprs. With the escaped forms filtered out of the product's matching,
    the raw-text check must hide the pair alone -- otherwise dropping that
    line would pass every cell while halving the defense."""
    from automated_security_helper.config import config_validator

    quoted = _free_of_environment_values(lambda: "pa'ss-" + secrets.token_hex(8))
    clean = _free_of_environment_values(lambda: "right-" + secrets.token_hex(6))
    monkeypatch.setenv("ASH_TEST_QUOTED_VALUE", quoted)
    real_forms = config_validator._printed_forms

    def unescaped_forms(value):
        return [
            form
            for form in real_forms(value)
            if "\\'" not in form and '\\"' not in form
        ]

    monkeypatch.setattr(config_validator, "_printed_forms", unescaped_forms)
    env_assertions._folded_printed_forms.cache_clear()
    try:
        lines = explain_environment_comparison(
            "==",
            _Read(os.environ, 'say "hi" ' + quoted),
            _Read({NAMED: "x"}, clean),
        )
    finally:
        env_assertions._folded_printed_forms.cache_clear()
    assert _holds_line(lines, "  other: <str> != <str>")
    assert quoted not in "\n".join(lines or ())


@pytest.mark.unit
def test_attributes_are_hidden_when_the_products_matching_cannot_be_imported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without the product's ``_printed_forms``, whether a repr holds a value
    cannot be told in the forms the product matches, so a str or int
    attribute pair falls back to the types: not knowing hides."""
    from automated_security_helper.config import config_validator

    clean = _free_of_environment_values(lambda: "plain-" + secrets.token_hex(6))
    # The assert runs after the undo: while _printed_forms is deleted, the
    # report backstop cannot redact this cell's own failure either, so a red
    # read "this report could not be redacted" instead of saying why.
    with monkeypatch.context() as patched:
        patched.delattr(config_validator, "_printed_forms")
        env_assertions._folded_printed_forms.cache_clear()
        try:
            lines = explain_environment_comparison(
                "==", _Read(os.environ, clean), _Read({NAMED: "x"}, clean + "-b")
            )
        finally:
            env_assertions._folded_printed_forms.cache_clear()
    assert _holds_line(lines, "  other: <str> != <str>")


@dataclasses.dataclass
class _Pair:
    first: object
    second: object


@pytest.mark.unit
def test_an_environment_is_drilled_into_first_at_each_level() -> None:
    """Of two values each holding an environment beside a number, nested in
    one pair, each is drilled into in field order, and inside each the
    environment's names come before the number. So the first value's number
    comes before the second value's environment: the order holds at each
    level, not across levels."""
    left = _Pair(_Read(os.environ, 0), _Read(os.environ, 0))
    right = _Pair(_Read({NAMED: "x"}, 1), _Read({NAMED: "x"}, 1))
    text = "\n".join(explain_environment_comparison("==", left, right) or ())
    first_at = text.find("Drill down into differing attribute first:")
    second_at = text.find("Drill down into differing attribute second:")
    first_block, second_block = text[first_at:second_at], text[second_at:]

    def environment_before_number(block: str) -> bool:
        env_at = block.find("Drill down into differing attribute env:")
        other_at = block.find("Drill down into differing attribute other:")
        return 0 <= env_at < other_at

    in_each = (
        environment_before_number(first_block),
        environment_before_number(second_block),
    )
    first_number_before_second_environment = 0 <= first_at < second_at and (
        "  other: 0 != 1" in first_block
    )
    assert in_each == (True, True), "an environment is not first at its level"
    assert first_number_before_second_environment, (
        "a nested number is not shown inside its own drill-down"
    )


@pytest.mark.unit
def test_a_number_is_shown_below_the_length_the_product_redacts_from() -> None:
    """explain_environment_comparison shows a number by its repr only below
    env_assertions' ``MIN_REDACTED_LENGTH``, which is config_validator's: the
    length from which ASH hides a value read from the environment in what it
    prints. env_assertions does not import it, since the root conftest loads
    that module before any of ASH, so this keeps the two equal."""
    from automated_security_helper.config.config_validator import (
        MIN_REDACTED_LENGTH,
    )

    assert env_assertions.MIN_REDACTED_LENGTH == MIN_REDACTED_LENGTH


#: A value holding an environment mapping, compared beside a number read from
#: the environment, in a child pytest, whose junit report holds the lines the
#: run prints for each failure. The control compares the number on its own,
#: which pytest prints.
NUMBERS_CHILD = f"""\
import dataclasses
import os

NUMBER = {NUMBER!r}


@dataclasses.dataclass
class _Read:
    env: object
    other: object


def test_a_number_read_from_the_environment_beside_it():
    assert _Read(os.environ, int(os.environ[NUMBER])) == _Read(os.environ, 1)


def test_a_one_digit_number_beside_it():
    assert _Read(os.environ, 0) == _Read(os.environ, 1)


def test_a_number_not_the_environments_beside_it():
    assert _Read(os.environ, 7654321) == _Read(os.environ, 7654329)


def test_control_the_number_compared_on_its_own():
    assert int(os.environ[NUMBER]) == 1
"""


@pytest.mark.integration
@pytest.mark.parametrize(
    "options",
    [
        pytest.param((), id="default"),
        pytest.param(("-vv",), id="most-verbose"),
        pytest.param(("-l", "-vv"), id="locals-shown"),
    ],
)
def test_a_number_read_from_the_environment_beside_one_is_not_reported(
    tmp_path: Path, options: Tuple[str, ...]
) -> None:
    """What a failure's explanation reaches: the failure pytest prints, and
    the junit report, which holds the same lines and is what this reads. A
    number of ``MIN_REDACTED_LENGTH`` characters or more read from the
    environment, beside an environment mapping, is in neither, while a
    one-digit number beside one is shown by its repr. The control prints the
    number, so this is not blind."""
    number = str(100000 + secrets.randbelow(900000))
    failures, ran, returncode = _run_the_child(
        tmp_path,
        NUMBERS_CHILD,
        "sentinel-" + secrets.token_hex(16),
        options=options,
        extra_environment={NUMBER: number},
    )
    shape = "test_a_number_read_from_the_environment_beside_it"
    short = "test_a_one_digit_number_beside_it"
    clean = "test_a_number_not_the_environments_beside_it"
    control = "test_control_the_number_compared_on_its_own"
    assert sorted(failures) == sorted([shape, short, clean, control]), (
        f"the child exited {returncode}; ran {sorted(ran)}"
    )
    blind = number not in failures[control]
    assert not blind, "the control did not print the number, so this check is blind"
    reported = number in failures[shape]
    assert not reported, "the number read from the environment is in the report"
    short_shown = "  other: 0 != 1" in failures[short]
    assert short_shown, "a one-digit number beside an environment is not shown"
    clean_shown = "  other: 7654321 != 7654329" in failures[clean]
    assert clean_shown, "a number the environment does not hold is not shown"


@pytest.mark.unit
def test_a_comparison_without_an_environment_mapping_is_left_to_pytest() -> None:
    """Two plain mappings, two dataclasses holding plain mappings, and a
    membership test get pytest's own explanation, which explains them better
    and shows no environment's values."""
    left_to_pytest = [
        explain_environment_comparison("==", {"A": "1"}, {"A": "2"}),
        explain_environment_comparison("==", _Run({"A": "1"}), _Run({"A": "2"})),
        explain_environment_comparison("not in", "A", os.environ),
    ]
    assert left_to_pytest == [None, None, None]


@pytest.mark.unit
def test_this_runs_comparisons_with_an_environment_mapping_are_explained_by_names(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> None:
    """pytest asks every ``pytest_assertrepr_compare`` that applies to a test
    for an explanation and shows the first one given. For this test, in this
    run, with every plugin installed, that is the root conftest's, called
    before pytest's own and syrupy's: a comparison with ``os.environ`` is
    explained by names, while one with a plain dict of the same names still
    gets pytest's diff, values included. That dict is built here from the
    sentinel, not copied from the environment, so no explanation is given the
    run's own values."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)
    monkeypatch.setenv(NAMED, "actual")

    def first_explanation_holds(
        left: object, text: str, line: str
    ) -> Tuple[bool, bool]:
        explanations = request.node.ihook.pytest_assertrepr_compare(
            config=request.config, op="==", left=left, right={NAMED: "x"}
        )
        first = next((lines for lines in explanations if lines), None)
        return _holds(first, text), _holds_line(first, line)

    differ = f"Names whose values differ: [{NAMED!r}]"
    pytest_shows_a_value, _ = first_explanation_holds(
        {SENTINEL: sentinel, NAMED: "actual"}, sentinel, differ
    )
    assert pytest_shows_a_value, "a plain dict's diff shows no value, so this is blind"
    leaked, named = first_explanation_holds(os.environ, sentinel, differ)
    assert not leaked, "the explanation shown for os.environ holds a value"
    assert named, "the explanation shown for os.environ does not name the name"


#: The cells above that check an explanation, run in a child whose
#: explanation is made to show the run's values, as a broken hook would:
#: {plant} is the leaking explanation's body. {before_explaining} runs before
#: anything is explained, so a raise there is one for every comparison, a plain
#: mapping's included. The child's hook reads the explanation from
#: env_assertions at each call, so replacing it there replaces what it gives.
_EXPLANATION_CELLS_UNDER_A_LEAK = """\
import os
from pathlib import Path

from tests.utils import env_assertions

_explain = env_assertions.explain_environment_comparison


def _leaking(op, left, right):
    {before_explaining}
    lines = _explain(op, left, right)
    if lines is None:
        return None
    {plant}


env_assertions.explain_environment_comparison = _leaking

from tests.unit import test_environment_assertions_print_no_values as _cells  # noqa: E402
from tests.unit.test_environment_assertions_print_no_values import (  # noqa: E402
    test_a_comparison_with_an_environment_mapping_is_explained_by_names,
    test_a_differing_attribute_beside_an_environment_is_shown_as_the_summary_shows_values,
    test_a_number_beside_an_environment_is_shown_by_its_repr_only_when_short,
    test_this_runs_comparisons_with_an_environment_mapping_are_explained_by_names,
)

CHECKOUT = Path({checkout!r})


def test_the_helpers_and_cells_imported_are_this_checkouts():
    for module in (env_assertions, _cells):
        imported = Path(module.__file__).resolve()
        assert imported.is_relative_to(CHECKOUT.resolve()), imported


def test_control_a_copy_shows_the_canary():
    env = dict(os.environ)
    assert env == {{}}
"""
#: The leak child's cell that checks it imports this checkout's helpers and
#: cells, which passes.
IMPORTS_THIS_CHECKOUTS_CELLS = "test_the_helpers_and_cells_imported_are_this_checkouts"


def _introspected(failure: str) -> bool:
    """Whether a failure's text holds pytest's rewritten explanation of the
    failing assertion (an ``E   assert ...`` line), which a run without
    assertion rewriting does not print."""
    return any(
        line.startswith("E") and line[1:].lstrip().startswith("assert ")
        for line in failure.splitlines()
    )


#: The child's cells, in the order the fallback explanation's set is cut from:
#: only the first reaches the fallback.
_EXPLAINED_CELLS = (
    "test_a_comparison_with_an_environment_mapping_is_explained_by_names",
    "test_a_differing_attribute_beside_an_environment_is_shown_as_the_summary_shows_values",
    "test_a_number_beside_an_environment_is_shown_by_its_repr_only_when_short",
    "test_this_runs_comparisons_with_an_environment_mapping_are_explained_by_names",
)
CANARY = "ASH_TEST_CANARY_VALUE"


@pytest.mark.integration
@pytest.mark.parametrize(
    ("plant", "options", "failing"),
    [
        pytest.param(
            "return [*lines, repr(dict(os.environ))]",
            ("-l", "-vv"),
            _EXPLAINED_CELLS,
            id="every-explanation-with-locals-shown",
        ),
        pytest.param(
            "return [repr(dict(os.environ))]"
            " if 'The names could not be read.' in lines else lines",
            ("-vv",),
            _EXPLAINED_CELLS[:1],
            id="the-fallback-explanation",
        ),
    ],
)
def test_the_explanation_cells_print_no_value_when_they_fail(
    tmp_path: Path, plant: str, options: Sequence[str], failing: Sequence[str]
) -> None:
    """Each cell that checks an explanation fails, under an explanation that
    shows the run's values, without printing them: it asserts on booleans
    computed from the explanation, never on the explanation's text, which
    pytest would print as an assertion's operand and, under ``-l``, as a
    local. A control in the same child prints a copy of the environment, so a
    value that leaks would be seen. The child's first cell checks that the
    helpers and the cells it runs are this checkout's, and each failure must
    hold pytest's rewritten explanation, so a run that imported other code or
    did not rewrite assertions does not pass as one that printed nothing."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    canary = "canary-" + secrets.token_hex(16)
    failures, ran, returncode = _run_the_child(
        tmp_path,
        _EXPLANATION_CELLS_UNDER_A_LEAK.format(
            before_explaining="pass", plant=plant, checkout=str(REPOSITORY)
        ),
        sentinel,
        options=options,
        extra_environment={CANARY: canary},
    )
    assert IMPORTS_THIS_CHECKOUTS_CELLS in ran, f"the child exited {returncode}"
    control = "test_control_a_copy_shows_the_canary"
    assert sorted(failures) == sorted([*failing, control]), (
        f"the child exited {returncode}; ran {sorted(ran)}"
    )
    assert canary in failures[control], "the control did not print the canary"
    unexplained = [name for name in failing if not _introspected(failures[name])]
    assert unexplained == [], "these failures hold no rewritten explanation"
    leaked = [name for name in failing if canary in failures[name]]
    assert leaked == [], "these cells printed the run's values when they failed"


#: What the explanation raises in the child below.
_EXPLANATION_RAISED = "the explanation could not be built"


@pytest.mark.integration
def test_the_explanation_cells_hand_no_value_to_an_explanation_that_raises(
    tmp_path: Path,
) -> None:
    """Each cell that checks an explanation fails, under an explanation that
    raises before it explains anything, without printing the run's values.
    The traceback's last entry shows the arguments the explanation was given,
    in full under ``-vv``, and ``-l`` shows the locals of the entries it
    prints whole, so a cell must give an explanation nothing of the run's own
    environment, the mapping it compares as a control included. The control
    in the same child prints a copy of the environment, so a value that leaks
    would be seen, and each failure must hold the raise, so a run whose
    explanation did not raise does not pass as one that printed nothing."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    canary = "canary-" + secrets.token_hex(16)
    failures, ran, returncode = _run_the_child(
        tmp_path,
        _EXPLANATION_CELLS_UNDER_A_LEAK.format(
            before_explaining=f"raise RuntimeError({_EXPLANATION_RAISED!r})",
            plant="return lines",
            checkout=str(REPOSITORY),
        ),
        sentinel,
        options=("-l", "-vv"),
        extra_environment={CANARY: canary},
    )
    assert IMPORTS_THIS_CHECKOUTS_CELLS in ran, f"the child exited {returncode}"
    control = "test_control_a_copy_shows_the_canary"
    assert sorted(failures) == sorted([*_EXPLAINED_CELLS, control]), (
        f"the child exited {returncode}; ran {sorted(ran)}"
    )
    assert canary in failures[control], "the control did not print the canary"
    unraised = [
        name for name in _EXPLAINED_CELLS if _EXPLANATION_RAISED not in failures[name]
    ]
    assert unraised == [], "these failures do not hold the explanation's raise"
    leaked = [name for name in _EXPLAINED_CELLS if canary in failures[name]]
    assert leaked == [], "these cells gave an explanation the run's values"


UNITTEST_CHILD = f"""\
import os
import unittest
from pathlib import Path

from tests.utils import env_assertions
from tests.utils.env_assertions import NamesOnlyEnvironment
from tests.utils.helpers import checkout_env

SENTINEL = {SENTINEL!r}
NAMED = {NAMED!r}
CHECKOUT = Path({str(REPOSITORY)!r})


def _sentinel_first():
    return {{SENTINEL: os.environ[SENTINEL], **os.environ}}


def test_the_helpers_imported_are_this_checkouts():
    imported = Path(env_assertions.__file__).resolve()
    assert imported.is_relative_to(CHECKOUT.resolve()), imported


class TestEnvironmentsInUnittestAssertions(unittest.TestCase):
    def test_os_environ_in_assert_equal(self):
        self.assertEqual(os.environ, {{NAMED: "x"}})

    def test_checkout_env_in_assert_equal(self):
        self.assertEqual(checkout_env(_sentinel_first()), {{NAMED: "x"}})

    def test_names_only_environment_in_assert_dict_equal(self):
        self.assertDictEqual(NamesOnlyEnvironment(_sentinel_first()), {{NAMED: "x"}})

    def test_a_small_names_only_environment_in_assert_dict_equal(self):
        # Small enough that the diff of the two sides unittest pprints stays
        # under maxDiff, so it is shown: pprint is called from unittest.case.
        small = NamesOnlyEnvironment(
            {{SENTINEL: os.environ[SENTINEL], NAMED: "actual"}}
        )
        self.assertDictEqual(small, {{NAMED: "x"}})

    def test_control_a_copy_in_assert_equal(self):
        self.assertEqual(_sentinel_first(), {{NAMED: "x"}})
"""
#: unittest builds a failing assertion's message in its own frames (unittest
#: .case, unittest.util), and cuts each operand's repr to its first 41 and
#: last 5 characters: each shape must show the mapping's names-only repr.
UNITTEST_SHAPES = {
    "test_os_environ_in_assert_equal": "environ(names=",
    "test_checkout_env_in_assert_equal": "NamesOnlyEnvironment(names=",
    "test_names_only_environment_in_assert_dict_equal": "NamesOnlyEnvironment(names=",
    # The diff line of the first side, as unittest's pprint gives it.
    "test_a_small_names_only_environment_in_assert_dict_equal": (
        "- NamesOnlyEnvironment(names="
    ),
}
UNITTEST_CONTROLS = ("test_control_a_copy_in_assert_equal",)


def _holds_a_sentinel_run(text: str, sentinel: str) -> bool:
    """Whether *text* holds any 8 consecutive characters of the sentinel's
    random part: unittest cuts a repr short, so the whole sentinel need not
    be there for some of it to be."""
    random_part = sentinel.removeprefix("sentinel-")
    return any(
        random_part[start : start + 8] in text for start in range(len(random_part) - 7)
    )


@pytest.mark.integration
@pytest.mark.parametrize(
    "options",
    [pytest.param((), id="default"), pytest.param(("-vv",), id="most-verbose")],
)
def test_a_unittest_assertion_on_an_environment_mapping_prints_its_names(
    tmp_path: Path, options: Tuple[str, ...]
) -> None:
    """unittest's assertEqual and assertDictEqual build their message from
    the operands' reprs in unittest's own frames: on an environment mapping
    that message shows its names, not part of a value. The control, a plain
    copy with the sentinel first, shows a run of the sentinel through the same
    cut, so the check is not blind."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    failures, ran, returncode = _run_the_child(
        tmp_path, UNITTEST_CHILD, sentinel, options
    )
    assert IMPORTS_THIS_CHECKOUTS_HELPERS in ran, f"the child exited {returncode}"
    failed = sorted(failures)
    expected = sorted([*UNITTEST_SHAPES, *UNITTEST_CONTROLS])
    assert failed == expected, f"the child exited {returncode}"
    blind = [
        name
        for name in UNITTEST_CONTROLS
        if not _holds_a_sentinel_run(failures[name], sentinel)
    ]
    assert blind == [], "a control printed no run of the sentinel, so this is blind"
    leaked = [
        name
        for name in UNITTEST_SHAPES
        if _holds_a_sentinel_run(failures[name], sentinel)
    ]
    assert leaked == [], "these unittest messages print part of a value"
    unnamed = [
        name for name, shown in UNITTEST_SHAPES.items() if shown not in failures[name]
    ]
    assert unnamed == [], "these unittest messages do not show the names-only repr"


@pytest.mark.unit
def test_code_a_mock_calls_gets_the_environments_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """unittest's frames count as reporting only when one of them is the
    first caller that is not a formatting layer: code a mock calls (its
    side_effect) is that caller, and gets the values, so a leak it makes stays
    visible to a test that checks for it."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)
    seen: List[str] = []
    run = mock.Mock(side_effect=lambda: seen.append(repr(os.environ)))
    run()
    shown = sentinel in seen[0]
    assert shown, "code a mock called got the names-only repr"


@pytest.mark.unit
def test_this_sessions_root_conftest_is_asked_first(
    request: pytest.FixtureRequest,
) -> None:
    """The root conftest's ``pytest_assertrepr_compare`` is the first
    implementation pytest asks in this session, and no hookwrapper is
    registered for the hook: ``tryfirst`` alone does not put it before a
    plugin that registers one later, in its own ``pytest_configure``, and a
    wrapper could replace its result."""
    problems = assertrepr_compare_order_problems(
        request.config.pluginmanager, REPOSITORY / "tests" / "conftest.py"
    )
    assert problems == []


@pytest.mark.unit
def test_the_root_conftest_registers_the_suites_hook(
    request: pytest.FixtureRequest,
) -> None:
    """The root conftest's ``pytest_assertrepr_compare`` is the suite's one
    function in tests/utils/env_assertions.py, so the hook the child sessions
    register (test_the_childs_conftest_registers_the_suites_hook) is the one
    this session runs, and a change to it is measured."""
    shared = getattr(env_assertions, "explain_comparisons_by_names", None)
    root_conftest = (REPOSITORY / "tests" / "conftest.py").resolve()
    root_functions = [
        implementation.function
        for implementation in (
            request.config.pluginmanager.hook.pytest_assertrepr_compare.get_hookimpls()
        )
        if Path(getattr(implementation.plugin, "__file__", "") or "").resolve()
        == root_conftest
    ]
    assert shared is not None and root_functions == [shared], (
        "the root conftest registers a hook of its own, not the suite's"
    )


#: A child test that reads what the child's own conftest registered for the
#: hook, as pytest holds it once the conftest is loaded: so a later binding of
#: the name, not only a def or the import, decides.
_CHILD_REGISTERS = """\
from pathlib import Path

from tests.utils.env_assertions import explain_comparisons_by_names


def test_the_conftest_registers_the_suites_hook(request):
    conftest = (Path(__file__).parent / "conftest.py").resolve()
    hook = request.config.pluginmanager.hook.pytest_assertrepr_compare
    registered = [
        implementation.function
        for implementation in hook.get_hookimpls()
        if Path(getattr(implementation.plugin, "__file__", "") or "").resolve()
        == conftest
    ]
    is_the_suites = [function is explain_comparisons_by_names for function in registered]
    assert is_the_suites == [True]
"""

#: CHILD_CONFTEST with the hook's name bound again after the import, to a
#: hook implementation of its own: the child registers that one instead.
_CHILD_CONFTEST_REBOUND = (
    CHILD_CONFTEST
    + "\nimport pytest\n\n"
    + "pytest_assertrepr_compare = pytest.hookimpl(tryfirst=True)(\n"
    + "    lambda op, left, right: None\n"
    + ")\n"
)


@pytest.mark.integration
@pytest.mark.parametrize(
    ("conftest", "registers_the_suites"),
    [
        pytest.param(CHILD_CONFTEST, True, id="the-childs-conftest"),
        pytest.param(_CHILD_CONFTEST_REBOUND, False, id="the-name-bound-again"),
    ],
)
def test_the_childs_conftest_registers_the_suites_hook(
    tmp_path: Path, conftest: str, registers_the_suites: bool
) -> None:
    """The child sessions' conftest registers the suite's hook function, read
    from the child session itself, so what the children measure is the hook
    this session runs; one that binds the name to anything else is refused."""
    failures, ran, returncode = _run_the_child(
        tmp_path,
        _CHILD_REGISTERS,
        "sentinel-" + secrets.token_hex(16),
        conftest=conftest,
    )
    assert ran == ["test_the_conftest_registers_the_suites_hook"], (
        f"the child exited {returncode}"
    )
    assert (failures == {}) is registers_the_suites, f"the child exited {returncode}"
    if not registers_the_suites:
        # One implementation registered, and not the suite's.
        failure = failures["test_the_conftest_registers_the_suites_hook"]
        assert "[False] == [True]" in failure, f"the child exited {returncode}"


@pytest.mark.integration
@pytest.mark.parametrize(
    "workers", [pytest.param("0", id="no-workers"), pytest.param("2", id="workers")]
)
def test_the_root_conftest_is_asked_first_with_and_without_workers(
    tmp_path: Path, workers: str
) -> None:
    """The call-order pin above, run in a session of its own without xdist
    workers and in one with them, under the repository's own configuration
    and every installed plugin: a worker loads its plugins again."""
    report = tmp_path / "report.xml"
    pin = (
        f"{Path(__file__).resolve().relative_to(REPOSITORY)}"
        "::test_this_sessions_root_conftest_is_asked_first"
    )
    # Not this session's pytest variables: a child that inherited a worker's
    # would take itself for that worker. Filtered before checkout_env routes
    # the mapping, so the routed result is given to the child as it is.
    env = checkout_env(
        {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("PYTEST_")
        }
    )
    run = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:randomly",
            "-n",
            workers,
            "-q",
            f"--basetemp={tmp_path / 'child'}",
            f"--junit-xml={report}",
            pin,
        ],
        cwd=REPOSITORY,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    cases = list(ET.parse(report).getroot().iter("testcase"))
    ran = [case.get("name") for case in cases]
    failed = [case.get("name") for case in cases if case.find("failure") is not None]
    assert ran == ["test_this_sessions_root_conftest_is_asked_first"], (
        f"the child exited {run.returncode}"
    )
    assert failed == [], f"the child exited {run.returncode}"


#: Plugins the call-order pin is measured against, each loaded with ``-p``.
#: One registered early (the only shape ``tryfirst`` alone wins against), one
#: that registers a ``tryfirst`` implementation in its own
#: ``pytest_configure``, after the conftests, and a wrapper of each style.
_EARLY_TRYFIRST_PLUGIN = """\
import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_assertrepr_compare(op, left, right):
    return None
"""
_LATE_TRYFIRST_PLUGIN = """\
import pytest


class _Late:
    @pytest.hookimpl(tryfirst=True)
    def pytest_assertrepr_compare(self, op, left, right):
        return None


def pytest_configure(config):
    config.pluginmanager.register(_Late(), "late-tryfirst")
"""
_HOOKWRAPPER_PLUGIN = """\
import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_assertrepr_compare(op, left, right):
    yield
"""
_NEW_STYLE_WRAPPER_PLUGIN = """\
import pytest


@pytest.hookimpl(wrapper=True)
def pytest_assertrepr_compare(op, left, right):
    return (yield)
"""
_ORDER_PIN = """\
from pathlib import Path

from tests.utils.env_assertions import assertrepr_compare_order_problems


def test_the_conftest_is_asked_first(request):
    problems = assertrepr_compare_order_problems(
        request.config.pluginmanager, Path(__file__).parent / "conftest.py"
    )
    assert problems == []
"""


@pytest.mark.integration
@pytest.mark.parametrize(
    ("plugin", "refusal"),
    [
        pytest.param(None, None, id="no-plugin"),
        pytest.param(_EARLY_TRYFIRST_PLUGIN, None, id="tryfirst-loaded-with-p"),
        pytest.param(
            _LATE_TRYFIRST_PLUGIN,
            "late-tryfirst is asked before",
            id="tryfirst-registered-in-configure",
        ),
        pytest.param(
            _HOOKWRAPPER_PLUGIN,
            "a hookwrapper is registered: order_plugin",
            id="hookwrapper",
        ),
        pytest.param(
            _NEW_STYLE_WRAPPER_PLUGIN,
            "a hookwrapper is registered: order_plugin",
            id="wrapper",
        ),
    ],
)
def test_the_order_pin_refuses_a_late_or_wrapping_implementation(
    tmp_path: Path, plugin: Optional[str], refusal: Optional[str]
) -> None:
    """The pin, in a child session under CHILD_CONFTEST: it fails on the two
    shapes that would be asked before the conftest's hook, or replace its
    result, and passes on a plugin ``tryfirst`` already wins against."""
    options: Tuple[str, ...] = ()
    if plugin is not None:
        (tmp_path / "order_plugin.py").write_text(plugin, encoding="utf-8")
        options = ("-p", "order_plugin")
    failures, ran, returncode = _run_the_child(
        tmp_path,
        _ORDER_PIN,
        "sentinel-" + secrets.token_hex(16),
        options,
        {"PYTHONPATH": str(tmp_path)},
    )
    assert ran == ["test_the_conftest_is_asked_first"], f"the child exited {returncode}"
    if refusal is None:
        assert failures == {}, f"the child exited {returncode}"
    else:
        assert refusal in failures.get("test_the_conftest_is_asked_first", ""), (
            f"the child exited {returncode}"
        )


@pytest.mark.unit
def test_os_environ_shows_values_to_code_and_names_to_pytest(monkeypatch):
    """repr(os.environ) called by ordinary code, the code under test first,
    gives the values, so a leak a test checks a command's output for stays
    visible. pytest's own reporting, which prints a frame's arguments and an
    explanation's receivers through ``_pytest._io.saferepr``, gets the names
    only."""
    from _pytest._io.saferepr import saferepr

    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)
    shown_to_code = sentinel in repr(os.environ)
    shown_to_pytest = sentinel in saferepr(os.environ, maxsize=None)
    named_to_pytest = SENTINEL in saferepr(os.environ, maxsize=None)
    assert (shown_to_code, shown_to_pytest, named_to_pytest) == (True, False, True)


@pytest.mark.unit
def test_a_generator_is_looked_through_to_the_frame_that_runs_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A generator expression or a comprehension runs in a frame of its own:
    code that formats the environment in one gets the values, so a leak
    through it stays visible, and a carrier's repr that formats it in one
    gives pytest's reporting the names only."""
    from _pytest._io.saferepr import saferepr

    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)

    class Carrier:
        def __repr__(self) -> str:
            return ", ".join(repr(env) for env in [os.environ])

    by_code_in_a_generator = sentinel in "".join(repr(env) for env in [os.environ])
    by_code_in_a_list = sentinel in "".join([repr(env) for env in [os.environ]])
    carrier_to_pytest = sentinel in saferepr(Carrier(), maxsize=None)
    carrier_to_code = sentinel in repr(Carrier())
    assert (
        by_code_in_a_generator,
        by_code_in_a_list,
        carrier_to_pytest,
        carrier_to_code,
    ) == (True, True, False, True)


@pytest.mark.unit
def test_a_names_only_environment_shows_values_to_code():
    """The same split for NamesOnlyEnvironment: code under test that formats
    one prints the values, so its leak stays visible, and pytest's reporting
    prints the names."""
    from _pytest._io.saferepr import saferepr

    from tests.utils.env_assertions import NamesOnlyEnvironment

    sentinel = "sentinel-" + secrets.token_hex(16)
    mapping = NamesOnlyEnvironment({SENTINEL: sentinel})
    shown_to_code = sentinel in repr(mapping)
    shown_to_pytest = sentinel in saferepr(mapping, maxsize=None)
    named_to_pytest = SENTINEL in saferepr(mapping, maxsize=None)
    assert (shown_to_code, shown_to_pytest, named_to_pytest) == (True, False, True)


@pytest.mark.unit
def test_a_leak_planted_in_code_under_test_is_caught(tmp_path, monkeypatch):
    """A print of ``repr(os.environ)`` planted in a command's path puts the
    environment's values in the command's output, where the leak cells that
    assert a value is absent catch it. A repr that hid the values from every
    caller would blind those cells instead."""
    from typer.testing import CliRunner

    from automated_security_helper.cli import config as cli_config
    from automated_security_helper.cli.main import app

    value = "qzab1234" * 75
    monkeypatch.setenv("ASH_TEST_LONG_VALUE", value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ash.yaml").write_text(
        "project_name: ${ASH_TEST_LONG_VALUE}\n", encoding="utf-8"
    )
    real = cli_config._config_path_or_discovered

    def planted(*args, **kwargs):
        print(f"environment at start: {os.environ!r}")
        return real(*args, **kwargs)

    monkeypatch.setattr(cli_config, "_config_path_or_discovered", planted)

    result = CliRunner().invoke(
        app, ["config", "validate", "--config", str(tmp_path / "ash.yaml")]
    )

    assert "environment at start:" in result.output, result.output[:2000]
    assert value[:12] in result.output, (
        "the planted print does not show the value, so a leak like it is "
        "invisible to the cells that check command output"
    )


@pytest.mark.unit
def test_a_carrier_built_repr_shows_names_to_pytest():
    """pytest's reporting prints a frame's arguments with repr. A carrier
    object's own Python ``__repr__`` that embeds the mapping
    (``f"Carrier(env={env!r})"``) rebuilds the mapping's repr from the
    carrier's frame, so the names-only split must hold through that frame,
    not only when pytest's code is the direct caller."""
    from _pytest._io.saferepr import saferepr

    from tests.utils.env_assertions import NamesOnlyEnvironment

    sentinel = "sentinel-" + secrets.token_hex(16)
    mapping = NamesOnlyEnvironment({SENTINEL: sentinel})

    class Carrier:
        def __repr__(self):
            return f"Carrier(env={mapping!r})"

    shown_to_code = sentinel in repr(Carrier())
    shown_to_pytest = sentinel in saferepr(Carrier(), maxsize=None)
    named_to_pytest = SENTINEL in saferepr(Carrier(), maxsize=None)
    assert (shown_to_code, shown_to_pytest, named_to_pytest) == (True, False, True)


@pytest.mark.unit
def test_os_environ_in_a_carrier_built_repr_shows_names_to_pytest(monkeypatch):
    """The same split for ``os.environ`` under ``hide_environ_values``, which
    the root conftest has applied: a carrier's ``__repr__`` embedding
    ``os.environ`` gives pytest's reporting the names only."""
    from _pytest._io.saferepr import saferepr

    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)

    class Carrier:
        def __repr__(self):
            return f"Carrier(env={os.environ!r})"

    shown_to_code = sentinel in repr(Carrier())
    shown_to_pytest = sentinel in saferepr(Carrier(), maxsize=None)
    named_to_pytest = SENTINEL in saferepr(Carrier(), maxsize=None)
    assert (shown_to_code, shown_to_pytest, named_to_pytest) == (True, False, True)


@pytest.mark.unit
def test_environment_views_show_names_to_pytest(monkeypatch):
    """``os.environ.keys()`` and ``.items()`` are views whose Python
    ``__repr__`` (in ``_collections_abc``) rebuilds the mapping's repr from
    the view's own frame, so the names-only split must hold through it when
    pytest's reporting prints a comparison's receiver or a frame's argument.
    The same reprs from test or product code show the values."""
    from _pytest._io.saferepr import saferepr

    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)

    keys_to_pytest = sentinel in saferepr(os.environ.keys(), maxsize=None)
    items_to_pytest = sentinel in saferepr(os.environ.items(), maxsize=None)
    keys_named_to_pytest = SENTINEL in saferepr(os.environ.keys(), maxsize=None)
    keys_to_code = sentinel in repr(os.environ.keys())
    items_to_code = sentinel in repr(os.environ.items())
    assert (
        keys_to_pytest,
        items_to_pytest,
        keys_named_to_pytest,
        keys_to_code,
        items_to_code,
    ) == (False, False, True, True, True)


def _mock_failure_message(env):
    from unittest import mock

    m = mock.Mock()
    m(["x"], env=env)
    try:
        m.assert_called_once_with(["y"])
    except AssertionError as error:
        return str(error)
    raise AssertionError("the mock assertion did not fail")


@pytest.mark.unit
def test_a_mock_assertion_message_shows_names_for_os_environ(monkeypatch):
    """``unittest.mock`` builds a failing assertion's message in its own
    frames, formatting the actual call's arguments; pytest prints that message
    as the failure. An environment passed as ``env=`` appears in it as names
    only, even when the assertion itself names no ``env=``."""
    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)

    message = _mock_failure_message(os.environ)
    shown = sentinel in message
    named = SENTINEL in message
    assert (shown, named) == (False, True)


@pytest.mark.unit
def test_a_mock_assertion_message_shows_names_for_names_only_environment(
    monkeypatch,
):
    """The same split for the mapping ``checkout_env`` returns."""
    from tests.utils.env_assertions import NamesOnlyEnvironment

    sentinel = "sentinel-" + secrets.token_hex(16)
    monkeypatch.setenv(SENTINEL, sentinel)

    message = _mock_failure_message(NamesOnlyEnvironment(os.environ))
    shown = sentinel in message
    named = SENTINEL in message
    assert (shown, named) == (False, True)


@pytest.mark.unit
def test_a_names_only_environments_views_show_names_to_pytest():
    """``.items()`` and ``.values()`` of a ``NamesOnlyEnvironment`` hold the
    names-only split too: a plain dict's C views would print raw key-value
    pairs without ever reaching the mapping's repr. Test and product code
    still see the values through the same views."""
    from _pytest._io.saferepr import saferepr

    from tests.utils.env_assertions import NamesOnlyEnvironment

    sentinel = "sentinel-" + secrets.token_hex(16)
    mapping = NamesOnlyEnvironment({SENTINEL: sentinel})

    items_to_pytest = sentinel in saferepr(mapping.items(), maxsize=None)
    values_to_pytest = sentinel in saferepr(mapping.values(), maxsize=None)
    items_named_to_pytest = SENTINEL in saferepr(mapping.items(), maxsize=None)
    items_to_code = sentinel in repr(mapping.items())
    values_to_code = sentinel in repr(mapping.values())
    assert (
        items_to_pytest,
        values_to_pytest,
        items_named_to_pytest,
        items_to_code,
        values_to_code,
    ) == (False, False, True, True, True)


@pytest.mark.unit
def test_pprint_called_by_code_shows_values(monkeypatch):
    """``pprint`` and ``reprlib`` are ordinary library code: code under test
    that formats an environment through them prints the values, so a leak
    through either stays visible to a test that checks the command's output.
    They give names only when they are formatting for pytest's reporting
    (``safeformat``, below)."""
    import pprint
    import reprlib

    from tests.utils.env_assertions import NamesOnlyEnvironment

    sentinel = "sentinel-" + secrets.token_hex(16)
    mapping = NamesOnlyEnvironment({SENTINEL: sentinel})
    monkeypatch.setenv(SENTINEL, sentinel)

    mapping_by_pprint = sentinel in pprint.pformat(mapping)
    environ_by_pprint = sentinel in pprint.pformat(os.environ)
    # reprlib shows a dict subclass by its own repr, cut at maxother. Repr
    # takes that limit as a keyword only from Python 3.12; set as an attribute
    # it holds on every version this supports.
    long_repr = reprlib.Repr()
    long_repr.maxother = 10_000
    mapping_by_reprlib = sentinel in long_repr.repr(mapping)
    assert (mapping_by_pprint, environ_by_pprint, mapping_by_reprlib) == (
        True,
        True,
        True,
    )


@pytest.mark.unit
def test_pprint_formatting_for_pytest_shows_names(monkeypatch):
    """``safeformat``, pytest's locals formatter, formats through stdlib
    ``pprint``: the mapping still gives it names only, because the formatting
    frames sit under pytest's reporting."""
    from _pytest._io.saferepr import safeformat

    from tests.utils.env_assertions import NamesOnlyEnvironment

    sentinel = "sentinel-" + secrets.token_hex(16)
    mapping = NamesOnlyEnvironment({SENTINEL: sentinel})
    monkeypatch.setenv(SENTINEL, sentinel)

    mapping_hidden = sentinel not in safeformat(mapping)
    mapping_named = SENTINEL in safeformat(mapping)
    environ_hidden = sentinel not in safeformat(os.environ)
    assert (mapping_hidden, mapping_named, environ_hidden) == (True, True, True)


@pytest.mark.unit
def test_a_pprint_leak_planted_in_code_under_test_is_caught(tmp_path, monkeypatch):
    """Like the planted ``repr`` leak above, but the planted print formats the
    environment through ``pprint``: the values must reach the command's
    output, where the cells that assert a value is absent catch them."""
    import pprint

    from typer.testing import CliRunner

    from automated_security_helper.cli import config as cli_config
    from automated_security_helper.cli.main import app

    value = "qzab1234" * 75
    monkeypatch.setenv("ASH_TEST_LONG_VALUE", value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    (tmp_path / "ash.yaml").write_text(
        "project_name: ${ASH_TEST_LONG_VALUE}\n", encoding="utf-8"
    )
    real = cli_config._config_path_or_discovered

    def planted(*args, **kwargs):
        print(f"environment at start: {pprint.pformat(os.environ)}")
        return real(*args, **kwargs)

    monkeypatch.setattr(cli_config, "_config_path_or_discovered", planted)

    result = CliRunner().invoke(
        app, ["config", "validate", "--config", str(tmp_path / "ash.yaml")]
    )

    assert "environment at start:" in result.output, result.output[:2000]
    assert value[:12] in result.output, (
        "the planted pprint does not show the value, so a leak like it is "
        "invisible to the cells that check command output"
    )
