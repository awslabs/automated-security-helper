"""The per-test logger restore in tests/conftest.py covers every ASH logger.

A library calling ``logging.config.dictConfig`` with ``disable_existing_loggers``
(commitizen does, at import) disables every logger that exists at that moment.
The restore used to cover only the ``ash`` logger, so a module logger such as
``automated_security_helper.interactions.run_ash_scan`` stayed disabled for the
rest of the xdist worker, and a later CLI snapshot captured an empty stderr.
"""

import logging
import logging.config

from tests.conftest import _AshLoggerSwitches

MODULE_LOGGER = "automated_security_helper.interactions.run_ash_scan"


def _disable_everything_like_commitizen():
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})


def test_a_module_logger_disabled_by_dictconfig_is_restored():
    module_logger = logging.getLogger(MODULE_LOGGER)
    assert module_logger.disabled is False

    with _AshLoggerSwitches():
        _disable_everything_like_commitizen()
        assert module_logger.disabled is True, "the control: dictConfig did disable it"

    assert module_logger.disabled is False


def test_the_ash_logger_is_still_restored():
    ash_logger = logging.getLogger("ash")
    before = (ash_logger.level, ash_logger.propagate, ash_logger.disabled)

    with _AshLoggerSwitches():
        ash_logger.setLevel(logging.CRITICAL)
        ash_logger.propagate = not ash_logger.propagate
        _disable_everything_like_commitizen()

    assert (ash_logger.level, ash_logger.propagate, ash_logger.disabled) == before


def test_an_ash_logger_created_and_disabled_inside_the_block_is_re_enabled():
    name = "automated_security_helper.tests_only.created_inside_the_block"
    with _AshLoggerSwitches():
        created = logging.getLogger(name)
        _disable_everything_like_commitizen()
        assert created.disabled is True

    assert created.disabled is False


def test_loggers_outside_ashs_namespaces_are_left_alone():
    other = logging.getLogger("not_ash.tests_only")
    with _AshLoggerSwitches():
        _disable_everything_like_commitizen()
    assert other.disabled is True
    other.disabled = False
