"""The per-test logger restore in tests/conftest.py covers every ASH logger.

A library calling ``logging.config.dictConfig`` with ``disable_existing_loggers``
(commitizen does, at import) disables every logger that exists at that moment.
The restore used to cover only the ``ash`` logger, so a module logger such as
``automated_security_helper.interactions.run_ash_scan`` stayed disabled for the
rest of the xdist worker, and a later CLI snapshot captured an empty stderr.
"""

import logging
import logging.config
from pathlib import Path

import pytest

MODULE_LOGGER = "automated_security_helper.interactions.run_ash_scan"


@pytest.fixture
def logger_switches(request):
    """``_AshLoggerSwitches`` from the tests/conftest.py pytest loaded.

    Not ``from tests.conftest import _AshLoggerSwitches``: pytest imports that file as
    ``conftest``, so the import would execute it a second time under another module
    name, and with it the setup it runs when it is imported.
    """
    target = (Path(__file__).resolve().parents[1] / "conftest.py").resolve()
    for plugin in request.config.pluginmanager.get_plugins():
        if Path(getattr(plugin, "__file__", "") or "").resolve() == target:
            return plugin._AshLoggerSwitches
    raise AssertionError(f"pytest has not loaded {target} as a plugin")


def _disable_everything_like_commitizen():
    logging.config.dictConfig({"version": 1, "disable_existing_loggers": True})


def test_a_module_logger_disabled_by_dictconfig_is_restored(logger_switches):
    module_logger = logging.getLogger(MODULE_LOGGER)
    assert module_logger.disabled is False

    with logger_switches():
        _disable_everything_like_commitizen()
        assert module_logger.disabled is True, "the control: dictConfig did disable it"

    assert module_logger.disabled is False


def test_the_ash_logger_is_still_restored(logger_switches):
    ash_logger = logging.getLogger("ash")
    before = (ash_logger.level, ash_logger.propagate, ash_logger.disabled)

    with logger_switches():
        ash_logger.setLevel(logging.CRITICAL)
        ash_logger.propagate = not ash_logger.propagate
        _disable_everything_like_commitizen()

    assert (ash_logger.level, ash_logger.propagate, ash_logger.disabled) == before


def test_an_ash_logger_created_and_disabled_inside_the_block_is_re_enabled(
    logger_switches,
):
    name = "automated_security_helper.tests_only.created_inside_the_block"
    with logger_switches():
        created = logging.getLogger(name)
        _disable_everything_like_commitizen()
        assert created.disabled is True

    assert created.disabled is False


def test_loggers_outside_ashs_namespaces_are_left_alone(logger_switches):
    other = logging.getLogger("not_ash.tests_only")
    with logger_switches():
        _disable_everything_like_commitizen()
    assert other.disabled is True
    other.disabled = False
