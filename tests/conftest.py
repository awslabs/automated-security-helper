"""Pytest configuration file for ASH tests."""

import logging
import os
import sys
import tempfile
import pytest
from pathlib import Path
from typing import List, Literal

from tests.utils.helpers import get_ash_temp_path

# Add the project root to the Python path
sys.path.insert(0, str(Path(__file__).parent.parent))


def _isolate_jsii_package_cache_per_worker() -> str | None:
    """Give each xdist worker its own jsii package cache, and say which one.

    THE RACE THIS REMOVES. jsii caches an extracted assembly under a per-user
    directory and takes a lockfile while extracting. ``Entry.retrieve`` only locks
    on a cache *miss*, and holds the lock for the whole extraction --
    ``aws-cdk-lib`` is 7,457 files and about 133 MB. Its waiter, ``lockSyncWithWait``,
    retries 12 times with randomized backoff and then rethrows, so roughly 13 s
    expected and 26 s worst case. Two workers that each boot a kernel can therefore
    collide on one cache entry and the loser dies with

        EEXIST: file already exists, open
        '...\\AWS\\jsii\\package-cache\\aws-cdk-lib\\<version>\\<sha>.lock'

    Measured across the 600 most recent CI runs: zero occurrences in 1,772 decided
    Windows unit-test legs while exactly one test booted a kernel, then 12 across 583
    once a second one did. Separate roots mean there is no shared lockfile to
    contend for, so the failure is unreachable rather than merely unlikely.

    WHAT WAS NOT SHOWN. The race does not reproduce on Linux. With the guard removed,
    a cold cache and up to three booting tests sharing one root under -n 4, no EEXIST
    ever appeared: extraction finishes in about three seconds here, far inside the
    retry budget, so the loser waits and then gets its hit. The guard is therefore
    justified structurally -- distinct roots mean there is no shared lockfile to
    contend for -- and by the CI rates above, not by reproducing a failure locally and
    then preventing it. Anyone re-testing this on Linux should expect green either
    way and not read that as the guard being unnecessary.

    WHY IT IS NOT PLATFORM-GATED. Only Windows has been observed failing, but jsii's
    lock path carries no platform branch -- the sole ``process.platform`` checks in
    that module write ``.nobackup``/``.noindex`` on darwin and sweep ``.DS_Store``.
    The bounded retry budget is identical everywhere; Windows loses because creating
    7,457 files there is slow enough to exhaust it. Gating this to Windows would
    leave the same defect reachable on macOS and Linux to save nothing, because:

    WHAT IT COSTS, MEASURED. Extraction happens only when a kernel actually boots, so
    the bill is (workers that boot) x extraction, not (workers) x extraction. Measured
    on Linux with a cold cache under -n 4, one extraction being 163,654,045 bytes:

        booters   guard    bytes written   per-worker roots created
        0         on                   0   none
        1         on         163,654,045   1
        2         on         327,308,090   2
        1 or 2    off        163,654,045   n/a, one shared root

    So with no eager import anywhere the guard writes nothing and creates no
    directory -- measured across the whole unit suite, 7,734 tests, zero bytes. With
    one booter it costs the same single extraction as no guard at all. Only two or
    more booting workers pay a multiple, and that is precisely the case which is
    otherwise an intermittent failure. Note the multiplier counts booting *workers*,
    not booting tests: three booters produced two roots in one run because two landed
    on the same worker.

    Returns the root it set, or ``None`` when it deliberately set nothing.
    """
    # xdist sets this in each worker before pytest_configure runs; the controller
    # has neither it nor config.workerinput, and runs no tests. A plain pytest run,
    # -n 0, or -p no:xdist likewise has no worker id -- and needs none, because one
    # process cannot race itself. Leave jsii's own default alone in that case rather
    # than inventing a root named after an empty string.
    worker = (os.environ.get("PYTEST_XDIST_WORKER") or "").strip()
    if not worker:
        return None

    # Honor an explicitly chosen location by isolating *within* it, so this does not
    # silently relocate a cache someone pointed somewhere deliberately.
    configured = (os.environ.get("JSII_RUNTIME_PACKAGE_CACHE_ROOT") or "").strip()
    if configured:
        base = Path(configured)
    else:
        # tempfile.gettempdir() rather than a per-platform user cache path: it needs
        # no platform branching to rot, it is per-user on Windows, it sits outside
        # the checkout so neither the repo nor ASH's own self-scan grows by 133 MB a
        # worker, and jsii itself falls back to a tmpdir root, so this is a shape it
        # already supports. The trade is that a /tmp sweep makes the cache cold.
        # That costs nothing in CI, where the runner is fresh and this cache is not
        # restored between runs anyway, and only costs a local re-extraction.
        base = Path(tempfile.gettempdir()) / "ash-jsii-package-cache"

    # Deliberately not created here. jsii's DiskCache.inDirectory already does a
    # recursive mkdir, and only on the extraction path, so leaving creation to it
    # keeps the no-booter case at literally zero directories and zero bytes rather
    # than four empty directories per run.
    root = base / worker
    os.environ["JSII_RUNTIME_PACKAGE_CACHE_ROOT"] = str(root)
    return str(root)


def pytest_configure(config):
    """Configure pytest for ASH tests."""
    # Must happen before anything imports a jsii-backed package. pytest_configure is
    # the earliest per-worker hook, and collection -- which imports test modules --
    # runs after it. jsii reads this variable in the Node runtime it spawns, so it
    # only has to be set before the first kernel starts.
    _isolate_jsii_package_cache_per_worker()

    # Register custom markers
    config.addinivalue_line(
        "markers", "unit: Unit tests that test individual components in isolation"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests that test component interactions"
    )
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")
    config.addinivalue_line(
        "markers", "scanner: Tests related to scanner functionality"
    )
    config.addinivalue_line(
        "markers", "reporter: Tests related to reporter functionality"
    )
    config.addinivalue_line(
        "markers", "config: Tests related to configuration functionality"
    )
    config.addinivalue_line("markers", "model: Tests related to data models")
    config.addinivalue_line("markers", "serial: Tests that should not run in parallel")


def pytest_addoption(parser):
    """Add custom command-line options to pytest."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests",
    )
    parser.addoption(
        "--run-integration",
        action="store_true",
        default=False,
        help="Run integration tests",
    )
    parser.addoption(
        "--run-changed-only",
        action="store_true",
        default=False,
        help="Run only tests for changed files",
    )
    parser.addoption(
        "--base-branch",
        default="main",
        help="Base branch for --run-changed-only option",
    )


def pytest_collection_modifyitems(config, items):
    """Modify the collected test items based on command-line options."""
    # Skip slow tests unless --run-slow is specified
    if not config.getoption("--run-slow"):
        skip_slow = pytest.mark.skip(reason="Need --run-slow option to run")
        for item in items:
            if "slow" in item.keywords:
                item.add_marker(skip_slow)

    # Skip integration tests unless --run-integration is specified
    if not config.getoption("--run-integration"):
        skip_integration = pytest.mark.skip(
            reason="Need --run-integration option to run"
        )
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)


@pytest.fixture(scope="session", autouse=True)
def _keep_live_logging_off_the_ash_logger(request):
    """Detach pytest's live-logging handler from the ``ash`` logger.

    Why this exists. ``pytest.ini`` sets ``log_cli = True``, and
    ``automated_security_helper.utils.log`` sets ``ASH_LOGGER.propagate = False``.
    pytest adds its session-lifetime ``_LiveLoggingStreamHandler`` to the root
    logger and -- because a non-propagating logger would never reach root -- to
    every non-propagating logger that exists when the test loop starts
    (``catching_logs.__enter__`` in ``_pytest/logging.py``). So every ASH record at
    ``log_cli_level`` or above goes through that handler, and the handler suspends
    and resumes pytest's capture around its write, via
    ``CaptureManager.global_and_fixture_disabled``. Resuming assigns
    ``sys.stdout``/``sys.stderr`` (``SysCapture.suspend`` in
    ``_pytest/capture.py``).

    That assignment is fatal inside ``typer.testing.CliRunner.invoke``. Its
    ``isolation()`` puts a ``TextIOWrapper`` over each buffer it will read back
    afterwards and keeps no reference to the wrapper other than ``sys.stdout`` /
    ``sys.stderr``. Reassigning those drops the last reference, the wrapper is
    finalized, finalizing closes the wrapped buffer, and ``invoke``'s ``finally``
    clause raises ``ValueError: I/O operation on closed file`` where it would have
    returned a ``Result``. A CLI test on any code path that logs then dies in the
    harness instead of reporting what the CLI did -- and the CLI itself is fine,
    which is what makes the failure so hard to read.

    Only ``log_cli_handler`` is removed. ``LogCaptureHandler`` stays, so ``caplog``
    and the "Captured log call" report section still see ASH records; those
    handlers write to a ``StringIO`` and never touch capture.

    What was tried and rejected. Dropping ``capsys`` from the affected test does
    not help -- pytest's global fd-level capture reassigns the streams on suspend
    as well, and the failure reproduces byte for byte without the fixture. Setting
    ``log_cli = False`` in ``pytest.ini`` also works and is a shorter edit, but it
    turns live logging off for every logger rather than for the one that is
    incompatible with ``CliRunner``, and live logging is genuinely useful when
    running a single test with ``-n0``.

    Failure mode this prevents, and why it looked like a platform bug. Without
    this fixture the outcome is order-dependent, because any test that clears the
    ``ash`` logger's handlers permanently detaches the session-scoped handler for
    the rest of that worker process -- ``cli/main.py``'s ``reset_logging_config``
    and ``utils/log.py``'s ``get_logger`` both do exactly that, and seven files
    under ``tests/unit/cli`` reach one of them. Under ``-n auto`` the xdist worker
    count decides which tests share a process, so one commit was green on the
    4-worker Linux and Windows runners and red on the 3-worker macOS runners.
    """
    plugin = request.config.pluginmanager.get_plugin("logging-plugin")
    handler = getattr(plugin, "log_cli_handler", None)
    if handler is not None:
        logging.getLogger("ash").removeHandler(handler)
    yield


@pytest.fixture(autouse=True)
def _restore_ash_logger_switches():
    """Stop one test's logging side effects from blinding another's ``caplog``.

    ``level``, ``propagate`` and ``disabled`` live on a process-global logger
    object, so a test that changes any of them changes it for every later test on
    the same xdist worker. ``disabled`` is the dangerous one: a disabled logger
    drops records inside ``Logger.handle``, before any handler is consulted, so
    ``caplog.records`` comes back empty and the assertion reads as the code under
    test not having logged at all. Nothing in the record says logging was off.

    No test sets ``disabled`` on purpose. It gets set from a distance: any
    ``logging.config.dictConfig`` call whose payload has
    ``disable_existing_loggers`` true -- the default -- disables every logger not
    named in that payload, and libraries do this at import time. ``commitizen``
    is one, at ``commitizen/__init__.py``, so a single ``import commitizen`` from
    inside a test disables the ``ash`` logger for the rest of that worker.

    That is how this was found, and the shape is worth remembering because none
    of the signals point at the cause. Two ``test_cdk_nag_wrapper_behavior``
    assertions went red on eleven CI cells after an unrelated test file was added
    in a different directory; they passed with that file removed, passed when run
    alone, and passed at a different ``-n`` because the worker count decides which
    tests share a process. The failing tests were not at fault, the added file did
    not touch logging, and nothing in either was near cdk-nag.

    Snapshotting the three switches per test keeps the blast radius of any such
    import inside the test that caused it. Handlers are deliberately left alone:
    the session fixture above manages those, and rebuilding the handler list here
    would fight it.
    """
    ash_logger = logging.getLogger("ash")
    level, propagate, disabled = (
        ash_logger.level,
        ash_logger.propagate,
        ash_logger.disabled,
    )
    try:
        yield
    finally:
        ash_logger.level = level
        ash_logger.propagate = propagate
        ash_logger.disabled = disabled


@pytest.fixture
def ash_temp_path():
    """Create a temporary directory using the gitignored tests/pytest-temp directory.

    This fixture provides a consistent temporary directory that is gitignored
    and located within the tests directory structure.

    Returns:
        Path to the temporary directory
    """
    import shutil

    temp_dir = get_ash_temp_path()
    yield temp_dir

    # Cleanup after the test
    if temp_dir.exists():
        shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def temp_config_dir(ash_temp_path):
    """Create a temporary directory for configuration files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary configuration directory
    """
    config_dir = ash_temp_path / "config"
    config_dir.mkdir()
    return config_dir


@pytest.fixture
def temp_output_dir(ash_temp_path):
    """Create a temporary directory for output files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary output directory
    """
    output_dir = ash_temp_path / "output"
    output_dir.mkdir()
    return output_dir


@pytest.fixture
def temp_project_dir(ash_temp_path):
    """Create a temporary directory for project files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the temporary project directory
    """
    project_dir = ash_temp_path / "project"
    project_dir.mkdir()

    # Create a basic project structure
    (project_dir / "src").mkdir()
    (project_dir / "tests").mkdir()
    (project_dir / ".ash").mkdir()

    return project_dir


@pytest.fixture
def temp_env_vars():
    """Create a fixture for temporarily setting environment variables.

    Returns:
        Function that sets environment variables for the duration of a test
    """
    original_env = {}

    def _set_env_vars(**kwargs):
        for key, value in kwargs.items():
            if key in os.environ:
                original_env[key] = os.environ[key]
            os.environ[key] = str(value)

    yield _set_env_vars

    # Restore original environment variables
    for key in original_env:
        os.environ[key] = original_env[key]

    # Remove environment variables that were not originally set
    for key in os.environ.keys() - original_env.keys():
        if key in os.environ:
            del os.environ[key]


@pytest.fixture
def test_plugin_context(ash_temp_path):
    """Create a test plugin context for testing.

    Returns:
        A mock plugin context for testing
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from pathlib import Path

    # Create a real PluginContext object instead of a mock
    source_dir = Path(f"{ash_temp_path}/test_source_dir")
    output_dir = Path(f"{ash_temp_path}/test_output_dir")
    work_dir = Path(f"{ash_temp_path}/test_work_dir")

    # Use a proper AshConfig object
    from automated_security_helper.config.default_config import get_default_config

    # Use default config to ensure all required fields are present
    config = get_default_config()

    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=config,
    )

    return context


@pytest.fixture
def test_source_dir(ash_temp_path):
    """Create a test source directory with sample files.

    Args:
        ash_temp_path: ASH fixture that provides a temporary directory

    Returns:
        Path to the test source directory
    """
    source_dir = ash_temp_path / "source"
    Path(source_dir).mkdir(exist_ok=True, parents=True)

    # Create a sample file
    test_file = source_dir / "test.py"
    test_file.write_text("print('Hello, world!')")

    return source_dir


@pytest.fixture
def sample_ash_model():
    """Create a mock ASH model for testing."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    # Create a real model instead of a mock
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.config.ash_config import AshConfig

    # First define AshConfig and rebuild the model
    AshConfig.model_rebuild()
    AshAggregatedResults.model_rebuild()

    # Now create the model
    model = AshAggregatedResults()
    model.metadata.scanner_name = "test_scanner"
    model.metadata.scan_id = "test_scan_id"
    model.ash_config = get_default_config()

    return model


@pytest.fixture
def test_data_dir(ash_temp_path):
    """Create a test data directory with sample files."""
    data_dir = ash_temp_path / "test_data"
    Path(data_dir).mkdir(exist_ok=True, parents=True)

    # Create a sample CloudFormation template
    cfn_dir = data_dir / "cloudformation"
    cfn_dir.mkdir()
    cfn_file = cfn_dir / "template.yaml"
    cfn_file.write_text("""
    Resources:
      MyBucket:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: my-test-bucket
    """)

    # Create a sample Terraform file
    tf_dir = data_dir / "terraform"
    tf_dir.mkdir()
    tf_file = tf_dir / "main.tf"
    tf_file.write_text("""
    resource "aws_s3_bucket" "my_bucket" {
      bucket = "my-test-bucket"
    }
    """)

    return data_dir


@pytest.fixture
def test_output_dir(ash_temp_path):
    """Create a test output directory."""
    output_dir = ash_temp_path / "output"
    Path(output_dir).mkdir(exist_ok=True, parents=True)
    return output_dir


# Add fixtures for the test plugin classes to fix validation errors
@pytest.fixture
def dummy_scanner_config():
    """Create a dummy scanner config for testing."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginConfigBase

    class DummyConfig(ScannerPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    return DummyConfig()


@pytest.fixture
def dummy_reporter_config():
    """Create a dummy reporter config for testing."""
    from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase

    class DummyConfig(ReporterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"
        extension: str = ".txt"

    return DummyConfig()


@pytest.fixture
def dummy_converter_config():
    """Create a dummy converter config for testing."""
    from automated_security_helper.base.converter_plugin import (
        ConverterPluginConfigBase,
    )

    class DummyConfig(ConverterPluginConfigBase):
        """Dummy config for testing."""

        name: str = "dummy"

    return DummyConfig()


@pytest.fixture
def dummy_scanner(test_plugin_context, dummy_scanner_config):
    """Create a dummy scanner for testing."""
    from automated_security_helper.base.scanner_plugin import ScannerPluginBase
    from automated_security_helper.schemas.sarif_schema_model import SarifReport
    from pathlib import Path

    class DummyScanner(ScannerPluginBase):
        """Dummy scanner for testing."""

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):  # type: ignore[override]
            """Abstract stub — DummyScanner overrides scan() directly."""
            raise NotImplementedError(
                f"{self.__class__.__name__} overrides scan() directly."
            )

        def scan(
            self,
            target: Path,
            target_type: Literal["source", "converted"],
            global_ignore_paths: List | None = None,
            config=None,
            *args,
            **kwargs,
        ):
            if global_ignore_paths is None:
                global_ignore_paths = []

            self.output.append("hello world")
            return SarifReport(
                version="2.1.0",
                runs=[],
            )

    # Initialize with required config
    scanner = DummyScanner(config=dummy_scanner_config, context=test_plugin_context)
    return scanner


@pytest.fixture
def dummy_reporter(test_plugin_context, dummy_reporter_config):
    """Create a dummy reporter for testing."""
    from automated_security_helper.base.reporter_plugin import ReporterPluginBase
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    class DummyReporter(ReporterPluginBase):
        """Dummy reporter for testing."""

        def validate_plugin_dependencies(self) -> bool:
            return True

        def report(self, model: AshAggregatedResults) -> str:
            return '{"report": "complete"}'

    # Initialize with required config
    reporter = DummyReporter(config=dummy_reporter_config, context=test_plugin_context)
    return reporter


@pytest.fixture
def dummy_converter(test_plugin_context, dummy_converter_config):
    """Create a dummy converter for testing."""
    from automated_security_helper.base.converter_plugin import ConverterPluginBase
    from pathlib import Path

    class DummyConverter(ConverterPluginBase):
        """Dummy converter for testing."""

        def validate_plugin_dependencies(self) -> bool:
            return True

        def convert(self) -> list[Path]:
            return [Path("test.txt")]

    # Initialize with required config
    converter = DummyConverter(
        config=dummy_converter_config, context=test_plugin_context
    )
    return converter
