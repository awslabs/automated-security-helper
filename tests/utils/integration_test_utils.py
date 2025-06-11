"""Utilities for integration testing.

This module provides utilities for setting up integration test environments,
testing component interactions, and verifying integration points.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Callable
from contextlib import contextmanager
import json
import yaml


class IntegrationTestEnvironment:
    """Class for managing an integration test environment."""

    def __init__(self, base_dir: Optional[Union[str, Path]] = None):
        """Initialize the integration test environment.

        Args:
            base_dir: Base directory for the test environment (defaults to a temporary directory)
        """
        if base_dir is None:
            self.base_dir = Path(tempfile.mkdtemp())
            self._temp_dir = True
        else:
            self.base_dir = Path(base_dir)
            self._temp_dir = False
            self.base_dir.mkdir(parents=True, exist_ok=True)

        # Create standard directories
        self.project_dir = self.base_dir / "project"
        self.project_dir.mkdir(exist_ok=True)

        self.config_dir = self.project_dir / ".ash"
        self.config_dir.mkdir(exist_ok=True)

        self.output_dir = self.project_dir / ".ash" / "ash_output"
        self.output_dir.mkdir(exist_ok=True)

    def __del__(self):
        """Clean up the test environment when the object is destroyed."""
        if hasattr(self, "_temp_dir") and self._temp_dir and hasattr(self, "base_dir"):
            try:
                shutil.rmtree(self.base_dir, ignore_errors=True)
            except Exception:
                pass

    def create_file(
        self,
        relative_path: Union[str, Path],
        content: Union[str, bytes, Dict[str, Any]],
    ) -> Path:
        """Create a file in the test environment.

        Args:
            relative_path: Path relative to the project directory
            content: Content to write to the file

        Returns:
            Path to the created file
        """
        file_path = self.project_dir / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(content, dict):
            # Determine file type based on extension
            if str(file_path).endswith(".json"):
                with file_path.open("w", encoding="utf-8") as f:
                    json.dump(content, f, indent=2)
            elif str(file_path).endswith((".yaml", ".yml")):
                with file_path.open("w", encoding="utf-8") as f:
                    yaml.dump(content, f)
            else:
                # Default to JSON
                with file_path.open("w", encoding="utf-8") as f:
                    json.dump(content, f, indent=2)
        elif isinstance(content, bytes):
            with file_path.open("wb") as f:
                f.write(content)
        else:
            with file_path.open("w", encoding="utf-8") as f:
                f.write(str(content))

        return file_path

    def create_config_file(
        self, config_data: Dict[str, Any], format: str = "yaml"
    ) -> Path:
        """Create a configuration file in the test environment.

        Args:
            config_data: Configuration data
            format: Format of the configuration file ("yaml" or "json")

        Returns:
            Path to the created configuration file
        """
        file_name = ".ash.yaml" if format.lower() == "yaml" else ".ash.json"
        return self.create_file(f".ash/{file_name}", config_data)

    def create_source_file(self, relative_path: str, content: str) -> Path:
        """Create a source file in the test environment.

        Args:
            relative_path: Path relative to the project directory
            content: Content to write to the file

        Returns:
            Path to the created file
        """
        return self.create_file(relative_path, content)

    def create_directory(self, relative_path: Union[str, Path]) -> Path:
        """Create a directory in the test environment.

        Args:
            relative_path: Path relative to the project directory

        Returns:
            Path to the created directory
        """
        dir_path = self.project_dir / relative_path
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    def run_command(
        self, command: List[str], cwd: Optional[Union[str, Path]] = None
    ) -> subprocess.CompletedProcess:
        """Run a command in the test environment.

        Args:
            command: Command to run
            cwd: Working directory for the command (defaults to the project directory)

        Returns:
            CompletedProcess object with the command result
        """
        if cwd is None:
            cwd = self.project_dir

        return subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
        )

    def run_ash(self, args: List[str]) -> subprocess.CompletedProcess:
        """Run the ASH command in the test environment.

        Args:
            args: Arguments to pass to the ASH command

        Returns:
            CompletedProcess object with the command result
        """
        # Determine the path to the ASH executable
        ash_path = shutil.which("ash")
        if not ash_path:
            # If ash is not in PATH, try to use the local ash script
            ash_path = str(Path(__file__).parent.parent.parent / "ash")

        command = [ash_path] + args
        return self.run_command(command)

    def get_output_file(self, relative_path: Union[str, Path]) -> Path:
        """Get the path to an output file.

        Args:
            relative_path: Path relative to the output directory

        Returns:
            Path to the output file
        """
        return self.output_dir / relative_path

    def read_output_file(self, relative_path: Union[str, Path]) -> str:
        """Read the contents of an output file.

        Args:
            relative_path: Path relative to the output directory

        Returns:
            Contents of the output file
        """
        file_path = self.get_output_file(relative_path)
        return file_path.read_text(encoding="utf-8")

    def read_output_json(self, relative_path: Union[str, Path]) -> Dict[str, Any]:
        """Read the contents of an output JSON file.

        Args:
            relative_path: Path relative to the output directory

        Returns:
            Contents of the output file as a dictionary
        """
        file_path = self.get_output_file(relative_path)
        with file_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    def read_output_yaml(self, relative_path: Union[str, Path]) -> Dict[str, Any]:
        """Read the contents of an output YAML file.

        Args:
            relative_path: Path relative to the output directory

        Returns:
            Contents of the output file as a dictionary
        """
        file_path = self.get_output_file(relative_path)
        with file_path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def cleanup(self):
        """Clean up the test environment."""
        if self._temp_dir:
            shutil.rmtree(self.base_dir, ignore_errors=True)


@contextmanager
def integration_test_environment(
    base_dir: Optional[Union[str, Path]] = None,
) -> IntegrationTestEnvironment:
    """Context manager for creating and managing an integration test environment.

    Args:
        base_dir: Base directory for the test environment (defaults to a temporary directory)

    Yields:
        IntegrationTestEnvironment object

    Example:
        >>> with integration_test_environment() as env:
        ...     env.create_config_file({"scanners": {"bandit": {"enabled": True}}})
        ...     env.create_source_file("src/main.py", "print('Hello, world!')")
        ...     result = env.run_ash(["scan"])
        ...     assert result.returncode == 0
    """
    env = IntegrationTestEnvironment(base_dir)
    try:
        yield env
    finally:
        env.cleanup()


class ComponentInteractionTester:
    """Class for testing interactions between components."""

    def __init__(self, base_dir: Optional[Union[str, Path]] = None):
        """Initialize the component interaction tester.

        Args:
            base_dir: Base directory for the test environment (defaults to a temporary directory)
        """
        self.env = IntegrationTestEnvironment(base_dir)
        self.components = {}
        self.interactions = []

    def register_component(self, name: str, component_class: Any, **kwargs) -> Any:
        """Register a component for testing.

        Args:
            name: Name of the component
            component_class: Class of the component
            **kwargs: Arguments to pass to the component constructor

        Returns:
            The created component instance
        """
        component = component_class(**kwargs)
        self.components[name] = component
        return component

    def record_interaction(
        self,
        source: str,
        target: str,
        method: str,
        args: List[Any],
        kwargs: Dict[str, Any],
        result: Any,
    ) -> None:
        """Record an interaction between components.

        Args:
            source: Name of the source component
            target: Name of the target component
            method: Name of the method called
            args: Positional arguments passed to the method
            kwargs: Keyword arguments passed to the method
            result: Result of the method call
        """
        self.interactions.append(
            {
                "source": source,
                "target": target,
                "method": method,
                "args": args,
                "kwargs": kwargs,
                "result": result,
            }
        )

    def get_interactions(
        self,
        source: Optional[str] = None,
        target: Optional[str] = None,
        method: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get recorded interactions filtered by source, target, and method.

        Args:
            source: Optional source component name to filter by
            target: Optional target component name to filter by
            method: Optional method name to filter by

        Returns:
            List of matching interactions
        """
        result = self.interactions

        if source is not None:
            result = [i for i in result if i["source"] == source]

        if target is not None:
            result = [i for i in result if i["target"] == target]

        if method is not None:
            result = [i for i in result if i["method"] == method]

        return result

    def verify_interaction(
        self, source: str, target: str, method: str, expected_result: Any = None
    ) -> bool:
        """Verify that a specific interaction occurred.

        Args:
            source: Name of the source component
            target: Name of the target component
            method: Name of the method called
            expected_result: Optional expected result of the method call

        Returns:
            True if the interaction occurred with the expected result, False otherwise
        """
        interactions = self.get_interactions(source, target, method)

        if not interactions:
            return False

        if expected_result is not None:
            return any(i["result"] == expected_result for i in interactions)

        return True

    def verify_interaction_sequence(self, sequence: List[Dict[str, Any]]) -> bool:
        """Verify that a sequence of interactions occurred in order.

        Args:
            sequence: List of dictionaries describing the expected interactions

        Returns:
            True if the sequence of interactions occurred in order, False otherwise
        """
        if not sequence:
            return True

        # Find the first interaction in the sequence
        first = sequence[0]
        first_source = first.get("source")
        first_target = first.get("target")
        first_method = first.get("method")

        # Find all matching interactions
        matches = self.get_interactions(first_source, first_target, first_method)

        # If there are no matches for the first interaction, the sequence didn't occur
        if not matches:
            return False

        # For each potential starting point, check if the sequence occurs
        for i, _ in enumerate(self.interactions):
            if i + len(sequence) > len(self.interactions):
                # Not enough interactions left to match the sequence
                return False

            # Check if the sequence matches starting at index i
            match = True
            for j, expected in enumerate(sequence):
                actual = self.interactions[i + j]

                # Check if the interaction matches the expected values
                if (
                    expected.get("source") is not None
                    and actual["source"] != expected["source"]
                ):
                    match = False
                    break

                if (
                    expected.get("target") is not None
                    and actual["target"] != expected["target"]
                ):
                    match = False
                    break

                if (
                    expected.get("method") is not None
                    and actual["method"] != expected["method"]
                ):
                    match = False
                    break

                if (
                    expected.get("result") is not None
                    and actual["result"] != expected["result"]
                ):
                    match = False
                    break

            if match:
                return True

        return False

    def cleanup(self):
        """Clean up the test environment."""
        self.env.cleanup()


@contextmanager
def component_interaction_tester(
    base_dir: Optional[Union[str, Path]] = None,
) -> ComponentInteractionTester:
    """Context manager for creating and managing a component interaction tester.

    Args:
        base_dir: Base directory for the test environment (defaults to a temporary directory)

    Yields:
        ComponentInteractionTester object

    Example:
        >>> with component_interaction_tester() as tester:
        ...     scanner = tester.register_component("scanner", BanditScanner)
        ...     reporter = tester.register_component("reporter", SarifReporter)
        ...     scanner.scan()
        ...     reporter.report(scanner.results)
        ...     assert tester.verify_interaction("scanner", "reporter", "report")
    """
    tester = ComponentInteractionTester(base_dir)
    try:
        yield tester
    finally:
        tester.cleanup()


class IntegrationPoint:
    """Class for verifying integration points between components."""

    def __init__(
        self, name: str, source: str, target: str, interface: Optional[List[str]] = None
    ):
        """Initialize the integration point.

        Args:
            name: Name of the integration point
            source: Name of the source component
            target: Name of the target component
            interface: Optional list of method names that define the interface
        """
        self.name = name
        self.source = source
        self.target = target
        self.interface = interface or []
        self.verified = False
        self.verification_result = None

    def verify(self, tester: ComponentInteractionTester) -> bool:
        """Verify that the integration point is working correctly.

        Args:
            tester: ComponentInteractionTester object to use for verification

        Returns:
            True if the integration point is working correctly, False otherwise
        """
        # Check if all interface methods were called
        for method in self.interface:
            if not tester.verify_interaction(self.source, self.target, method):
                self.verified = True
                self.verification_result = False
                return False

        self.verified = True
        self.verification_result = True
        return True


class IntegrationTestVerifier:
    """Class for verifying integration tests."""

    def __init__(self):
        """Initialize the integration test verifier."""
        self.integration_points = []
        self.verification_results = {}

    def register_integration_point(
        self, name: str, source: str, target: str, interface: Optional[List[str]] = None
    ) -> IntegrationPoint:
        """Register an integration point for verification.

        Args:
            name: Name of the integration point
            source: Name of the source component
            target: Name of the target component
            interface: Optional list of method names that define the interface

        Returns:
            The created IntegrationPoint object
        """
        integration_point = IntegrationPoint(name, source, target, interface)
        self.integration_points.append(integration_point)
        return integration_point

    def verify_all(self, tester: ComponentInteractionTester) -> bool:
        """Verify all registered integration points.

        Args:
            tester: ComponentInteractionTester object to use for verification

        Returns:
            True if all integration points are working correctly, False otherwise
        """
        all_verified = True
        for integration_point in self.integration_points:
            result = integration_point.verify(tester)
            self.verification_results[integration_point.name] = result
            if not result:
                all_verified = False
        return all_verified

    def get_verification_results(self) -> Dict[str, bool]:
        """Get the verification results for all integration points.

        Returns:
            Dictionary mapping integration point names to verification results
        """
        return self.verification_results

    def get_failed_integration_points(self) -> List[IntegrationPoint]:
        """Get a list of integration points that failed verification.

        Returns:
            List of IntegrationPoint objects that failed verification
        """
        return [
            ip
            for ip in self.integration_points
            if ip.verified and not ip.verification_result
        ]


@contextmanager
def integration_test_verifier() -> IntegrationTestVerifier:
    """Context manager for creating and managing an integration test verifier.

    Yields:
        IntegrationTestVerifier object

    Example:
        >>> with integration_test_verifier() as verifier:
        ...     verifier.register_integration_point("scan-report", "scanner", "reporter", ["report"])
        ...     with component_interaction_tester() as tester:
        ...         scanner = tester.register_component("scanner", BanditScanner)
        ...         reporter = tester.register_component("reporter", SarifReporter)
        ...         scanner.scan()
        ...         reporter.report(scanner.results)
        ...         assert verifier.verify_all(tester)
    """
    verifier = IntegrationTestVerifier()
    yield verifier


class WorkflowTester:
    """Class for testing end-to-end workflows."""

    def __init__(self, base_dir: Optional[Union[str, Path]] = None):
        """Initialize the workflow tester.

        Args:
            base_dir: Base directory for the test environment (defaults to a temporary directory)
        """
        self.env = IntegrationTestEnvironment(base_dir)
        self.steps = []
        self.current_step = 0

    def add_step(
        self, name: str, action: Callable[[], Any], expected_result: Any = None
    ) -> None:
        """Add a step to the workflow.

        Args:
            name: Name of the step
            action: Function to call for this step
            expected_result: Optional expected result of the action
        """
        self.steps.append(
            {
                "name": name,
                "action": action,
                "expected_result": expected_result,
                "executed": False,
                "result": None,
                "success": None,
            }
        )

    def execute_step(self, step_index: int) -> bool:
        """Execute a specific step in the workflow.

        Args:
            step_index: Index of the step to execute

        Returns:
            True if the step executed successfully, False otherwise
        """
        if step_index < 0 or step_index >= len(self.steps):
            raise IndexError(f"Step index {step_index} out of range")

        step = self.steps[step_index]
        try:
            result = step["action"]()
            step["result"] = result
            step["executed"] = True

            if step["expected_result"] is not None:
                success = result == step["expected_result"]
            else:
                success = True

            step["success"] = success
            return success
        except Exception as e:
            step["result"] = e
            step["executed"] = True
            step["success"] = False
            return False

    def execute_next_step(self) -> bool:
        """Execute the next step in the workflow.

        Returns:
            True if the step executed successfully, False otherwise
        """
        if self.current_step >= len(self.steps):
            raise IndexError("No more steps to execute")

        success = self.execute_step(self.current_step)
        self.current_step += 1
        return success

    def execute_all(self) -> bool:
        """Execute all steps in the workflow.

        Returns:
            True if all steps executed successfully, False otherwise
        """
        all_success = True
        for i in range(len(self.steps)):
            if not self.execute_step(i):
                all_success = False
                break
        return all_success

    def get_step_results(self) -> List[Dict[str, Any]]:
        """Get the results of all executed steps.

        Returns:
            List of dictionaries with step results
        """
        return [
            {
                "name": step["name"],
                "executed": step["executed"],
                "result": step["result"],
                "success": step["success"],
            }
            for step in self.steps
        ]

    def cleanup(self):
        """Clean up the test environment."""
        self.env.cleanup()


@contextmanager
def workflow_tester(base_dir: Optional[Union[str, Path]] = None) -> WorkflowTester:
    """Context manager for creating and managing a workflow tester.

    Args:
        base_dir: Base directory for the test environment (defaults to a temporary directory)

    Yields:
        WorkflowTester object

    Example:
        >>> with workflow_tester() as tester:
        ...     tester.add_step("Configure", lambda: env.create_config_file({"scanners": {"bandit": {"enabled": True}}}))
        ...     tester.add_step("Create source", lambda: env.create_source_file("src/main.py", "print('Hello, world!')"))
        ...     tester.add_step("Run scan", lambda: env.run_ash(["scan"]), expected_result=0)
        ...     assert tester.execute_all()
    """
    tester = WorkflowTester(base_dir)
    try:
        yield tester
    finally:
        tester.cleanup()


class ComponentMockFactory:
    """Factory for creating mock components for integration testing."""

    @staticmethod
    def create_mock_scanner(name: str, results: Optional[Dict[str, Any]] = None) -> Any:
        """Create a mock scanner component.

        Args:
            name: Name of the scanner
            results: Optional results to return from the scan method

        Returns:
            Mock scanner object
        """

        class MockScanner:
            def __init__(self):
                self.name = name
                self.results = results or {}
                self.scan_called = False
                self.scan_args = None
                self.scan_kwargs = None

            def scan(self, *args, **kwargs):
                self.scan_called = True
                self.scan_args = args
                self.scan_kwargs = kwargs
                return self.results

        return MockScanner()

    @staticmethod
    def create_mock_reporter(name: str) -> Any:
        """Create a mock reporter component.

        Args:
            name: Name of the reporter

        Returns:
            Mock reporter object
        """

        class MockReporter:
            def __init__(self):
                self.name = name
                self.report_called = False
                self.report_args = None
                self.report_kwargs = None
                self.reports = []

            def report(self, *args, **kwargs):
                self.report_called = True
                self.report_args = args
                self.report_kwargs = kwargs
                self.reports.append(args[0] if args else None)
                return True

        return MockReporter()

    @staticmethod
    def create_mock_plugin(name: str, plugin_type: str) -> Any:
        """Create a mock plugin component.

        Args:
            name: Name of the plugin
            plugin_type: Type of the plugin (e.g., "scanner", "reporter")

        Returns:
            Mock plugin object
        """

        class MockPlugin:
            def __init__(self):
                self.name = name
                self.type = plugin_type
                self.initialized = False
                self.executed = False
                self.args = None
                self.kwargs = None

            def initialize(self, *args, **kwargs):
                self.initialized = True
                self.args = args
                self.kwargs = kwargs
                return True

            def execute(self, *args, **kwargs):
                self.executed = True
                self.args = args
                self.kwargs = kwargs
                return {"status": "success", "data": {}}

        return MockPlugin()
