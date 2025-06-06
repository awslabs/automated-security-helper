"""Resource management utilities for integration tests.

This module provides utilities for managing test resources and cleanup mechanisms
for integration tests.
"""

import os
import shutil
import tempfile
import atexit
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Callable
from contextlib import contextmanager
import time
import threading
import subprocess


class ResourceManager:
    """Class for managing test resources."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        """Create a singleton instance of ResourceManager."""
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(ResourceManager, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize the resource manager."""
        if self._initialized:
            return

        self._temp_dirs: List[Path] = []
        self._temp_files: List[Path] = []
        self._processes: List[subprocess.Popen] = []
        self._cleanup_functions: List[Callable[[], None]] = []
        self._resources: Dict[str, Any] = {}

        # Register cleanup on exit
        atexit.register(self.cleanup_all)
        self._initialized = True

    def register_temp_dir(self, path: Union[str, Path]) -> Path:
        """Register a temporary directory for cleanup.

        Args:
            path: Path to the temporary directory

        Returns:
            Path object for the registered directory
        """
        path_obj = Path(path)
        self._temp_dirs.append(path_obj)
        return path_obj

    def create_temp_dir(self) -> Path:
        """Create a temporary directory and register it for cleanup.

        Returns:
            Path object for the created directory
        """
        temp_dir = Path(tempfile.mkdtemp())
        return self.register_temp_dir(temp_dir)

    def register_temp_file(self, path: Union[str, Path]) -> Path:
        """Register a temporary file for cleanup.

        Args:
            path: Path to the temporary file

        Returns:
            Path object for the registered file
        """
        path_obj = Path(path)
        self._temp_files.append(path_obj)
        return path_obj

    def create_temp_file(
        self,
        suffix: Optional[str] = None,
        prefix: Optional[str] = None,
        dir: Optional[Union[str, Path]] = None,
        content: Optional[str] = None,
    ) -> Path:
        """Create a temporary file and register it for cleanup.

        Args:
            suffix: Optional suffix for the filename
            prefix: Optional prefix for the filename
            dir: Optional directory where the file should be created
            content: Optional content to write to the file

        Returns:
            Path object for the created file
        """
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
        os.close(fd)

        if content is not None:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

        return self.register_temp_file(path)

    def register_process(self, process: subprocess.Popen) -> subprocess.Popen:
        """Register a process for cleanup.

        Args:
            process: Process to register

        Returns:
            The registered process
        """
        self._processes.append(process)
        return process

    def start_process(self, command: List[str], **kwargs) -> subprocess.Popen:
        """Start a process and register it for cleanup.

        Args:
            command: Command to run
            **kwargs: Additional arguments to pass to subprocess.Popen

        Returns:
            The started process
        """
        process = subprocess.Popen(command, **kwargs)
        return self.register_process(process)

    def register_cleanup_function(self, func: Callable[[], None]) -> None:
        """Register a function to be called during cleanup.

        Args:
            func: Function to call during cleanup
        """
        self._cleanup_functions.append(func)

    def register_resource(self, name: str, resource: Any) -> Any:
        """Register a resource with a name.

        Args:
            name: Name of the resource
            resource: The resource to register

        Returns:
            The registered resource
        """
        self._resources[name] = resource
        return resource

    def get_resource(self, name: str) -> Any:
        """Get a registered resource by name.

        Args:
            name: Name of the resource

        Returns:
            The registered resource, or None if not found
        """
        return self._resources.get(name)

    def cleanup_temp_dirs(self) -> None:
        """Clean up all registered temporary directories."""
        for path in self._temp_dirs:
            try:
                if path.exists():
                    shutil.rmtree(path)
            except Exception:
                pass
        self._temp_dirs = []

    def cleanup_temp_files(self) -> None:
        """Clean up all registered temporary files."""
        for path in self._temp_files:
            try:
                if path.exists():
                    path.unlink()
            except Exception:
                pass
        self._temp_files = []

    def cleanup_processes(self) -> None:
        """Clean up all registered processes."""
        for process in self._processes:
            try:
                if process.poll() is None:  # Process is still running
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
            except Exception:
                pass
        self._processes = []

    def cleanup_functions(self) -> None:
        """Call all registered cleanup functions."""
        for func in self._cleanup_functions:
            try:
                func()
            except Exception:
                pass
        self._cleanup_functions = []

    def cleanup_all(self) -> None:
        """Clean up all registered resources."""
        self.cleanup_processes()
        self.cleanup_functions()
        self.cleanup_temp_files()
        self.cleanup_temp_dirs()
        self._resources = {}


# Create a singleton instance
resource_manager = ResourceManager()


@contextmanager
def temp_directory() -> Path:
    """Context manager for creating and cleaning up a temporary directory.

    Yields:
        Path object for the temporary directory

    Example:
        >>> with temp_directory() as temp_dir:
        ...     (temp_dir / "file.txt").write_text("Hello, world!")
    """
    temp_dir = resource_manager.create_temp_dir()
    try:
        yield temp_dir
    finally:
        try:
            if temp_dir.exists():
                shutil.rmtree(temp_dir)
        except Exception:
            pass


@contextmanager
def temp_file(
    suffix: Optional[str] = None,
    prefix: Optional[str] = None,
    dir: Optional[Union[str, Path]] = None,
    content: Optional[str] = None,
) -> Path:
    """Context manager for creating and cleaning up a temporary file.

    Args:
        suffix: Optional suffix for the filename
        prefix: Optional prefix for the filename
        dir: Optional directory where the file should be created
        content: Optional content to write to the file

    Yields:
        Path object for the temporary file

    Example:
        >>> with temp_file(suffix=".txt", content="Hello, world!") as temp_file_path:
        ...     print(temp_file_path.read_text())
    """
    temp_file_path = resource_manager.create_temp_file(suffix, prefix, dir, content)
    try:
        yield temp_file_path
    finally:
        try:
            if temp_file_path.exists():
                temp_file_path.unlink()
        except Exception:
            pass


@contextmanager
def managed_process(command: List[str], **kwargs) -> subprocess.Popen:
    """Context manager for starting and cleaning up a process.

    Args:
        command: Command to run
        **kwargs: Additional arguments to pass to subprocess.Popen

    Yields:
        The started process

    Example:
        >>> with managed_process(["echo", "Hello, world!"]) as process:
        ...     stdout, stderr = process.communicate()
    """
    process = resource_manager.start_process(command, **kwargs)
    try:
        yield process
    finally:
        try:
            if process.poll() is None:  # Process is still running
                process.terminate()
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    process.kill()
        except Exception:
            pass


class ServiceManager:
    """Class for managing external services for integration tests."""

    def __init__(self):
        """Initialize the service manager."""
        self.services = {}
        self.resource_manager = ResourceManager()

    def start_service(
        self,
        name: str,
        command: List[str],
        ready_check: Optional[Callable[[], bool]] = None,
        ready_timeout: int = 30,
        **kwargs,
    ) -> subprocess.Popen:
        """Start a service and wait for it to be ready.

        Args:
            name: Name of the service
            command: Command to run
            ready_check: Optional function that returns True when the service is ready
            ready_timeout: Timeout in seconds for the service to become ready
            **kwargs: Additional arguments to pass to subprocess.Popen

        Returns:
            The started process

        Raises:
            TimeoutError: If the service does not become ready within the timeout
        """
        process = self.resource_manager.start_process(command, **kwargs)
        self.services[name] = process

        if ready_check is not None:
            start_time = time.time()
            while time.time() - start_time < ready_timeout:
                if ready_check():
                    break
                time.sleep(0.1)
            else:
                raise TimeoutError(
                    f"Service {name} did not become ready within {ready_timeout} seconds"
                )

        return process

    def stop_service(self, name: str) -> None:
        """Stop a service.

        Args:
            name: Name of the service
        """
        process = self.services.get(name)
        if process is not None:
            try:
                if process.poll() is None:  # Process is still running
                    process.terminate()
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
            except Exception:
                pass
            self.services.pop(name, None)

    def stop_all_services(self) -> None:
        """Stop all services."""
        for name in list(self.services.keys()):
            self.stop_service(name)


@contextmanager
def managed_service(
    name: str,
    command: List[str],
    ready_check: Optional[Callable[[], bool]] = None,
    ready_timeout: int = 30,
    **kwargs,
) -> subprocess.Popen:
    """Context manager for starting and stopping a service.

    Args:
        name: Name of the service
        command: Command to run
        ready_check: Optional function that returns True when the service is ready
        ready_timeout: Timeout in seconds for the service to become ready
        **kwargs: Additional arguments to pass to subprocess.Popen

    Yields:
        The started process

    Example:
        >>> def is_ready():
        ...     # Check if the service is ready
        ...     return True
        >>> with managed_service("my-service", ["python", "-m", "http.server"], ready_check=is_ready) as process:
        ...     # Use the service
        ...     pass
    """
    service_manager = ServiceManager()
    process = service_manager.start_service(
        name, command, ready_check, ready_timeout, **kwargs
    )
    try:
        yield process
    finally:
        service_manager.stop_service(name)


class MockExternalService:
    """Base class for mock external services."""

    def __init__(self, name: str):
        """Initialize the mock external service.

        Args:
            name: Name of the service
        """
        self.name = name
        self.running = False
        self.process = None

    def start(self) -> None:
        """Start the mock service."""
        raise NotImplementedError("Subclasses must implement start()")

    def stop(self) -> None:
        """Stop the mock service."""
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.process.kill()
        self.running = False

    def is_ready(self) -> bool:
        """Check if the service is ready.

        Returns:
            True if the service is ready, False otherwise
        """
        return self.running

    def __enter__(self):
        """Start the service when entering a context."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop the service when exiting a context."""
        self.stop()


class ResourcePool:
    """Class for managing a pool of resources."""

    def __init__(self, factory: Callable[[], Any], max_size: int = 10):
        """Initialize the resource pool.

        Args:
            factory: Function that creates a new resource
            max_size: Maximum number of resources in the pool
        """
        self.factory = factory
        self.max_size = max_size
        self.resources = []
        self.available = set()
        self.lock = threading.Lock()

    def get(self) -> Any:
        """Get a resource from the pool.

        Returns:
            A resource from the pool
        """
        with self.lock:
            if not self.available and len(self.resources) < self.max_size:
                # Create a new resource
                resource = self.factory()
                self.resources.append(resource)
                return resource

            if not self.available:
                # Wait for a resource to become available
                raise RuntimeError("No resources available in the pool")

            # Get an available resource
            resource_id = self.available.pop()
            return self.resources[resource_id]

    def release(self, resource: Any) -> None:
        """Release a resource back to the pool.

        Args:
            resource: Resource to release
        """
        with self.lock:
            resource_id = self.resources.index(resource)
            self.available.add(resource_id)

    def close(self) -> None:
        """Close all resources in the pool."""
        with self.lock:
            for resource in self.resources:
                if hasattr(resource, "close"):
                    try:
                        resource.close()
                    except Exception:
                        pass
            self.resources = []
            self.available = set()


@contextmanager
def resource_pool(factory: Callable[[], Any], max_size: int = 10) -> ResourcePool:
    """Context manager for creating and managing a resource pool.

    Args:
        factory: Function that creates a new resource
        max_size: Maximum number of resources in the pool

    Yields:
        ResourcePool object

    Example:
        >>> def create_connection():
        ...     return sqlite3.connect(":memory:")
        >>> with resource_pool(create_connection) as pool:
        ...     conn = pool.get()
        ...     # Use the connection
        ...     pool.release(conn)
    """
    pool = ResourcePool(factory, max_size)
    try:
        yield pool
    finally:
        pool.close()


@contextmanager
def pooled_resource(pool: ResourcePool) -> Any:
    """Context manager for getting and releasing a resource from a pool.

    Args:
        pool: ResourcePool to get the resource from

    Yields:
        A resource from the pool

    Example:
        >>> def create_connection():
        ...     return sqlite3.connect(":memory:")
        >>> with resource_pool(create_connection) as pool:
        ...     with pooled_resource(pool) as conn:
        ...         # Use the connection
        ...         pass
    """
    resource = pool.get()
    try:
        yield resource
    finally:
        pool.release(resource)
