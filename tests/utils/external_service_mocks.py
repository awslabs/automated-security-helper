"""Mock external services for integration testing.

This module provides mock implementations of external services that can be used
in integration tests to avoid dependencies on actual external services.
"""

import os
import threading
import socket
import json
import yaml
import http.server
import socketserver
from pathlib import Path
from typing import Dict, Any, Optional, Union, Callable
from contextlib import contextmanager

from tests.utils.resource_management import MockExternalService, resource_manager


class MockHTTPServer(MockExternalService):
    """Mock HTTP server for integration testing."""

    def __init__(
        self, name: str, port: int = 0, directory: Optional[Union[str, Path]] = None
    ):
        """Initialize the mock HTTP server.

        Args:
            name: Name of the service
            port: Port to listen on (0 for automatic port selection)
            directory: Directory to serve files from (defaults to a temporary directory)
        """
        super().__init__(name)
        self.port = port

        if directory is None:
            self.directory = resource_manager.create_temp_dir()
        else:
            self.directory = Path(directory)

        self.server = None
        self.server_thread = None
        self.actual_port = None

    def start(self) -> None:
        """Start the mock HTTP server."""
        if self.running:
            return

        # Create a simple HTTP server
        handler = http.server.SimpleHTTPRequestHandler

        # Change to the directory to serve
        os.chdir(self.directory)

        # Create the server
        self.server = socketserver.TCPServer(("", self.port), handler)
        self.actual_port = self.server.server_address[1]

        # Start the server in a separate thread
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        self.running = True

    def stop(self) -> None:
        """Stop the mock HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

        if self.server_thread:
            self.server_thread.join(timeout=1)

        self.running = False

    def is_ready(self) -> bool:
        """Check if the server is ready.

        Returns:
            True if the server is ready, False otherwise
        """
        if not self.running or not self.actual_port:
            return False

        try:
            with socket.create_connection(("localhost", self.actual_port), timeout=1):
                return True
        except (socket.timeout, ConnectionRefusedError):
            return False

    def add_file(
        self,
        relative_path: Union[str, Path],
        content: Union[str, bytes, Dict[str, Any]],
    ) -> Path:
        """Add a file to the server directory.

        Args:
            relative_path: Path relative to the server directory
            content: Content to write to the file

        Returns:
            Path to the created file
        """
        file_path = self.directory / relative_path
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

    def get_url(self, path: str = "") -> str:
        """Get the URL for a path on the server.

        Args:
            path: Path relative to the server root

        Returns:
            URL for the path
        """
        if not self.actual_port:
            raise RuntimeError("Server not started")

        return f"http://localhost:{self.actual_port}/{path.lstrip('/')}"


class MockAPIServer(MockExternalService):
    """Mock API server for integration testing."""

    class RequestHandler(http.server.BaseHTTPRequestHandler):
        """Request handler for the mock API server."""

        def do_GET(self):
            """Handle GET requests."""
            self.server.handle_request(self)

        def do_POST(self):
            """Handle POST requests."""
            self.server.handle_request(self)

        def do_PUT(self):
            """Handle PUT requests."""
            self.server.handle_request(self)

        def do_DELETE(self):
            """Handle DELETE requests."""
            self.server.handle_request(self)

    class APIServer(socketserver.TCPServer):
        """API server for the mock API server."""

        def __init__(self, server_address, RequestHandlerClass, routes):
            """Initialize the API server.

            Args:
                server_address: Server address (host, port)
                RequestHandlerClass: Request handler class
                routes: Dictionary mapping paths to handler functions
            """
            super().__init__(server_address, RequestHandlerClass)
            self.routes = routes

        def handle_request(self, handler):
            """Handle a request.

            Args:
                handler: Request handler
            """
            path = handler.path

            # Check if there's a query string
            if "?" in path:
                path, query = path.split("?", 1)
            else:
                query = ""

            # Find a matching route
            route_handler = None
            for route, route_handler_func in self.routes.items():
                if path == route:
                    route_handler = route_handler_func
                    break

            if route_handler:
                # Get request body if present
                content_length = int(handler.headers.get("Content-Length", 0))
                body = (
                    handler.rfile.read(content_length).decode("utf-8")
                    if content_length > 0
                    else ""
                )

                # Call the route handler
                status_code, headers, response_body = route_handler(
                    method=handler.command,
                    path=path,
                    query=query,
                    headers=handler.headers,
                    body=body,
                )

                # Send response
                handler.send_response(status_code)

                # Add headers
                for header, value in headers.items():
                    handler.send_header(header, value)
                handler.end_headers()

                # Send response body
                if response_body:
                    if isinstance(response_body, dict):
                        response_body = json.dumps(response_body)
                    handler.wfile.write(response_body.encode("utf-8"))
            else:
                # Route not found
                handler.send_response(404)
                handler.send_header("Content-Type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"error": "Not found"}).encode("utf-8"))

    def __init__(self, name: str, port: int = 0):
        """Initialize the mock API server.

        Args:
            name: Name of the service
            port: Port to listen on (0 for automatic port selection)
        """
        super().__init__(name)
        self.port = port
        self.routes = {}
        self.server = None
        self.server_thread = None
        self.actual_port = None

    def add_route(self, path: str, handler: Callable) -> None:
        """Add a route to the server.

        Args:
            path: Path to match
            handler: Function to call when the path is matched
                The function should take the following arguments:
                - method: HTTP method (GET, POST, etc.)
                - path: Path of the request
                - query: Query string
                - headers: Request headers
                - body: Request body
                And return a tuple of (status_code, headers, response_body)
        """
        self.routes[path] = handler

    def start(self) -> None:
        """Start the mock API server."""
        if self.running:
            return

        # Create the server
        self.server = self.APIServer(("", self.port), self.RequestHandler, self.routes)
        self.actual_port = self.server.server_address[1]

        # Start the server in a separate thread
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        self.running = True

    def stop(self) -> None:
        """Stop the mock API server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()

        if self.server_thread:
            self.server_thread.join(timeout=1)

        self.running = False

    def is_ready(self) -> bool:
        """Check if the server is ready.

        Returns:
            True if the server is ready, False otherwise
        """
        if not self.running or not self.actual_port:
            return False

        try:
            with socket.create_connection(("localhost", self.actual_port), timeout=1):
                return True
        except (socket.timeout, ConnectionRefusedError):
            return False

    def get_url(self, path: str = "") -> str:
        """Get the URL for a path on the server.

        Args:
            path: Path relative to the server root

        Returns:
            URL for the path
        """
        if not self.actual_port:
            raise RuntimeError("Server not started")

        return f"http://localhost:{self.actual_port}/{path.lstrip('/')}"


@contextmanager
def mock_http_server(
    name: str = "mock-http", port: int = 0, directory: Optional[Union[str, Path]] = None
) -> MockHTTPServer:
    """Context manager for creating and managing a mock HTTP server.

    Args:
        name: Name of the server
        port: Port to listen on (0 for automatic port selection)
        directory: Directory to serve files from (defaults to a temporary directory)

    Yields:
        MockHTTPServer object

    Example:
        >>> with mock_http_server() as server:
        ...     server.add_file("test.json", {"key": "value"})
        ...     url = server.get_url("test.json")
        ...     # Use the URL in tests
    """
    server = MockHTTPServer(name, port, directory)
    server.start()
    try:
        yield server
    finally:
        server.stop()


@contextmanager
def mock_api_server(name: str = "mock-api", port: int = 0) -> MockAPIServer:
    """Context manager for creating and managing a mock API server.

    Args:
        name: Name of the server
        port: Port to listen on (0 for automatic port selection)

    Yields:
        MockAPIServer object

    Example:
        >>> with mock_api_server() as server:
        ...     def handle_hello(method, path, query, headers, body):
        ...         return 200, {"Content-Type": "application/json"}, {"message": "Hello, world!"}
        ...     server.add_route("/hello", handle_hello)
        ...     url = server.get_url("hello")
        ...     # Use the URL in tests
    """
    server = MockAPIServer(name, port)
    server.start()
    try:
        yield server
    finally:
        server.stop()


class MockFileServer(MockExternalService):
    """Mock file server for integration testing."""

    def __init__(self, name: str, directory: Optional[Union[str, Path]] = None):
        """Initialize the mock file server.

        Args:
            name: Name of the service
            directory: Directory to serve files from (defaults to a temporary directory)
        """
        super().__init__(name)

        if directory is None:
            self.directory = resource_manager.create_temp_dir()
        else:
            self.directory = Path(directory)

        self.running = False

    def start(self) -> None:
        """Start the mock file server."""
        self.running = True

    def stop(self) -> None:
        """Stop the mock file server."""
        self.running = False

    def is_ready(self) -> bool:
        """Check if the server is ready.

        Returns:
            True if the server is ready, False otherwise
        """
        return self.running

    def add_file(
        self,
        relative_path: Union[str, Path],
        content: Union[str, bytes, Dict[str, Any]],
    ) -> Path:
        """Add a file to the server directory.

        Args:
            relative_path: Path relative to the server directory
            content: Content to write to the file

        Returns:
            Path to the created file
        """
        file_path = self.directory / relative_path
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

    def get_file_path(self, relative_path: Union[str, Path]) -> Path:
        """Get the path to a file on the server.

        Args:
            relative_path: Path relative to the server directory

        Returns:
            Path to the file
        """
        return self.directory / relative_path


@contextmanager
def mock_file_server(
    name: str = "mock-file", directory: Optional[Union[str, Path]] = None
) -> MockFileServer:
    """Context manager for creating and managing a mock file server.

    Args:
        name: Name of the server
        directory: Directory to serve files from (defaults to a temporary directory)

    Yields:
        MockFileServer object

    Example:
        >>> with mock_file_server() as server:
        ...     server.add_file("test.json", {"key": "value"})
        ...     path = server.get_file_path("test.json")
        ...     # Use the path in tests
    """
    server = MockFileServer(name, directory)
    server.start()
    try:
        yield server
    finally:
        server.stop()
