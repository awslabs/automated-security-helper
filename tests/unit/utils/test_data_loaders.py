"""Test data loaders for loading and managing test data.

This module provides utilities for loading test data from files and
managing the test data lifecycle.
"""

import json
import yaml
import csv
import shutil
from pathlib import Path
from typing import Dict, Any, List, Union, Optional, TypeVar, Generic, Type, Callable
import importlib.resources as pkg_resources

# Type variable for generic loader
T = TypeVar("T")


class TestDataLoader:
    """Base class for loading test data from files."""

    @staticmethod
    def load_json(file_path: Union[str, Path]) -> Dict[str, Any]:
        """Load JSON data from a file.

        Args:
            file_path: Path to the JSON file

        Returns:
            Dictionary containing the loaded JSON data

        Raises:
            FileNotFoundError: If the file does not exist
            json.JSONDecodeError: If the file contains invalid JSON
        """
        file_path = Path(file_path)
        with file_path.open("r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def load_yaml(file_path: Union[str, Path]) -> Dict[str, Any]:
        """Load YAML data from a file.

        Args:
            file_path: Path to the YAML file

        Returns:
            Dictionary containing the loaded YAML data

        Raises:
            FileNotFoundError: If the file does not exist
            yaml.YAMLError: If the file contains invalid YAML
        """
        file_path = Path(file_path)
        with file_path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    @staticmethod
    def load_csv(
        file_path: Union[str, Path], as_dict: bool = True
    ) -> Union[List[Dict[str, str]], List[List[str]]]:
        """Load CSV data from a file.

        Args:
            file_path: Path to the CSV file
            as_dict: Whether to return the data as a list of dictionaries (True) or a list of lists (False)

        Returns:
            List of dictionaries or list of lists containing the loaded CSV data

        Raises:
            FileNotFoundError: If the file does not exist
        """
        file_path = Path(file_path)
        with file_path.open("r", encoding="utf-8", newline="") as f:
            if as_dict:
                reader = csv.DictReader(f)
                return list(reader)
            else:
                reader = csv.reader(f)
                return list(reader)

    @staticmethod
    def load_text(file_path: Union[str, Path]) -> str:
        """Load text data from a file.

        Args:
            file_path: Path to the text file

        Returns:
            String containing the loaded text data

        Raises:
            FileNotFoundError: If the file does not exist
        """
        file_path = Path(file_path)
        return file_path.read_text(encoding="utf-8")

    @staticmethod
    def load_binary(file_path: Union[str, Path]) -> bytes:
        """Load binary data from a file.

        Args:
            file_path: Path to the binary file

        Returns:
            Bytes containing the loaded binary data

        Raises:
            FileNotFoundError: If the file does not exist
        """
        file_path = Path(file_path)
        return file_path.read_bytes()


class SharedTestData:
    """Manager for shared test data across tests."""

    _instance = None
    _data_cache: Dict[str, Any] = {}

    def __new__(cls):
        """Create a singleton instance of SharedTestData."""
        if cls._instance is None:
            cls._instance = super(SharedTestData, cls).__new__(cls)
            cls._instance._data_cache = {}
        return cls._instance

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from the shared test data.

        Args:
            key: Key to retrieve
            default: Default value to return if the key does not exist

        Returns:
            The value associated with the key, or the default value if the key does not exist
        """
        return self._data_cache.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set a value in the shared test data.

        Args:
            key: Key to set
            value: Value to associate with the key
        """
        self._data_cache[key] = value

    def delete(self, key: str) -> None:
        """Delete a value from the shared test data.

        Args:
            key: Key to delete
        """
        if key in self._data_cache:
            del self._data_cache[key]

    def clear(self) -> None:
        """Clear all shared test data."""
        self._data_cache.clear()

    def has_key(self, key: str) -> bool:
        """Check if a key exists in the shared test data.

        Args:
            key: Key to check

        Returns:
            True if the key exists, False otherwise
        """
        return key in self._data_cache


class TestDataManager:
    """Manager for test data lifecycle."""

    def __init__(self, base_dir: Optional[Union[str, Path]] = None):
        """Initialize the test data manager.

        Args:
            base_dir: Base directory for test data (defaults to a temporary directory)
        """
        if base_dir is None:
            import tempfile

            self.base_dir = Path(tempfile.mkdtemp())
            self._temp_dir = True
        else:
            self.base_dir = Path(base_dir)
            self._temp_dir = False
            self.base_dir.mkdir(parents=True, exist_ok=True)

    def __del__(self):
        """Clean up temporary directories when the manager is destroyed."""
        if hasattr(self, "_temp_dir") and self._temp_dir and hasattr(self, "base_dir"):
            try:
                shutil.rmtree(self.base_dir, ignore_errors=True)
            except Exception:
                pass

    def get_path(self, relative_path: Union[str, Path]) -> Path:
        """Get the absolute path for a relative path within the base directory.

        Args:
            relative_path: Relative path within the base directory

        Returns:
            Absolute path
        """
        return self.base_dir / relative_path

    def create_file(
        self,
        relative_path: Union[str, Path],
        content: Union[str, bytes, Dict[str, Any]],
    ) -> Path:
        """Create a file with the specified content.

        Args:
            relative_path: Relative path within the base directory
            content: Content to write to the file (string, bytes, or dictionary for JSON/YAML)

        Returns:
            Path to the created file
        """
        file_path = self.get_path(relative_path)
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

    def create_directory(self, relative_path: Union[str, Path]) -> Path:
        """Create a directory.

        Args:
            relative_path: Relative path within the base directory

        Returns:
            Path to the created directory
        """
        dir_path = self.get_path(relative_path)
        dir_path.mkdir(parents=True, exist_ok=True)
        return dir_path

    def copy_file(
        self, source_path: Union[str, Path], relative_dest_path: Union[str, Path]
    ) -> Path:
        """Copy a file to the test data directory.

        Args:
            source_path: Path to the source file
            relative_dest_path: Relative destination path within the base directory

        Returns:
            Path to the copied file
        """
        source_path = Path(source_path)
        dest_path = self.get_path(relative_dest_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, dest_path)
        return dest_path

    def remove(self, relative_path: Union[str, Path]) -> None:
        """Remove a file or directory.

        Args:
            relative_path: Relative path within the base directory
        """
        path = self.get_path(relative_path)
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        elif path.exists():
            path.unlink()


class PackageResourceLoader:
    """Loader for accessing resources from Python packages."""

    @staticmethod
    def load_text(package: str, resource: str) -> str:
        """Load text data from a package resource.

        Args:
            package: Package name
            resource: Resource name within the package

        Returns:
            String containing the loaded text data

        Raises:
            FileNotFoundError: If the resource does not exist
        """
        return pkg_resources.read_text(package, resource)

    @staticmethod
    def load_binary(package: str, resource: str) -> bytes:
        """Load binary data from a package resource.

        Args:
            package: Package name
            resource: Resource name within the package

        Returns:
            Bytes containing the loaded binary data

        Raises:
            FileNotFoundError: If the resource does not exist
        """
        return pkg_resources.read_binary(package, resource)

    @staticmethod
    def is_resource(package: str, resource: str) -> bool:
        """Check if a resource exists in a package.

        Args:
            package: Package name
            resource: Resource name within the package

        Returns:
            True if the resource exists, False otherwise
        """
        return pkg_resources.is_resource(package, resource)

    @staticmethod
    def get_resource_path(package: str, resource: str) -> Path:
        """Get the path to a package resource.

        Args:
            package: Package name
            resource: Resource name within the package

        Returns:
            Path to the resource

        Raises:
            FileNotFoundError: If the resource does not exist
        """
        with pkg_resources.path(package, resource) as path:
            return path


class TestDataRegistry:
    """Registry for managing and accessing test data sets."""

    _instance = None
    _registry: Dict[str, Dict[str, Any]] = {}

    def __new__(cls):
        """Create a singleton instance of TestDataRegistry."""
        if cls._instance is None:
            cls._instance = super(TestDataRegistry, cls).__new__(cls)
            cls._instance._registry = {}
        return cls._instance

    def register_data_set(self, name: str, data: Dict[str, Any]) -> None:
        """Register a data set.

        Args:
            name: Name of the data set
            data: Data set to register
        """
        self._registry[name] = data

    def get_data_set(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a registered data set.

        Args:
            name: Name of the data set

        Returns:
            The registered data set, or None if it does not exist
        """
        return self._registry.get(name)

    def unregister_data_set(self, name: str) -> None:
        """Unregister a data set.

        Args:
            name: Name of the data set
        """
        if name in self._registry:
            del self._registry[name]

    def list_data_sets(self) -> List[str]:
        """List all registered data sets.

        Returns:
            List of registered data set names
        """
        return list(self._registry.keys())

    def clear(self) -> None:
        """Clear all registered data sets."""
        self._registry.clear()


class TypedDataLoader(Generic[T]):
    """Generic loader for loading and converting data to specific types."""

    def __init__(
        self, cls: Type[T], converter: Optional[Callable[[Dict[str, Any]], T]] = None
    ):
        """Initialize the typed data loader.

        Args:
            cls: Class to convert data to
            converter: Optional function to convert dictionary data to the specified class
        """
        self.cls = cls
        self.converter = converter or (lambda data: cls(**data))

    def load_from_file(self, file_path: Union[str, Path]) -> T:
        """Load data from a file and convert it to the specified type.

        Args:
            file_path: Path to the file

        Returns:
            Instance of the specified class

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the file format is not supported
        """
        file_path = Path(file_path)
        if file_path.suffix.lower() in (".json",):
            data = TestDataLoader.load_json(file_path)
        elif file_path.suffix.lower() in (".yaml", ".yml"):
            data = TestDataLoader.load_yaml(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_path.suffix}")

        return self.converter(data)

    def load_from_dict(self, data: Dict[str, Any]) -> T:
        """Load data from a dictionary and convert it to the specified type.

        Args:
            data: Dictionary containing the data

        Returns:
            Instance of the specified class
        """
        return self.converter(data)

    def load_many_from_file(self, file_path: Union[str, Path]) -> List[T]:
        """Load multiple items from a file and convert them to the specified type.

        Args:
            file_path: Path to the file

        Returns:
            List of instances of the specified class

        Raises:
            FileNotFoundError: If the file does not exist
            ValueError: If the file format is not supported or the file does not contain a list
        """
        file_path = Path(file_path)
        if file_path.suffix.lower() in (".json",):
            data = TestDataLoader.load_json(file_path)
        elif file_path.suffix.lower() in (".yaml", ".yml"):
            data = TestDataLoader.load_yaml(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_path.suffix}")

        if not isinstance(data, list):
            raise ValueError("File does not contain a list of items")

        return [self.converter(item) for item in data]
