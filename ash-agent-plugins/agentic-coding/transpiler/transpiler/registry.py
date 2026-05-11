"""Backend registration + discovery.

@register_backend on a class adds it to BackendRegistry. Importing
transpiler.backends triggers all 15 platform modules, populating the registry.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core import BaseBackend


class BackendRegistry:
    _backends: dict[str, type["BaseBackend"]] = {}

    @classmethod
    def register(cls, backend_cls: type["BaseBackend"]) -> type["BaseBackend"]:
        if not backend_cls.NAME:
            raise ValueError(
                f"{backend_cls.__name__}.NAME is empty; backends must declare a NAME class var"
            )
        if backend_cls.NAME in cls._backends:
            raise ValueError(
                f"backend '{backend_cls.NAME}' already registered "
                f"({cls._backends[backend_cls.NAME].__name__} vs {backend_cls.__name__})"
            )
        cls._backends[backend_cls.NAME] = backend_cls
        return backend_cls

    @classmethod
    def all(cls) -> dict[str, type["BaseBackend"]]:
        return dict(cls._backends)

    @classmethod
    def get(cls, name: str) -> type["BaseBackend"]:
        if name not in cls._backends:
            available = ", ".join(sorted(cls._backends))
            raise KeyError(f"unknown backend '{name}'. Available: {available}")
        return cls._backends[name]

    @classmethod
    def names(cls) -> list[str]:
        return sorted(cls._backends)


def register_backend(cls: type["BaseBackend"]) -> type["BaseBackend"]:
    """Class decorator that registers a backend with BackendRegistry."""
    return BackendRegistry.register(cls)
