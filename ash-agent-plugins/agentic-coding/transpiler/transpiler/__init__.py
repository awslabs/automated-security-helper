"""Class-per-backend transpiler for AI coding agent plugin packages.

Backends register themselves at import time via @register_backend. Importing
``transpiler.backends`` triggers all 15 platform modules and populates the
BackendRegistry, which the CLI then iterates.
"""
from .core import (
    AgentsConfig,
    BaseBackend,
    BuildContext,
    BuildPhase,
    CommandsConfig,
    ConfigFile,
    CustomModes,
    ExtensionManifest,
    InstructionFile,
    MCPBBundle,
    MCPConfig,
    Manifest,
    Marketplace,
    PluginManifest,
    RulesDir,
    SkillConfig,
)
from .registry import BackendRegistry, register_backend

__all__ = [
    "AgentsConfig",
    "BackendRegistry",
    "BaseBackend",
    "BuildContext",
    "BuildPhase",
    "CommandsConfig",
    "ConfigFile",
    "CustomModes",
    "ExtensionManifest",
    "InstructionFile",
    "MCPBBundle",
    "MCPConfig",
    "Manifest",
    "Marketplace",
    "PluginManifest",
    "RulesDir",
    "SkillConfig",
    "register_backend",
]
