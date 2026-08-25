# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Workspace mode: resolve a multi-project workspace into an execution plan.

Why this package exists
-----------------------
A workspace is N project directories scanned as N independently-scoped
executions and aggregated with per-project attribution. Deciding *which*
projects those are, and refusing a definition ASH cannot honour, is a separate
concern from running the scans -- separate enough that it can be inspected on
its own with ``--dry-run`` before anything is executed. This package is only
the deciding half.

What this package deliberately does NOT do
------------------------------------------
* It does not scan. Nothing here starts a scanner, writes an output directory,
  or reads a source file. Execution is a later phase.
* It does not read policy out of the ``.code-workspace`` file's ``settings``
  block. ASH policy lives in ASH's own config; taking it from another tool's
  schema would mean two sources of truth for the same decision, with VS Code
  free to change its own without warning.
* It does not isolate scanner tool versions per project. One ASH run installs
  one version of each tool, so a workspace whose projects demand incompatible
  versions is refused rather than run with one project's requirement quietly
  ignored.

Module map
----------
* :mod:`~automated_security_helper.workspace.workspace_file` -- parse and
  discover the ``.code-workspace`` definition.
* :mod:`~automated_security_helper.workspace.scanner_pins` -- decide whether
  two version pins for the same scanner can both be satisfied.
* :mod:`~automated_security_helper.workspace.plan` -- the execution plan
  produced by resolution, and its rendering.
* :mod:`~automated_security_helper.workspace.resolver` -- validate every entry
  and build the plan.

Exit codes and failure modes are the ones modelled in
:mod:`automated_security_helper.models.workspace`; this package raises
``WorkspaceDefinitionError`` for code 2 and lets ``ASHConfigValidationError``
through for code 3, and never returns a partially-valid plan.

There are deliberately no re-exports here. Callers import from the submodule they
need, which keeps ``workspace_file`` importable without dragging in config
resolution and pydantic models along with it.
"""
