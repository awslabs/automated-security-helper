"""Auxiliary tools for the agentic-coding transpiler.

Currently contains:
  refresh_schemas — orchestrator that refreshes vendored external schemas
                    declared in transpiler/schemas/schemas.json
  zod_to_json_schema.mjs — Node script invoked by refresh_schemas for
                           zod-converted schema entries
"""
