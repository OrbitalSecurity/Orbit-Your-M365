"""Builders for schema-2 baselines in tests. Test-only: production code never imports this.

Everything goes through the real validator: a ``Baseline`` is only ever obtained from
``parse_baseline``, so tests cannot hand authorisation code an unvalidated object either.
"""
from __future__ import annotations

import json
from pathlib import Path

from orbit.core import baseline_schema as schema


def binding() -> schema.Binding:
    return schema.current_binding()


def document(tools: dict | None = None, *, bound: schema.Binding | None = None,
             generator: str = "test") -> dict:
    """A schema-2 document. ``tools`` is {tool: {version: {relative path: sha256}}}."""
    entries = {tool: {"versions": {version: {"files": files} for version, files in versions.items()}}
               for tool, versions in (tools or {}).items()}
    return {"schema": schema.SCHEMA, "kind": schema.KIND, "binding": (bound or binding()).to_json(),
            "generator": {"orbit": generator}, "tools": entries}


def encode(doc: dict) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def baseline(tools: dict | None = None, **kw) -> schema.Baseline:
    """A validated Baseline for the current user, built through ``parse_baseline``."""
    return schema.parse_baseline(encode(document(tools, **kw)), binding())


def write(path: Path, tools: dict | None = None, **kw) -> Path:
    """Write a valid schema-2 baseline for the current user at path."""
    path.write_bytes(encode(document(tools, **kw)))
    path.chmod(0o600)
    return path


# What a 1.5.0 / interim-candidate manifest looked like: no binding, schema 1 or none at all.
def legacy_document(files: dict | None = None, *, schema_value: object = 1) -> dict:
    doc: dict = {"tools": {"maester": {"versions": {"1.2.3": {
        "install_dir": "/somewhere/Maester", "files": files or {"Maester.psd1": "ab" * 32}}}}}}
    if schema_value is not None:
        doc["schema"] = schema_value
    return doc
