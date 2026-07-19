"""
title: Blacksite Workspace Writer
author: Blacksite
description: Safely write text data and export read-only SQLite queries into the mounted Blacksite output workspace.
required_open_webui_version: 0.10.0
version: 1.0.0
license: MIT
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sqlite3
import tempfile
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        input_root: str = Field(default=os.getenv("BLACKSITE_INPUT_DIR", "/workspace/input"))
        output_root: str = Field(default=os.getenv("BLACKSITE_OUTPUT_DIR", "/workspace/output"))
        max_write_bytes: int = Field(default=5_000_000, ge=1_024, le=100_000_000)
        max_query_rows: int = Field(default=10_000, ge=1, le=100_000)
        query_timeout_seconds: int = Field(default=15, ge=1, le=120)
        allowed_extensions: str = Field(
            default=".txt,.md,.json,.jsonl,.csv,.tsv,.xml,.html,.yaml,.yml,.log,.sql",
            description="Comma-separated output extensions permitted for writes.",
        )

    def __init__(self):
        self.valves = self.Valves()

    @staticmethod
    def _contained(root: Path, path: Path) -> bool:
        return path == root or root in path.parents

    def _safe_input_file(self, relative_path: str) -> Path:
        root = Path(self.valves.input_root).expanduser().resolve()
        path = (root / relative_path).resolve()
        if not self._contained(root, path):
            raise ValueError("Input path escapes the configured input workspace")
        if not path.is_file():
            raise FileNotFoundError(f"Input file not found: {relative_path}")
        return path

    def _safe_output_file(self, relative_path: str) -> Path:
        if not relative_path or relative_path.endswith(("/", "\\")):
            raise ValueError("An output filename is required")
        root = Path(self.valves.output_root).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        path = (root / relative_path).resolve()
        if not self._contained(root, path) or path == root:
            raise ValueError("Output path escapes the configured output workspace")
        allowed = {item.strip().lower() for item in self.valves.allowed_extensions.split(",") if item.strip()}
        if path.suffix.lower() not in allowed:
            raise ValueError(f"Output extension {path.suffix or '(none)'} is not allowed")
        parent = path.parent
        parent.mkdir(parents=True, exist_ok=True)
        if not self._contained(root, parent.resolve()):
            raise ValueError("Output directory escapes the configured output workspace")
        return path

    @staticmethod
    def _validate_query(query: str) -> str:
        query = query.strip()
        if not query:
            raise ValueError("Query must not be empty")
        without_literals = re.sub(r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"", "''", query)
        without_comments = re.sub(r"--[^\n]*|/\*.*?\*/", " ", without_literals, flags=re.DOTALL)
        if ";" in without_comments.rstrip(";"):
            raise ValueError("Only one SQL statement is permitted")
        tokens = set(re.findall(r"\b[A-Z_]+\b", without_comments.upper()))
        forbidden = {
            "ALTER", "ANALYZE", "ATTACH", "CALL", "COPY", "CREATE", "DELETE", "DETACH",
            "DROP", "EXEC", "EXECUTE", "GRANT", "INSERT", "INTO", "LOAD", "MERGE",
            "PRAGMA", "REINDEX", "REPLACE", "REVOKE", "TRUNCATE", "UPDATE", "VACUUM",
        }
        found = sorted(tokens & forbidden)
        if found:
            raise ValueError(f"Write or administrative SQL is not permitted: {', '.join(found)}")
        first = re.match(r"^\s*([A-Za-z]+)", without_comments)
        if not first or first.group(1).upper() not in {"SELECT", "WITH", "EXPLAIN"}:
            raise ValueError("Only SELECT, WITH, and EXPLAIN queries are permitted")
        return query.rstrip(";")

    def _atomic_write(self, path: Path, content: str, overwrite: bool) -> int:
        encoded = content.encode("utf-8")
        if len(encoded) > self.valves.max_write_bytes:
            raise ValueError(f"Output exceeds {self.valves.max_write_bytes} bytes")
        if path.exists() and not overwrite:
            raise FileExistsError(f"Output already exists: {path.name}; set overwrite=true to replace it")
        temporary_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".blacksite-write-", dir=path.parent, delete=False
            ) as handle:
                temporary_name = handle.name
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
            return len(encoded)
        finally:
            if temporary_name and os.path.exists(temporary_name):
                os.unlink(temporary_name)

    @staticmethod
    def _json_value(value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, bytes):
            return {"type": "bytes", "length": len(value), "hex_preview": value[:32].hex()}
        return str(value)

    @staticmethod
    def _spreadsheet_value(value: Any) -> Any:
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
            return "'" + value
        return value

    async def write_output_text(self, relative_path: str, content: str, overwrite: bool = False) -> str:
        """Atomically write UTF-8 text into the output workspace.

        :param relative_path: Destination relative to /workspace/output, including an allowed extension.
        :param content: UTF-8 text to write.
        :param overwrite: Replace an existing file when true; defaults to false.
        :return: JSON destination, size, and overwrite status.
        """
        path = self._safe_output_file(relative_path)
        existed = path.exists()
        size = self._atomic_write(path, content, overwrite)
        return json.dumps(
            {"path": f"/workspace/output/{path.relative_to(Path(self.valves.output_root).resolve()).as_posix()}", "size_bytes": size, "replaced": existed},
            indent=2,
        )

    async def write_output_json(
        self, relative_path: str, json_content: str, overwrite: bool = False, pretty: bool = True
    ) -> str:
        """Validate and atomically write JSON into the output workspace.

        :param relative_path: Destination relative to /workspace/output and ending in .json.
        :param json_content: Valid JSON string to write.
        :param overwrite: Replace an existing file when true; defaults to false.
        :param pretty: Indent and normalize JSON when true.
        :return: JSON destination, size, and overwrite status.
        """
        if Path(relative_path).suffix.lower() != ".json":
            raise ValueError("write_output_json requires a .json destination")
        value = json.loads(json_content)
        content = json.dumps(value, indent=2 if pretty else None, ensure_ascii=False) + "\n"
        return await self.write_output_text(relative_path, content, overwrite)

    async def export_sqlite_query(
        self,
        database_relative_path: str,
        query: str,
        output_relative_path: str,
        output_format: str = "csv",
        parameters_json: str = "{}",
        max_rows: int = 5_000,
        overwrite: bool = False,
    ) -> str:
        """Run a read-only SQLite query and atomically export its result to CSV, TSV, JSON, or JSONL.

        :param database_relative_path: SQLite file relative to /workspace/input.
        :param query: One SELECT, WITH, or EXPLAIN query using named parameters such as :port.
        :param output_relative_path: Destination relative to /workspace/output.
        :param output_format: csv, tsv, json, or jsonl.
        :param parameters_json: JSON object containing named SQL parameter values.
        :param max_rows: Maximum exported rows, capped by the administrator valve.
        :param overwrite: Replace an existing output file when true.
        :return: JSON destination, columns, exported row count, truncation, and size.
        """
        database = self._safe_input_file(database_relative_path)
        output = self._safe_output_file(output_relative_path)
        selected_format = output_format.lower().strip()
        expected_extensions = {"csv": ".csv", "tsv": ".tsv", "json": ".json", "jsonl": ".jsonl"}
        if selected_format not in expected_extensions:
            raise ValueError("output_format must be csv, tsv, json, or jsonl")
        if output.suffix.lower() != expected_extensions[selected_format]:
            raise ValueError(f"{selected_format} output requires a {expected_extensions[selected_format]} filename")
        safe_query = self._validate_query(query)
        parameters = json.loads(parameters_json or "{}")
        if not isinstance(parameters, dict):
            raise ValueError("parameters_json must be a JSON object")
        limit = max(1, min(max_rows, self.valves.max_query_rows))
        connection = sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
        connection.execute("PRAGMA query_only = ON")
        deadline = time.monotonic() + self.valves.query_timeout_seconds
        connection.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1000)
        try:
            cursor = connection.execute(safe_query, parameters)
            columns = [item[0] for item in cursor.description or []]
            fetched = cursor.fetchmany(limit + 1)
        finally:
            connection.close()
        rows = [[self._json_value(value) for value in row] for row in fetched[:limit]]
        if selected_format in {"csv", "tsv"}:
            buffer = io.StringIO(newline="")
            writer = csv.writer(
                buffer, delimiter="," if selected_format == "csv" else "\t", lineterminator="\n"
            )
            writer.writerow(columns)
            writer.writerows([[self._spreadsheet_value(value) for value in row] for row in rows])
            content = buffer.getvalue()
        else:
            objects = [dict(zip(columns, row)) for row in rows]
            if selected_format == "json":
                content = json.dumps(objects, indent=2, ensure_ascii=False) + "\n"
            else:
                content = "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in objects)
        existed = output.exists()
        size = self._atomic_write(output, content, overwrite)
        output_root = Path(self.valves.output_root).expanduser().resolve()
        return json.dumps(
            {
                "path": f"/workspace/output/{output.relative_to(output_root).as_posix()}",
                "columns": columns,
                "row_count": len(rows),
                "truncated": len(fetched) > limit,
                "size_bytes": size,
                "replaced": existed,
            },
            indent=2,
        )
