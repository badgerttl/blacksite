# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Jay Morris
"""
title: Blacksite Read-Only Database
author: Blacksite
description: Inspect and query local SQLite databases and configured SQL databases using enforced read-only sessions.
required_open_webui_version: 0.10.0
version: 1.0.0
license: GPL-3.0-only
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        input_root: str = Field(default=os.getenv("BLACKSITE_INPUT_DIR", "/workspace/input"))
        database_url: str = Field(
            default=os.getenv("BLACKSITE_DATABASE_URL", ""),
            description="Optional SQLAlchemy database URL configured by an administrator.",
            json_schema_extra={"format": "password"},
        )
        maximum_rows: int = Field(default=250, ge=1, le=5000)
        query_timeout_seconds: int = Field(default=15, ge=1, le=120)

    def __init__(self):
        self.valves = self.Valves()

    def _safe_db_path(self, relative_path: str) -> Path:
        root = Path(self.valves.input_root).expanduser().resolve()
        path = (root / relative_path).resolve()
        if path != root and root not in path.parents:
            raise ValueError("Database path escapes the configured input workspace")
        if not path.is_file():
            raise FileNotFoundError(f"Database not found: {relative_path}")
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
        if not first or first.group(1).upper() not in {"SELECT", "WITH", "EXPLAIN", "SHOW", "DESCRIBE"}:
            raise ValueError("Only SELECT, WITH, EXPLAIN, SHOW, and DESCRIBE queries are permitted")
        return query.rstrip(";")

    @staticmethod
    def _json_value(value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, bytes):
            return {"type": "bytes", "length": len(value), "hex_preview": value[:32].hex()}
        return str(value)

    async def list_sqlite_databases(self, max_results: int = 100) -> str:
        """Find likely SQLite database files in the mounted input workspace.

        :param max_results: Maximum files returned, up to 500.
        :return: JSON list of relative paths and sizes.
        """
        root = Path(self.valves.input_root).expanduser().resolve()
        limit = max(1, min(max_results, 500))
        found = []
        for path in root.rglob("*"):
            resolved = path.resolve()
            if root not in resolved.parents or not resolved.is_file():
                continue
            if path.suffix.lower() not in {".db", ".sqlite", ".sqlite3"}:
                try:
                    with resolved.open("rb") as handle:
                        if handle.read(16) != b"SQLite format 3\x00":
                            continue
                except OSError:
                    continue
            found.append({"path": path.relative_to(root).as_posix(), "size_bytes": resolved.stat().st_size})
            if len(found) >= limit:
                break
        return json.dumps({"count": len(found), "databases": found}, indent=2)

    def _sqlite_connect(self, relative_path: str) -> sqlite3.Connection:
        path = self._safe_db_path(relative_path)
        connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
        connection.execute("PRAGMA query_only = ON")
        deadline = time.monotonic() + self.valves.query_timeout_seconds
        connection.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1000)
        return connection

    async def inspect_sqlite_database(self, relative_path: str) -> str:
        """List tables, views, columns, and indexes in a local SQLite database.

        :param relative_path: Database file relative to the input workspace.
        :return: JSON schema metadata.
        """
        connection = self._sqlite_connect(relative_path)
        try:
            objects = []
            rows = connection.execute(
                "SELECT name, type FROM sqlite_master "
                "WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
            ).fetchall()
            for name, object_type in rows:
                escaped = name.replace('"', '""')
                columns = [
                    {"name": row[1], "type": row[2], "nullable": not bool(row[3]), "primary_key": bool(row[5])}
                    for row in connection.execute(f'PRAGMA table_info("{escaped}")').fetchall()
                ]
                objects.append({"name": name, "type": object_type, "columns": columns})
            return json.dumps({"database": relative_path, "objects": objects}, indent=2)
        finally:
            connection.close()

    async def query_sqlite_database(
        self, relative_path: str, query: str, parameters_json: str = "{}", max_rows: int = 100
    ) -> str:
        """Execute one parameterised read-only query against a local SQLite file.

        :param relative_path: Database file relative to the input workspace.
        :param query: SELECT, WITH, or EXPLAIN query using named parameters such as :host.
        :param parameters_json: JSON object containing named query parameter values.
        :param max_rows: Maximum rows returned, capped by the administrator valve.
        :return: JSON columns, rows, count, and truncation status.
        """
        safe_query = self._validate_query(query)
        parameters = json.loads(parameters_json or "{}")
        if not isinstance(parameters, dict):
            raise ValueError("parameters_json must be a JSON object")
        limit = max(1, min(max_rows, self.valves.maximum_rows))
        connection = self._sqlite_connect(relative_path)
        try:
            cursor = connection.execute(safe_query, parameters)
            columns = [item[0] for item in cursor.description or []]
            fetched = cursor.fetchmany(limit + 1)
            rows = [[self._json_value(value) for value in row] for row in fetched[:limit]]
            return json.dumps(
                {"columns": columns, "rows": rows, "row_count": len(rows), "truncated": len(fetched) > limit},
                indent=2,
            )
        finally:
            connection.close()

    async def query_configured_database(
        self, query: str, parameters_json: str = "{}", max_rows: int = 100
    ) -> str:
        """Query the administrator-configured PostgreSQL, MySQL, MariaDB, or SQLite URL read-only.

        This requires SQLAlchemy and the appropriate database driver in the Open WebUI image.

        :param query: One read-only SELECT, WITH, EXPLAIN, SHOW, or DESCRIBE statement.
        :param parameters_json: JSON object containing named query parameter values.
        :param max_rows: Maximum rows returned, capped by the administrator valve.
        :return: JSON columns, rows, database dialect, count, and truncation status.
        """
        if not self.valves.database_url:
            raise ValueError("No administrator database_url valve is configured")
        safe_query = self._validate_query(query)
        parameters = json.loads(parameters_json or "{}")
        if not isinstance(parameters, dict):
            raise ValueError("parameters_json must be a JSON object")
        try:
            from sqlalchemy import create_engine, text
            from sqlalchemy.pool import NullPool
        except ImportError as error:
            raise RuntimeError("SQLAlchemy is required for configured remote databases") from error
        engine = create_engine(self.valves.database_url, pool_pre_ping=True, poolclass=NullPool)
        dialect = engine.dialect.name
        if dialect not in {"postgresql", "mysql", "mariadb", "sqlite"}:
            engine.dispose()
            raise ValueError(f"Unsupported database dialect: {dialect}")
        limit = max(1, min(max_rows, self.valves.maximum_rows))
        try:
            with engine.connect() as connection:
                if dialect in {"mysql", "mariadb"}:
                    connection.execute(text("SET SESSION TRANSACTION READ ONLY"))
                    connection.commit()
                transaction = connection.begin()
                try:
                    if dialect == "postgresql":
                        connection.execute(text("SET TRANSACTION READ ONLY"))
                        connection.execute(text(f"SET LOCAL statement_timeout = {self.valves.query_timeout_seconds * 1000}"))
                    elif dialect == "sqlite":
                        connection.execute(text("PRAGMA query_only = ON"))
                    result = connection.execute(text(safe_query), parameters)
                    columns = list(result.keys())
                    fetched = result.fetchmany(limit + 1)
                    rows = [[self._json_value(value) for value in row] for row in fetched[:limit]]
                finally:
                    transaction.rollback()
            return json.dumps(
                {"dialect": dialect, "columns": columns, "rows": rows, "row_count": len(rows), "truncated": len(fetched) > limit},
                indent=2,
            )
        finally:
            engine.dispose()
