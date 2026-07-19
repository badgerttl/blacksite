"""
title: Blacksite Workspace Files
author: Blacksite
description: Safely list, inspect, read, and search files in the mounted Blacksite input workspace.
required_open_webui_version: 0.10.0
version: 1.0.0
license: MIT
"""

from __future__ import annotations

import fnmatch
import json
import mimetypes
import os
import re
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field


class Tools:
    class Valves(BaseModel):
        input_root: str = Field(
            default=os.getenv("BLACKSITE_INPUT_DIR", "/workspace/input"),
            description="Absolute directory this tool is permitted to read.",
        )
        max_read_bytes: int = Field(
            default=2_000_000,
            ge=1_024,
            le=25_000_000,
            description="Maximum bytes read from one file.",
        )
        max_output_chars: int = Field(
            default=30_000,
            ge=1_000,
            le=200_000,
            description="Maximum characters returned by a tool call.",
        )

    def __init__(self):
        self.valves = self.Valves()

    def _root(self) -> Path:
        root = Path(self.valves.input_root).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"Input workspace does not exist: {root}")
        return root

    def _safe_path(self, relative_path: str, *, require_file: bool = False) -> Path:
        root = self._root()
        candidate = (root / relative_path).resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError("Path escapes the configured input workspace")
        if not candidate.exists():
            raise FileNotFoundError(f"Path not found: {relative_path}")
        if require_file and not candidate.is_file():
            raise ValueError(f"Not a regular file: {relative_path}")
        return candidate

    @staticmethod
    def _looks_binary(data: bytes) -> bool:
        if b"\x00" in data:
            return True
        sample = data[:4096]
        if not sample:
            return False
        controls = sum(byte < 9 or (13 < byte < 32) for byte in sample)
        return controls / len(sample) > 0.15

    async def list_workspace_files(
        self,
        relative_directory: str = "",
        glob_pattern: str = "*",
        recursive: bool = True,
        max_results: int = 200,
    ) -> str:
        """List files in the input workspace with sizes and relative paths.

        :param relative_directory: Directory relative to the input workspace.
        :param glob_pattern: Filename glob such as *.json, *.xml, or nmap*.
        :param recursive: Search subdirectories when true.
        :param max_results: Maximum number of files to return, up to 1000.
        :return: JSON containing matching workspace files.
        """
        directory = self._safe_path(relative_directory)
        if not directory.is_dir():
            raise ValueError("relative_directory must identify a directory")
        limit = max(1, min(max_results, 1000))
        iterator = directory.rglob("*") if recursive else directory.glob("*")
        root = self._root()
        files = []
        for path in iterator:
            resolved = path.resolve()
            if root not in resolved.parents or not resolved.is_file() or not fnmatch.fnmatch(path.name, glob_pattern):
                continue
            stat = resolved.stat()
            files.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size_bytes": stat.st_size,
                    "modified_epoch": int(stat.st_mtime),
                }
            )
            if len(files) >= limit:
                break
        return json.dumps({"count": len(files), "files": files}, indent=2)

    async def inspect_workspace_file(self, relative_path: str) -> str:
        """Return safe metadata and a short hexadecimal signature for one file.

        :param relative_path: File path relative to the input workspace.
        :return: JSON metadata without returning the full file contents.
        """
        path = self._safe_path(relative_path, require_file=True)
        with path.open("rb") as handle:
            sample = handle.read(512)
        stat = path.stat()
        result = {
            "path": path.relative_to(self._root()).as_posix(),
            "size_bytes": stat.st_size,
            "mime_type": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
            "is_probably_binary": self._looks_binary(sample),
            "first_32_bytes_hex": sample[:32].hex(),
        }
        return json.dumps(result, indent=2)

    async def read_workspace_file(
        self,
        relative_path: str,
        start_line: int = 1,
        end_line: Optional[int] = 250,
    ) -> str:
        """Read a bounded line range from a text file in the input workspace.

        :param relative_path: File path relative to the input workspace.
        :param start_line: First one-based line to return.
        :param end_line: Last one-based line to return; defaults to 250.
        :return: Numbered text lines plus truncation information.
        """
        path = self._safe_path(relative_path, require_file=True)
        start = max(1, start_line)
        end = max(start, end_line or start + 249)
        with path.open("rb") as handle:
            data = handle.read(self.valves.max_read_bytes + 1)
        byte_truncated = len(data) > self.valves.max_read_bytes
        data = data[: self.valves.max_read_bytes]
        if self._looks_binary(data):
            raise ValueError("File appears binary; use inspect_workspace_file instead")
        text = data.decode("utf-8", errors="replace")
        selected = text.splitlines()[start - 1 : end]
        body = "\n".join(f"{number}: {line}" for number, line in enumerate(selected, start))
        char_truncated = len(body) > self.valves.max_output_chars
        body = body[: self.valves.max_output_chars]
        return json.dumps(
            {
                "path": relative_path,
                "start_line": start,
                "end_line_returned": start + max(0, len(selected) - 1),
                "truncated": byte_truncated or char_truncated,
                "content": body,
            },
            indent=2,
        )

    async def search_workspace_files(
        self,
        search_text: str,
        relative_directory: str = "",
        glob_pattern: str = "*",
        regex: bool = False,
        case_sensitive: bool = False,
        max_matches: int = 100,
    ) -> str:
        """Search bounded text files and return matching lines.

        :param search_text: Literal text or regular expression to find.
        :param relative_directory: Directory relative to the input workspace.
        :param glob_pattern: Filename glob limiting searched files.
        :param regex: Interpret search_text as a Python regular expression.
        :param case_sensitive: Perform a case-sensitive search when true.
        :param max_matches: Maximum matching lines to return, up to 500.
        :return: JSON with file paths, line numbers, and matching excerpts.
        """
        if not search_text:
            raise ValueError("search_text must not be empty")
        directory = self._safe_path(relative_directory)
        if not directory.is_dir():
            raise ValueError("relative_directory must identify a directory")
        flags = 0 if case_sensitive else re.IGNORECASE
        pattern = re.compile(search_text if regex else re.escape(search_text), flags)
        limit = max(1, min(max_matches, 500))
        root = self._root()
        matches = []
        skipped = []
        for path in directory.rglob("*"):
            resolved = path.resolve()
            if root not in resolved.parents or not resolved.is_file() or not fnmatch.fnmatch(path.name, glob_pattern):
                continue
            if resolved.stat().st_size > self.valves.max_read_bytes:
                skipped.append(path.relative_to(root).as_posix())
                continue
            data = resolved.read_bytes()
            if self._looks_binary(data):
                continue
            for line_number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if pattern.search(line):
                    matches.append(
                        {
                            "path": path.relative_to(root).as_posix(),
                            "line": line_number,
                            "text": line[:500],
                        }
                    )
                    if len(matches) >= limit:
                        return json.dumps(
                            {"count": len(matches), "truncated": True, "matches": matches}, indent=2
                        )
        return json.dumps(
            {"count": len(matches), "truncated": False, "skipped_large_files": skipped[:20], "matches": matches},
            indent=2,
        )
