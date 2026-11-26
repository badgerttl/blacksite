#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 Jay Morris
"""Idempotently create or update Blacksite tools through the Open WebUI API."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


TOOL_DEFINITIONS = (
    (
        "blacksite_security_output_parser",
        "Blacksite Security Output Parser",
        "security_output_parser.py",
        "Normalise common security-tool outputs, all documented Tenable export families, and arbitrary CSV files.",
    ),
    (
        "blacksite_workspace_files",
        "Blacksite Workspace Files",
        "workspace_files.py",
        "Safely list, inspect, read, and search the mounted input workspace.",
    ),
    (
        "blacksite_readonly_database",
        "Blacksite Read-Only Database",
        "readonly_database.py",
        "Inspect and query local or configured SQL databases read-only.",
    ),
    (
        "blacksite_workspace_writer",
        "Blacksite Workspace Writer",
        "workspace_writer.py",
        "Safely write output files and export read-only SQLite query results.",
    ),
)


class APIError(RuntimeError):
    pass


class OpenWebUIClient:
    def __init__(self, base_url: str, token: str = ""):
        self.base_url = base_url.rstrip("/")
        self.token = token

    def request(
        self, method: str, path: str, payload: dict[str, Any] | None = None, *, authenticate: bool = True
    ) -> tuple[int, Any]:
        headers = {"Accept": "application/json"}
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticate and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read()
                if not body:
                    parsed = None
                else:
                    try:
                        parsed = json.loads(body)
                    except json.JSONDecodeError:
                        parsed = body.decode("utf-8", errors="replace")
                return response.status, parsed
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            try:
                detail = json.loads(body).get("detail", body)
            except json.JSONDecodeError:
                detail = body
            return error.code, detail
        except urllib.error.URLError as error:
            raise APIError(f"Open WebUI request failed: {error.reason}") from error

    def wait_until_ready(self, attempts: int = 90) -> None:
        last_error = "not ready"
        for _ in range(attempts):
            try:
                status, _ = self.request("GET", "/health", authenticate=False)
                if status == 200:
                    return
                last_error = f"HTTP {status}"
            except APIError as error:
                last_error = str(error)
            time.sleep(2)
        raise APIError(f"Open WebUI did not become ready: {last_error}")

    def sign_in(self, email: str, password: str) -> None:
        status, response = self.request(
            "POST", "/api/v1/auths/signin", {"email": email, "password": password}, authenticate=False
        )
        if status != 200 or not isinstance(response, dict) or not response.get("token"):
            raise APIError(
                f"Open WebUI sign-in failed (HTTP {status}). Set matching admin credentials "
                "or OPEN_WEBUI_TOOLS_TOKEN. API response: {response}"
            )
        self.token = response["token"]

    def deploy_tool(self, tool_id: str, name: str, content: str, description: str) -> str:
        status, existing = self.request("GET", f"/api/v1/tools/id/{tool_id}")
        payload = {
            "id": tool_id,
            "name": name,
            "content": content,
            "meta": {"description": description, "manifest": {}},
            "access_grants": [],
        }
        if status == 404:
            create_status, response = self.request("POST", "/api/v1/tools/create", payload)
            if create_status != 200:
                raise APIError(f"Failed to create {tool_id} (HTTP {create_status}): {response}")
            return "created"
        if status != 200 or not isinstance(existing, dict):
            raise APIError(f"Failed to inspect {tool_id} (HTTP {status}): {existing}")
        payload["access_grants"] = existing.get("access_grants") or []
        if (
            existing.get("name") == name
            and existing.get("content") == content
            and (existing.get("meta") or {}).get("description") == description
        ):
            return "unchanged"
        update_status, response = self.request("POST", f"/api/v1/tools/id/{tool_id}/update", payload)
        if update_status != 200:
            raise APIError(f"Failed to update {tool_id} (HTTP {update_status}): {response}")
        return "updated"

    def reconcile_hardening(self) -> list[str]:
        """Persist security defaults that Open WebUI stores in its database."""
        changes = []
        public_url = os.getenv("OPEN_WEBUI_PUBLIC_URL", "http://localhost:9000")
        jwt_expiry = os.getenv("OPEN_WEBUI_JWT_EXPIRES_IN", "24h")
        allowed_endpoints = os.getenv(
            "OPEN_WEBUI_API_KEYS_ALLOWED_ENDPOINTS",
            "/api/chat/completions,/api/v1/models,/api/models,/api/v1/tools,/api/v1/tasks,/api/v1/retrieval,/api/v1/auths/admin/config,/api/v1/configs/connections",
        )

        status, admin_config = self.request("GET", "/api/v1/auths/admin/config")
        if status != 200 or not isinstance(admin_config, dict):
            raise APIError(f"Failed to read admin configuration (HTTP {status}): {admin_config}")
        admin_desired = {
            "WEBUI_URL": public_url,
            "ENABLE_SIGNUP": False,
            "ENABLE_API_KEYS": True,
            "ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS": True,
            "API_KEYS_ALLOWED_ENDPOINTS": allowed_endpoints,
            "DEFAULT_USER_ROLE": "pending",
            "JWT_EXPIRES_IN": jwt_expiry,
            "ENABLE_COMMUNITY_SHARING": False,
        }
        if any(admin_config.get(key) != value for key, value in admin_desired.items()):
            admin_config.update(admin_desired)
            update_status, response = self.request("POST", "/api/v1/auths/admin/config", admin_config)
            if update_status != 200:
                raise APIError(f"Failed to harden admin configuration (HTTP {update_status}): {response}")
            changes.append("admin/access configuration")

        status, task_config = self.request("GET", "/api/v1/tasks/config")
        if status != 200 or not isinstance(task_config, dict):
            raise APIError(f"Failed to read task configuration (HTTP {status}): {task_config}")
        if task_config.get("ENABLE_FOLLOW_UP_GENERATION") is not False:
            task_config["ENABLE_FOLLOW_UP_GENERATION"] = False
            update_status, response = self.request("POST", "/api/v1/tasks/config/update", task_config)
            if update_status != 200:
                raise APIError(f"Failed to disable follow-up generation (HTTP {update_status}): {response}")
            changes.append("follow-up generation disabled")

        rag_desired = {
            "FILE_MAX_SIZE": int(os.getenv("OPEN_WEBUI_RAG_FILE_MAX_SIZE", "50")),
            "FILE_MAX_COUNT": int(os.getenv("OPEN_WEBUI_RAG_FILE_MAX_COUNT", "10")),
            "ALLOWED_FILE_EXTENSIONS": [
                item.strip()
                for item in os.getenv(
                    "OPEN_WEBUI_RAG_ALLOWED_FILE_EXTENSIONS",
                    ".pdf,.txt,.md,.docx,.csv,.tsv,.json,.jsonl,.xml,.html,.nessus,.db,.zip,.yaml,.yml,.log",
                ).split(",")
                if item.strip()
            ],
        }
        status, rag_config = self.request("GET", "/api/v1/retrieval/config")
        if status != 200 or not isinstance(rag_config, dict):
            raise APIError(f"Failed to read retrieval configuration (HTTP {status}): {rag_config}")
        if any(rag_config.get(key) != value for key, value in rag_desired.items()):
            update_status, response = self.request("POST", "/api/v1/retrieval/config/update", rag_desired)
            if update_status != 200:
                raise APIError(f"Failed to set upload limits (HTTP {update_status}): {response}")
            changes.append("file upload limits")

        status, connections_config = self.request("GET", "/api/v1/configs/connections")
        if status != 200 or not isinstance(connections_config, dict):
            raise APIError(f"Failed to read connections configuration (HTTP {status}): {connections_config}")
        if connections_config.get("ENABLE_DIRECT_CONNECTIONS") is not False:
            connections_config["ENABLE_DIRECT_CONNECTIONS"] = False
            update_status, response = self.request("POST", "/api/v1/configs/connections", connections_config)
            if update_status != 200:
                raise APIError(f"Failed to disable direct connections (HTTP {update_status}): {response}")
            changes.append("direct model connections disabled")
        return changes


def deploy() -> int:
    base_url = os.getenv("OPEN_WEBUI_URL", "http://open-webui:8080")
    tools_directory = Path(os.getenv("OPEN_WEBUI_TOOLS_DIR", "/tools")).resolve()
    token = os.getenv("OPEN_WEBUI_TOOLS_TOKEN", "").strip()
    email = os.getenv("OPEN_WEBUI_ADMIN_EMAIL", "").strip()
    password = os.getenv("OPEN_WEBUI_ADMIN_PASSWORD", "")

    client = OpenWebUIClient(base_url, token)
    client.wait_until_ready()
    if not token:
        if not email or not password:
            raise APIError(
                "Set OPEN_WEBUI_ADMIN_EMAIL and OPEN_WEBUI_ADMIN_PASSWORD, or OPEN_WEBUI_TOOLS_TOKEN"
            )
        client.sign_in(email, password)

    changes = client.reconcile_hardening()
    if changes:
        for change in changes:
            print(f"hardened  {change}", flush=True)
    else:
        print("unchanged hardened Open WebUI configuration", flush=True)

    for tool_id, name, filename, description in TOOL_DEFINITIONS:
        path = (tools_directory / filename).resolve()
        if tools_directory not in path.parents or not path.is_file():
            raise APIError(f"Tool source not found or outside tools directory: {filename}")
        action = client.deploy_tool(tool_id, name, path.read_text(encoding="utf-8"), description)
        print(f"{action:9} {tool_id}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(deploy())
    except (APIError, OSError, UnicodeError) as error:
        print(f"tool deployment failed: {error}", file=sys.stderr)
        raise SystemExit(1)
