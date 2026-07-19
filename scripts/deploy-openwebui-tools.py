#!/usr/bin/env python3
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
        "Detect and normalise 20 common security-tool output formats.",
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
