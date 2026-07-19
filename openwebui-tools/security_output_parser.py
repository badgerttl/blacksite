"""
title: Blacksite Security Output Parser
author: Blacksite
description: Detect and normalise 20 common security-tool output formats from the mounted Blacksite workspace.
required_open_webui_version: 0.10.0
version: 1.0.0
license: MIT
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable
from xml.etree import ElementTree as ET

from pydantic import BaseModel, Field


SUPPORTED_FORMATS = [
    "nmap_xml", "masscan_xml", "nessus_xml", "openvas_xml", "burp_xml",
    "zap_json", "nikto_xml", "nuclei_jsonl", "ffuf_json", "gobuster_text",
    "dirsearch_json", "sqlmap_csv", "metasploit_xml", "bloodhound_json_zip",
    "trivy_json", "grype_json", "semgrep_json", "checkov_json", "gitleaks_json", "sarif_json",
]


class Tools:
    class Valves(BaseModel):
        input_root: str = Field(default=os.getenv("BLACKSITE_INPUT_DIR", "/workspace/input"))
        output_root: str = Field(default=os.getenv("BLACKSITE_OUTPUT_DIR", "/workspace/output"))
        max_input_bytes: int = Field(default=100_000_000, ge=1_000_000, le=500_000_000)
        max_findings: int = Field(default=5_000, ge=1, le=50_000)
        preview_findings: int = Field(default=20, ge=1, le=100)

    def __init__(self):
        self.valves = self.Valves()

    def _safe_input(self, relative_path: str) -> Path:
        root = Path(self.valves.input_root).expanduser().resolve()
        path = (root / relative_path).resolve()
        if path != root and root not in path.parents:
            raise ValueError("Path escapes the configured input workspace")
        if not path.is_file():
            raise FileNotFoundError(f"Input file not found: {relative_path}")
        if path.stat().st_size > self.valves.max_input_bytes:
            raise ValueError(f"Input exceeds {self.valves.max_input_bytes} bytes")
        return path

    def _safe_output(self, filename: str) -> Path:
        root = Path(self.valves.output_root).expanduser().resolve()
        root.mkdir(parents=True, exist_ok=True)
        path = (root / filename).resolve()
        if root not in path.parents:
            raise ValueError("Output path escapes the configured output workspace")
        return path

    @staticmethod
    def _text(value: Any, limit: int = 4000) -> str:
        if value is None:
            return ""
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        return str(value).strip()[:limit]

    @staticmethod
    def _severity(value: Any) -> str:
        value = str(value or "info").strip().lower()
        aliases = {"informational": "info", "moderate": "medium", "warning": "medium", "error": "high"}
        value = aliases.get(value, value)
        if value.isdigit():
            return {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}.get(value, "info")
        return value if value in {"info", "low", "medium", "high", "critical"} else "info"

    def _finding(self, tool: str, **values: Any) -> dict[str, Any]:
        finding = {
            "tool": tool,
            "category": self._text(values.get("category")),
            "title": self._text(values.get("title") or "Untitled finding", 1000),
            "severity": self._severity(values.get("severity")),
            "host": self._text(values.get("host"), 1000),
            "port": self._text(values.get("port"), 50),
            "protocol": self._text(values.get("protocol"), 50),
            "location": self._text(values.get("location"), 2000),
            "description": self._text(values.get("description")),
            "evidence": self._text(values.get("evidence")),
            "identifiers": values.get("identifiers") or [],
            "remediation": self._text(values.get("remediation")),
        }
        return finding

    @staticmethod
    def _json(path: Path) -> Any:
        return json.loads(path.read_text(encoding="utf-8-sig", errors="replace"))

    @staticmethod
    def _xml(path: Path) -> ET.Element:
        raw = path.read_bytes()
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise ValueError("XML document types and entities are not permitted")
        return ET.fromstring(raw)

    def _parse_nmap(self, path: Path) -> list[dict[str, Any]]:
        root, out = self._xml(path), []
        for host in root.findall(".//host"):
            address_node = host.find("address")
            address = address_node.get("addr", "") if address_node is not None else ""
            hostname_node = host.find("hostnames/hostname")
            hostname = hostname_node.get("name", "") if hostname_node is not None else address
            for port in host.findall("ports/port"):
                state = port.find("state")
                if state is not None and state.get("state") != "open":
                    continue
                service = port.find("service")
                scripts = "; ".join(f"{s.get('id')}: {s.get('output', '')}" for s in port.findall("script"))
                title = (service.get("name") if service is not None else "open port") or "open port"
                product = " ".join(filter(None, [(service.get("product") if service is not None else ""), (service.get("version") if service is not None else "")]))
                out.append(self._finding("Nmap", category="network-service", title=title, severity="info", host=hostname, port=port.get("portid"), protocol=port.get("protocol"), description=product, evidence=scripts))
        return out

    def _parse_masscan(self, path: Path) -> list[dict[str, Any]]:
        root, out = self._xml(path), []
        for host in root.findall(".//host"):
            address_node = host.find("address")
            address = address_node.get("addr", "") if address_node is not None else ""
            for port in host.findall(".//port"):
                state = port.find("state")
                service = port.find("service")
                out.append(self._finding("Masscan", category="network-service", title=(service.get("name") if service is not None else "open port"), severity="info", host=address, port=port.get("portid"), protocol=port.get("protocol"), evidence=(state.get("state") if state is not None else "open")))
        return out

    def _parse_nessus(self, path: Path) -> list[dict[str, Any]]:
        root, out = self._xml(path), []
        for report_host in root.findall(".//ReportHost"):
            host = report_host.get("name", "")
            for item in report_host.findall("ReportItem"):
                ids = [x for x in [item.findtext("cve"), item.findtext("cwe"), item.findtext("plugin_id")] if x]
                out.append(self._finding("Nessus", category=item.get("pluginFamily"), title=item.get("pluginName"), severity=item.get("severity"), host=host, port=item.get("port"), protocol=item.get("protocol"), description=item.findtext("synopsis") or item.findtext("description"), evidence=item.findtext("plugin_output"), identifiers=ids, remediation=item.findtext("solution")))
        return out

    def _parse_openvas(self, path: Path) -> list[dict[str, Any]]:
        root, out = self._xml(path), []
        for result in root.findall(".//result"):
            threat = result.findtext("threat") or "info"
            nvt = result.find("nvt")
            out.append(self._finding("OpenVAS", category=(nvt.findtext("family") if nvt is not None else "vulnerability"), title=result.findtext("name") or (nvt.findtext("name") if nvt is not None else "OpenVAS result"), severity=threat, host=result.findtext("host"), port=result.findtext("port"), description=result.findtext("description"), identifiers=[nvt.get("oid")] if nvt is not None and nvt.get("oid") else []))
        return out

    def _parse_burp(self, path: Path) -> list[dict[str, Any]]:
        root, out = self._xml(path), []
        for issue in root.findall(".//issue"):
            host_node = issue.find("host")
            out.append(self._finding("Burp Suite", category=issue.findtext("type"), title=issue.findtext("name"), severity=issue.findtext("severity"), host=(host_node.text if host_node is not None else ""), location=issue.findtext("path"), description=issue.findtext("issueDetail") or issue.findtext("issueBackground"), evidence=issue.findtext("requestresponse/response"), remediation=issue.findtext("remediationDetail") or issue.findtext("remediationBackground")))
        return out

    def _parse_zap(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        for site in data.get("site", data.get("sites", [])):
            host = site.get("@host") or site.get("host") or site.get("@name")
            for alert in site.get("alerts", []):
                instances = alert.get("instances") or [{}]
                for instance in instances:
                    out.append(self._finding("OWASP ZAP", category=alert.get("pluginid"), title=alert.get("alert") or alert.get("name"), severity=alert.get("riskdesc", "").split()[0], host=host, location=instance.get("uri"), description=alert.get("desc"), evidence=instance.get("evidence"), identifiers=[x for x in [alert.get("cweid"), alert.get("wascid")] if x], remediation=alert.get("solution")))
        return out

    def _parse_nikto(self, path: Path) -> list[dict[str, Any]]:
        root, out = self._xml(path), []
        for scan in root.findall(".//scandetails"):
            for item in scan.findall("item"):
                out.append(self._finding("Nikto", category=item.get("id"), title=item.findtext("description") or "Nikto finding", severity="medium", host=scan.get("targethostname") or scan.get("targetip"), port=scan.get("targetport"), location=item.findtext("uri"), description=item.findtext("description"), evidence=item.findtext("namelink")))
        return out

    def _parse_nuclei(self, path: Path) -> list[dict[str, Any]]:
        out = []
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            if not line.strip(): continue
            item = json.loads(line)
            info = item.get("info", {})
            classification = info.get("classification", {})
            ids = classification.get("cve-id", []) + classification.get("cwe-id", [])
            out.append(self._finding("Nuclei", category=info.get("tags"), title=info.get("name") or item.get("template-id"), severity=info.get("severity"), host=item.get("host"), location=item.get("matched-at"), description=info.get("description"), evidence=item.get("matcher-name") or item.get("extracted-results"), identifiers=ids, remediation=info.get("remediation")))
        return out

    def _parse_ffuf(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        for item in data.get("results", []):
            out.append(self._finding("ffuf", category="content-discovery", title=f"HTTP {item.get('status')} response", severity="info", host=item.get("host"), location=item.get("url"), evidence={"status": item.get("status"), "length": item.get("length"), "words": item.get("words"), "lines": item.get("lines"), "input": item.get("input")}))
        return out

    def _parse_gobuster(self, path: Path) -> list[dict[str, Any]]:
        out = []
        pattern = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", re.I)
        for line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
            match = pattern.search(line.strip())
            if match:
                out.append(self._finding("Gobuster", category="content-discovery", title=f"HTTP {match.group(2)} response", severity="info", location=match.group(1), evidence={"status": match.group(2), "size": match.group(3)}))
        return out

    def _parse_dirsearch(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        if isinstance(data, dict) and "results" in data: data = data["results"]
        if isinstance(data, dict):
            data = [dict(item, base_url=base) for base, items in data.items() for item in (items if isinstance(items, list) else [])]
        for item in data if isinstance(data, list) else []:
            location = item.get("url") or f"{item.get('base_url', '')}{item.get('path', '')}"
            out.append(self._finding("dirsearch", category="content-discovery", title=f"HTTP {item.get('status')} response", severity="info", location=location, evidence={"status": item.get("status"), "content-length": item.get("content-length") or item.get("content_length")}))
        return out

    def _parse_sqlmap(self, path: Path) -> list[dict[str, Any]]:
        out = []
        with path.open(encoding="utf-8-sig", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle):
                lookup = {k.lower().strip(): v for k, v in row.items() if k}
                out.append(self._finding("sqlmap", category="sql-injection", title=lookup.get("title") or lookup.get("type") or "SQL injection", severity="high", host=lookup.get("target") or lookup.get("hostname"), location=lookup.get("url") or lookup.get("place"), description=lookup.get("payload") or lookup.get("details"), evidence={k: v for k, v in lookup.items() if k in {"parameter", "payload", "technique", "dbms"}}))
        return out

    def _parse_metasploit(self, path: Path) -> list[dict[str, Any]]:
        root, out = self._xml(path), []
        for host in root.findall(".//host"):
            address = host.findtext("address") or host.findtext("name")
            for service in host.findall(".//service"):
                out.append(self._finding("Metasploit", category="service", title=service.findtext("name") or "discovered service", severity="info", host=address, port=service.findtext("port"), protocol=service.findtext("proto"), description=service.findtext("info")))
            for vuln in host.findall(".//vuln"):
                out.append(self._finding("Metasploit", category="vulnerability", title=vuln.findtext("name") or "Metasploit vulnerability", severity="high", host=address, description=vuln.findtext("info"), identifiers=[ref.text for ref in vuln.findall(".//ref") if ref.text]))
        return out

    def _bloodhound_objects(self, data: Any, source: str) -> list[dict[str, Any]]:
        out = []
        objects = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(objects, list): return out
        for item in objects:
            props = item.get("Properties", item.get("properties", {})) if isinstance(item, dict) else {}
            name = props.get("name") or props.get("displayname") or item.get("Name") or "BloodHound object"
            out.append(self._finding("BloodHound", category=source, title=name, severity="info", host=props.get("domain"), description={k: v for k, v in props.items() if k.lower() in {"enabled", "admincount", "highvalue", "hasspn", "unconstraineddelegation", "description"}}))
        return out

    def _parse_bloodhound(self, path: Path) -> list[dict[str, Any]]:
        if path.suffix.lower() != ".zip": return self._bloodhound_objects(self._json(path), path.stem)
        out, total = [], 0
        with zipfile.ZipFile(path) as archive:
            members = [m for m in archive.infolist() if not m.is_dir() and m.filename.lower().endswith(".json")]
            if len(members) > 1000: raise ValueError("BloodHound ZIP contains too many members")
            for member in members:
                total += member.file_size
                if total > self.valves.max_input_bytes or member.file_size > self.valves.max_input_bytes:
                    raise ValueError("BloodHound ZIP expands beyond the configured size limit")
                with archive.open(member) as handle:
                    data = json.load(io.TextIOWrapper(handle, encoding="utf-8-sig", errors="replace"))
                out.extend(self._bloodhound_objects(data, Path(member.filename).stem))
        return out

    def _parse_trivy(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        for result in data.get("Results", []):
            target = result.get("Target")
            for item in result.get("Vulnerabilities") or []:
                out.append(self._finding("Trivy", category=result.get("Class") or result.get("Type"), title=item.get("Title") or item.get("VulnerabilityID"), severity=item.get("Severity"), location=target, description=item.get("Description"), evidence={"package": item.get("PkgName"), "installed": item.get("InstalledVersion"), "fixed": item.get("FixedVersion")}, identifiers=[item.get("VulnerabilityID")], remediation=f"Upgrade to {item.get('FixedVersion')}" if item.get("FixedVersion") else ""))
            for item in result.get("Misconfigurations") or []:
                out.append(self._finding("Trivy", category="misconfiguration", title=item.get("Title") or item.get("ID"), severity=item.get("Severity"), location=target, description=item.get("Description"), evidence=item.get("Message"), identifiers=[item.get("ID")], remediation=item.get("Resolution")))
        return out

    def _parse_grype(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        for match in data.get("matches", []):
            vuln, artifact = match.get("vulnerability", {}), match.get("artifact", {})
            out.append(self._finding("Grype", category=artifact.get("type"), title=vuln.get("description") or vuln.get("id"), severity=vuln.get("severity"), location=artifact.get("locations"), evidence={"package": artifact.get("name"), "version": artifact.get("version"), "fix": vuln.get("fix")}, identifiers=[vuln.get("id")]))
        return out

    def _parse_semgrep(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        for item in data.get("results", []):
            extra = item.get("extra", {}); metadata = extra.get("metadata", {})
            out.append(self._finding("Semgrep", category=item.get("check_id"), title=extra.get("message") or item.get("check_id"), severity=extra.get("severity"), location=f"{item.get('path')}:{item.get('start', {}).get('line', '')}", evidence=extra.get("lines"), identifiers=metadata.get("cwe", []) or metadata.get("owasp", []), remediation=metadata.get("fix")))
        return out

    def _parse_checkov(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        reports = data if isinstance(data, list) else [data]
        for report in reports:
            checks = report.get("results", {}).get("failed_checks", [])
            for item in checks:
                out.append(self._finding("Checkov", category=item.get("check_id"), title=item.get("check_name"), severity=item.get("severity") or "medium", location=f"{item.get('file_path')}:{item.get('file_line_range')}", description=item.get("guideline"), evidence=item.get("resource"), identifiers=[item.get("check_id")]))
        return out

    def _parse_gitleaks(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        if isinstance(data, dict): data = data.get("findings", data.get("leaks", []))
        for item in data:
            fingerprint = hashlib.sha256(str(item.get("Secret", "")).encode()).hexdigest()[:12] if item.get("Secret") else ""
            out.append(self._finding("Gitleaks", category=item.get("RuleID"), title=item.get("Description") or item.get("RuleID") or "Potential secret", severity="high", location=f"{item.get('File')}:{item.get('StartLine', '')}", evidence={"match": "[REDACTED]", "secret_sha256_prefix": fingerprint, "commit": item.get("Commit"), "author": item.get("Author")}, identifiers=[item.get("RuleID")]))
        return out

    def _parse_sarif(self, path: Path) -> list[dict[str, Any]]:
        data, out = self._json(path), []
        for run in data.get("runs", []):
            rules = {rule.get("id"): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", [])}
            driver = run.get("tool", {}).get("driver", {}).get("name", "SARIF")
            for item in run.get("results", []):
                rule = rules.get(item.get("ruleId"), {})
                location = ((item.get("locations") or [{}])[0].get("physicalLocation") or {})
                artifact = (location.get("artifactLocation") or {}).get("uri", "")
                line = (location.get("region") or {}).get("startLine", "")
                message = (item.get("message") or {}).get("text")
                out.append(self._finding(driver, category=item.get("ruleId"), title=message or (rule.get("shortDescription") or {}).get("text") or item.get("ruleId"), severity=item.get("level"), location=f"{artifact}:{line}", description=(rule.get("fullDescription") or {}).get("text"), identifiers=[item.get("ruleId")]))
        return out

    def _detect(self, path: Path) -> str:
        name = path.name.lower()
        sample = path.read_bytes()[:200_000].lstrip()
        text = sample.decode("utf-8", errors="ignore")
        if path.suffix.lower() == ".zip": return "bloodhound_json_zip"
        if sample.startswith(b"<"):
            lower = text.lower()
            if "<nmaprun" in lower: return "masscan_xml" if "masscan" in lower else "nmap_xml"
            if "<nessusclientdata" in lower: return "nessus_xml"
            if "<issues" in lower and "burp" in lower: return "burp_xml"
            if "<niktoscan" in lower: return "nikto_xml"
            if "<metasploit" in lower or "<hosts>" in lower: return "metasploit_xml"
            if "<report" in lower or "<get_reports" in lower: return "openvas_xml"
        if name.endswith(".csv"):
            return "sqlmap_csv"
        if name.endswith((".jsonl", ".ndjson")) or (text.startswith("{") and "template-id" in text.splitlines()[0]):
            return "nuclei_jsonl"
        try: data = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return "gobuster_text" if "(Status:" in text else "unknown"
        if isinstance(data, dict):
            if data.get("version") == "2.1.0" and "runs" in data: return "sarif_json"
            if "site" in data or "sites" in data: return "zap_json"
            if "Results" in data and ("SchemaVersion" in data or "ArtifactName" in data): return "trivy_json"
            if "matches" in data and "source" in data: return "grype_json"
            if "results" in data and "errors" in data:
                results = data.get("results") or []
                if results and "check_id" in results[0]: return "semgrep_json"
            if "results" in data and "config" in data: return "ffuf_json"
            if "results" in data and isinstance(data["results"], dict) and "failed_checks" in data["results"]: return "checkov_json"
            if "data" in data and "meta" in data: return "bloodhound_json_zip"
            if "results" in data: return "dirsearch_json"
            if "findings" in data or "leaks" in data: return "gitleaks_json"
        if isinstance(data, list) and data:
            first = data[0]
            if "RuleID" in first and ("File" in first or "Secret" in first): return "gitleaks_json"
            if isinstance(first, dict) and "results" in first: return "checkov_json"
            if isinstance(first, dict) and ("status" in first or "path" in first): return "dirsearch_json"
        return "unknown"

    async def list_supported_security_formats(self) -> str:
        """List the 20 security output formats this parser supports.

        :return: JSON list of accepted format identifiers.
        """
        return json.dumps({"count": len(SUPPORTED_FORMATS), "formats": SUPPORTED_FORMATS}, indent=2)

    async def detect_security_output_format(self, relative_path: str) -> str:
        """Detect a security tool's output format without parsing all findings.

        :param relative_path: Input file path relative to the mounted input workspace.
        :return: JSON detected format and whether it is supported.
        """
        detected = self._detect(self._safe_input(relative_path))
        return json.dumps({"path": relative_path, "format": detected, "supported": detected in SUPPORTED_FORMATS}, indent=2)

    async def parse_security_output(
        self,
        relative_path: str,
        output_format: str = "auto",
        save_normalized: bool = True,
        max_findings: int = 500,
    ) -> str:
        """Parse and normalise security-tool output, returning a bounded preview and optionally saving full JSON.

        :param relative_path: Input file path relative to the mounted input workspace.
        :param output_format: auto or one of the identifiers returned by list_supported_security_formats.
        :param save_normalized: Save the bounded normalised findings under /workspace/output.
        :param max_findings: Maximum findings parsed and saved, capped by the administrator valve.
        :return: JSON format, severity summary, preview, truncation state, and saved output path.
        """
        path = self._safe_input(relative_path)
        selected = self._detect(path) if output_format == "auto" else output_format.lower().strip()
        parsers: dict[str, Callable[[Path], list[dict[str, Any]]]] = {
            "nmap_xml": self._parse_nmap, "masscan_xml": self._parse_masscan,
            "nessus_xml": self._parse_nessus, "openvas_xml": self._parse_openvas,
            "burp_xml": self._parse_burp, "zap_json": self._parse_zap,
            "nikto_xml": self._parse_nikto, "nuclei_jsonl": self._parse_nuclei,
            "ffuf_json": self._parse_ffuf, "gobuster_text": self._parse_gobuster,
            "dirsearch_json": self._parse_dirsearch, "sqlmap_csv": self._parse_sqlmap,
            "metasploit_xml": self._parse_metasploit, "bloodhound_json_zip": self._parse_bloodhound,
            "trivy_json": self._parse_trivy, "grype_json": self._parse_grype,
            "semgrep_json": self._parse_semgrep, "checkov_json": self._parse_checkov,
            "gitleaks_json": self._parse_gitleaks, "sarif_json": self._parse_sarif,
        }
        if selected not in parsers:
            raise ValueError(f"Unsupported or undetected format: {selected}")
        limit = max(1, min(max_findings, self.valves.max_findings))
        parsed = parsers[selected](path)
        truncated = len(parsed) > limit
        findings = parsed[:limit]
        payload = {
            "source": relative_path,
            "format": selected,
            "finding_count": len(findings),
            "truncated": truncated,
            "severity_counts": dict(Counter(item["severity"] for item in findings)),
            "findings": findings,
        }
        saved_path = ""
        if save_normalized:
            stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", path.stem)[:100]
            output = self._safe_output(f"{stem}.{selected}.normalized.json")
            output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
            saved_path = f"/workspace/output/{output.name}"
        response = {key: value for key, value in payload.items() if key != "findings"}
        response["saved_output"] = saved_path
        response["preview"] = findings[: self.valves.preview_findings]
        return json.dumps(response, indent=2, ensure_ascii=False)
