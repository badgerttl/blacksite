import asyncio
import importlib.util
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "openwebui-tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Tools()


class OpenWebUIToolsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.input = Path(self.temp.name) / "input"
        self.output = Path(self.temp.name) / "output"
        self.input.mkdir()
        self.output.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_all_twenty_security_formats(self):
        fixtures = {
            "nmap_xml": '<nmaprun scanner="nmap"><host><address addr="10.0.0.1"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>',
            "masscan_xml": '<nmaprun scanner="masscan"><host><address addr="10.0.0.2"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>',
            "nessus_xml": '<NessusClientData_v2><Report><ReportHost name="host"><ReportItem port="22" protocol="tcp" severity="2" pluginName="SSH" pluginFamily="Services"><description>desc</description></ReportItem></ReportHost></Report></NessusClientData_v2>',
            "openvas_xml": '<report><results><result><name>TLS issue</name><host>host</host><port>443/tcp</port><threat>High</threat><description>desc</description></result></results></report>',
            "burp_xml": '<issues burpVersion="1"><issue><name>XSS</name><severity>High</severity><host>example.test</host><path>/x</path></issue></issues>',
            "zap_json": {"site": [{"@host": "example.test", "alerts": [{"alert": "XSS", "riskdesc": "High (3)", "instances": [{"uri": "https://example.test/x"}]}]}]},
            "nikto_xml": '<niktoscan><scandetails targethostname="host" targetport="80"><item id="1"><description>Header issue</description><uri>/</uri></item></scandetails></niktoscan>',
            "nuclei_jsonl": '{"template-id":"tls","host":"host","matched-at":"host:443","info":{"name":"TLS finding","severity":"medium"}}\n',
            "ffuf_json": {"config": {}, "results": [{"status": 200, "url": "https://host/admin", "length": 12}]},
            "gobuster_text": "/admin (Status: 200) [Size: 12]\n",
            "dirsearch_json": [{"status": 200, "url": "https://host/admin", "content-length": 12}],
            "sqlmap_csv": "Target,Place,Parameter,Technique,Title,Payload\nhttps://host,GET,id,B,Boolean injection,id=1\n",
            "metasploit_xml": '<MetasploitV5><hosts><host><address>10.0.0.3</address><services><service><name>ssh</name><port>22</port><proto>tcp</proto></service></services></host></hosts></MetasploitV5>',
            "bloodhound_json_zip": {"data": [{"Properties": {"name": "ADMIN@TEST.LOCAL", "highvalue": True}}], "meta": {"type": "users"}},
            "trivy_json": {"SchemaVersion": 2, "Results": [{"Target": "image", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "pkg", "Severity": "HIGH"}]}]},
            "grype_json": {"source": {}, "matches": [{"vulnerability": {"id": "CVE-1", "severity": "High"}, "artifact": {"name": "pkg", "version": "1", "type": "apk"}}]},
            "semgrep_json": {"errors": [], "results": [{"check_id": "rule", "path": "a.py", "start": {"line": 1}, "extra": {"message": "issue", "severity": "ERROR"}}]},
            "checkov_json": {"results": {"failed_checks": [{"check_id": "CKV_1", "check_name": "Public resource", "file_path": "main.tf", "file_line_range": [1, 2]}]}},
            "gitleaks_json": [{"RuleID": "key", "Description": "API key", "File": "a.env", "StartLine": 1, "Secret": "do-not-return"}],
            "sarif_json": {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Scanner", "rules": []}}, "results": [{"ruleId": "R1", "level": "warning", "message": {"text": "issue"}}]}]},
        }
        tool = load_tool("security_output_parser")
        tool.valves.input_root = str(self.input)
        tool.valves.output_root = str(self.output)
        for name, fixture in fixtures.items():
            path = self.input / f"{name}.txt"
            if isinstance(fixture, str):
                path.write_text(fixture)
            else:
                path.write_text(json.dumps(fixture))
            with self.subTest(name=name):
                result = json.loads(asyncio.run(tool.parse_security_output(path.name, name, False)))
                self.assertEqual(result["format"], name)
                self.assertGreaterEqual(result["finding_count"], 1)
                if name == "gitleaks_json":
                    self.assertNotIn("do-not-return", json.dumps(result))

    def test_bloodhound_zip_and_saved_output(self):
        archive = self.input / "bloodhound.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("users.json", json.dumps({"data": [{"Properties": {"name": "USER@TEST"}}]}))
        tool = load_tool("security_output_parser")
        tool.valves.input_root = str(self.input)
        tool.valves.output_root = str(self.output)
        result = json.loads(asyncio.run(tool.parse_security_output(archive.name)))
        self.assertEqual(result["format"], "bloodhound_json_zip")
        self.assertTrue((self.output / Path(result["saved_output"]).name).is_file())

    def test_all_tenable_export_families_and_generic_csv(self):
        tool = load_tool("security_output_parser")
        tool.valves.input_root = str(self.input)
        tool.valves.output_root = str(self.output)

        fixtures = {
            "tenable.csv": "Plugin ID,CVE,Risk,Host,Protocol,Port,Name,Description,Solution,Plugin Output\n100,CVE-2026-1,High,10.0.0.1,tcp,443,TLS issue,description,fix,evidence\n",
            "tenable.json": json.dumps([{"finding_id": "f-1", "severity": "critical", "asset": {"hostname": "host"}, "plugin": {"id": 100, "name": "Plugin finding", "description": "desc", "solution": "fix"}, "output": "evidence"}]),
            "tenable-was.xml": "<report><vulnerabilities><vulnerability><name>XSS</name><severity>high</severity><url>https://host/x</url><description>desc</description></vulnerability></vulnerabilities></report>",
            "tenable.html": "<html><head><title>Tenable Report</title></head><body><table><tr><th>Name</th><th>Risk</th><th>Host</th></tr><tr><td>Weak TLS</td><td>High</td><td>host</td></tr></table></body></html>",
            "scan.db": b"proprietary-encrypted-tenable-data",
            "policy.json": json.dumps({"uuid": "policy-1", "name": "Basic scan", "settings": {}, "plugins": {}}),
            "timing.csv": "Hostname,IP,FQDN,Scan Start,Scan End,Duration\nhost,10.0.0.1,host.test,1,2,1\n",
        }
        for filename, content in fixtures.items():
            path = self.input / filename
            path.write_bytes(content if isinstance(content, bytes) else content.encode())

        expected = {
            "tenable.csv": "tenable_csv",
            "tenable.json": "tenable_json",
            "tenable-was.xml": "tenable_was_xml",
            "tenable.html": "tenable_html",
            "scan.db": "tenable_db",
            "policy.json": "tenable_policy_json",
            "timing.csv": "tenable_timing_csv",
        }
        for filename, output_format in expected.items():
            with self.subTest(filename=filename):
                detected = json.loads(asyncio.run(tool.detect_security_output_format(filename)))
                self.assertEqual(detected["format"], output_format)
                parsed = json.loads(asyncio.run(tool.parse_security_output(filename, "auto", False)))
                self.assertGreaterEqual(parsed["finding_count"], 1)

        archive = self.input / "security-center.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("scan.nessus", '<NessusClientData_v2><Report><ReportHost name="host"><ReportItem port="22" protocol="tcp" severity="2" pluginName="SSH" pluginFamily="Services" pluginID="100"/></ReportHost></Report></NessusClientData_v2>')
        parsed = json.loads(asyncio.run(tool.parse_security_output(archive.name, "auto", False)))
        self.assertEqual(parsed["format"], "tenable_nessus_zip")
        self.assertEqual(parsed["finding_count"], 1)

        from pypdf import PdfWriter
        pdf_path = self.input / "tenable.pdf"
        writer = PdfWriter()
        writer.add_blank_page(width=612, height=792)
        with pdf_path.open("wb") as handle:
            writer.write(handle)
        parsed = json.loads(asyncio.run(tool.parse_security_output(pdf_path.name, "auto", False)))
        self.assertEqual(parsed["format"], "tenable_pdf")
        self.assertEqual(parsed["finding_count"], 1)

        generic = self.input / "custom.csv"
        generic.write_text("Issue,Rating,Machine,Fix,Password\nExposed service,Critical,server-1,Close it,do-not-return\n")
        parsed = json.loads(asyncio.run(tool.parse_generic_csv(
            generic.name,
            json.dumps({"title": "Issue", "severity": "Rating", "host": "Machine", "remediation": "Fix"}),
            "auto",
            False,
        )))
        self.assertEqual(parsed["preview"][0]["title"], "Exposed service")
        self.assertEqual(parsed["preview"][0]["severity"], "critical")
        self.assertNotIn("do-not-return", json.dumps(parsed))

    def test_file_reader_is_bounded_and_jailed(self):
        (self.input / "evidence.txt").write_text("alpha\nbeta\ngamma\n")
        tool = load_tool("workspace_files")
        tool.valves.input_root = str(self.input)
        result = json.loads(asyncio.run(tool.read_workspace_file("evidence.txt", 2, 3)))
        self.assertIn("2: beta", result["content"])
        with self.assertRaises(ValueError):
            asyncio.run(tool.read_workspace_file("../outside.txt"))

    def test_sqlite_is_read_only(self):
        database = self.input / "findings.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE findings (severity TEXT, title TEXT)")
        connection.execute("INSERT INTO findings VALUES ('high', 'test')")
        connection.commit()
        connection.close()
        tool = load_tool("readonly_database")
        tool.valves.input_root = str(self.input)
        result = json.loads(asyncio.run(tool.query_sqlite_database("findings.db", "SELECT * FROM findings")))
        self.assertEqual(result["row_count"], 1)
        with self.assertRaises(ValueError):
            asyncio.run(tool.query_sqlite_database("findings.db", "DELETE FROM findings"))

    def test_workspace_writer_and_sqlite_export(self):
        database = self.input / "services.db"
        connection = sqlite3.connect(database)
        connection.execute("CREATE TABLE services (ip TEXT, port INTEGER, protocol TEXT, state TEXT)")
        connection.executemany(
            "INSERT INTO services VALUES (?, ?, ?, ?)",
            [("192.0.2.10", 22, "tcp", "open"), ("192.0.2.20", 443, "tcp", "open")],
        )
        connection.commit()
        connection.close()
        tool = load_tool("workspace_writer")
        tool.valves.input_root = str(self.input)
        tool.valves.output_root = str(self.output)
        result = json.loads(asyncio.run(tool.export_sqlite_query(
            "services.db",
            "SELECT DISTINCT ip FROM services WHERE port = :port AND state = 'open'",
            "reports/ssh-open.csv",
            "csv",
            '{"port": 22}',
        )))
        self.assertEqual(result["row_count"], 1)
        self.assertEqual((self.output / "reports" / "ssh-open.csv").read_text(), "ip\n192.0.2.10\n")
        with self.assertRaises(FileExistsError):
            asyncio.run(tool.write_output_text("reports/ssh-open.csv", "replacement"))
        with self.assertRaises(ValueError):
            asyncio.run(tool.write_output_text("../escape.txt", "blocked"))
        with self.assertRaises(ValueError):
            asyncio.run(tool.export_sqlite_query(
                "services.db", "DELETE FROM services", "blocked.csv", "csv"
            ))


class ToolDeploymentTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location(
            "deploy_openwebui_tools", ROOT / "scripts" / "deploy-openwebui-tools.py"
        )
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        module = self.module

        class FakeClient(module.OpenWebUIClient):
            def __init__(self):
                super().__init__("http://open-webui", "token")
                self.tools = {}
                self.admin_config = {
                    "WEBUI_URL": "http://localhost:3000",
                    "ENABLE_SIGNUP": True,
                    "ENABLE_API_KEYS": True,
                    "ENABLE_API_KEYS_ENDPOINT_RESTRICTIONS": False,
                    "API_KEYS_ALLOWED_ENDPOINTS": "",
                    "DEFAULT_USER_ROLE": "user",
                    "JWT_EXPIRES_IN": "4w",
                    "ENABLE_COMMUNITY_SHARING": True,
                }
                self.task_config = {"ENABLE_FOLLOW_UP_GENERATION": True}
                self.rag_config = {"FILE_MAX_SIZE": None, "FILE_MAX_COUNT": None, "ALLOWED_FILE_EXTENSIONS": []}
                self.connections_config = {"ENABLE_DIRECT_CONNECTIONS": True, "ENABLE_BASE_MODELS_CACHE": True}

            def request(self, method, path, payload=None, *, authenticate=True):
                if path == "/health":
                    return 200, {"status": True}
                configs = {
                    "/api/v1/auths/admin/config": "admin_config",
                    "/api/v1/tasks/config": "task_config",
                    "/api/v1/tasks/config/update": "task_config",
                    "/api/v1/retrieval/config": "rag_config",
                    "/api/v1/retrieval/config/update": "rag_config",
                    "/api/v1/configs/connections": "connections_config",
                }
                if path in configs:
                    attribute = configs[path]
                    if method == "POST":
                        setattr(self, attribute, dict(payload))
                    return 200, getattr(self, attribute)
                if method == "GET" and path.startswith("/api/v1/tools/id/"):
                    tool_id = path.rsplit("/", 1)[1]
                    return (200, self.tools[tool_id]) if tool_id in self.tools else (404, "Not found")
                if method == "POST" and path == "/api/v1/tools/create":
                    self.tools[payload["id"]] = payload
                    return 200, payload
                if method == "POST" and path.endswith("/update"):
                    tool_id = path.split("/")[-2]
                    self.tools[tool_id] = payload
                    return 200, payload
                return 404, "Not found"

        self.client = FakeClient()

    def test_create_unchanged_and_update(self):
        self.client.wait_until_ready(1)
        action = self.client.deploy_tool("tool_id", "Tool", "version-one", "Description")
        self.assertEqual(action, "created")
        action = self.client.deploy_tool("tool_id", "Tool", "version-one", "Description")
        self.assertEqual(action, "unchanged")
        action = self.client.deploy_tool("tool_id", "Tool", "version-two", "Description")
        self.assertEqual(action, "updated")
        self.assertEqual(self.client.tools["tool_id"]["content"], "version-two")

    def test_hardening_reconciliation_is_idempotent(self):
        changes = self.client.reconcile_hardening()
        self.assertEqual(len(changes), 4)
        self.assertFalse(self.client.admin_config["ENABLE_SIGNUP"])
        self.assertEqual(self.client.admin_config["DEFAULT_USER_ROLE"], "pending")
        self.assertFalse(self.client.task_config["ENABLE_FOLLOW_UP_GENERATION"])
        self.assertEqual(self.client.rag_config["FILE_MAX_SIZE"], 50)
        self.assertFalse(self.client.connections_config["ENABLE_DIRECT_CONNECTIONS"])
        self.assertEqual(self.client.reconcile_hardening(), [])


if __name__ == "__main__":
    unittest.main()
