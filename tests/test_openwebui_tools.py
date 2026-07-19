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

            def request(self, method, path, payload=None, *, authenticate=True):
                if path == "/health":
                    return 200, {"status": True}
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


if __name__ == "__main__":
    unittest.main()
