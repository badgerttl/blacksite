# Blacksite Open WebUI tools

The current Blacksite tools are licensed under GPL-3.0-only. See the repository's
[LICENSE](../LICENSE). Upstream applications retain their own licenses.

These standalone Python tools operate only within Blacksite's mounted workspace:

- `security_output_parser.py` detects and normalises common security-tool formats, Tenable exports, and arbitrary CSV data.
- `workspace_files.py` safely lists, inspects, reads, and searches input files.
- `readonly_database.py` inspects and queries local SQLite files or an administrator-configured SQL database.
- `workspace_writer.py` atomically writes text/JSON and exports read-only SQLite query results.

## Automated deployment

The one-shot `open-webui-tools-deploy` Compose service automatically creates or updates all three tools after Open WebUI becomes healthy. It uses the supported `/api/v1/tools` endpoints and preserves existing access grants.

Run it again at any time after editing a tool:

```sh
./blacksite tools
```

On a fresh installation, `./blacksite init` generates an administrator bootstrap password and the deployer signs in with it. For an existing Open WebUI data volume, set `OPEN_WEBUI_ADMIN_EMAIL` and `OPEN_WEBUI_ADMIN_PASSWORD` to an existing administrator's credentials, or place an administrator bearer/API token in `OPEN_WEBUI_TOOLS_TOKEN`.

The deployer is idempotent: tools are created when missing, updated when source or metadata changes, and otherwise left unchanged.

## Workspace access

Place source material under `workspace/input/` on the host. It is mounted read-only at `/workspace/input` inside Open WebUI. Parser output is written to `workspace/output/`, mounted read-write at `/workspace/output`.

Both file-based tools resolve paths before access and reject traversal or symlink escapes. Large reads, returned text, archive expansion, findings, rows, and database query time are bounded with administrator-configurable valves.

## Writing output files

The workspace writer can create approved text formats only under `/workspace/output`. Writes are atomic, bounded by size, and refuse to replace an existing file unless `overwrite` is explicitly true.

`export_sqlite_query` opens a database under `/workspace/input` using SQLite read-only mode and exports one `SELECT`, `WITH`, or `EXPLAIN` statement as CSV, TSV, JSON, or JSONL. Queries support named parameters, row and time limits, and spreadsheet-formula neutralisation for CSV/TSV output.

Example request:

```text
Export distinct IP addresses with TCP port 22 to reports/ssh-open.csv from example.db.
```

The corresponding query is:

```sql
SELECT DISTINCT ip_address
FROM finding_details
WHERE port = 22 AND protocol = 'tcp';
```

## Supported security formats

1. Nmap XML
2. Masscan XML
3. Nessus XML (`.nessus`)
4. OpenVAS/GVM XML
5. Burp Suite Scanner XML
6. OWASP ZAP JSON
7. Nikto XML
8. Nuclei JSONL/NDJSON
9. ffuf JSON
10. Gobuster text
11. dirsearch JSON
12. sqlmap CSV
13. Metasploit XML
14. BloodHound JSON or ZIP
15. Trivy JSON
16. Grype JSON
17. Semgrep JSON
18. Checkov JSON
19. Gitleaks JSON
20. SARIF 2.1 JSON

### Tenable formats

- Nessus XML (`.nessus`), including Tenable Security Center ZIP containers
- Nessus and Tenable Vulnerability Management scan-report CSV
- Vulnerability Management findings/API JSON, including nested asset and plugin objects
- Tenable Web App Scanning JSON, XML, CSV, HTML, and PDF reports
- Nessus HTML and PDF reports
- Nessus policy JSON
- Nessus timing-data CSV
- Proprietary encrypted Nessus DB (`.db`) identification, hashing, and conversion guidance

Tenable's `.db` format is proprietary and encrypted, so it cannot be decoded locally. The parser identifies and fingerprints it without exposing contents; import it into Nessus with its export password and re-export a machine-readable format for finding-level normalization.

### Generic CSV

Use `parse_generic_csv` for CSV, TSV, semicolon-delimited, or pipe-delimited data. It automatically maps common column names or accepts a target-to-source JSON map:

```json
{
  "title": "Issue",
  "severity": "Rating",
  "host": "Machine",
  "remediation": "Recommended Fix"
}
```

Supported normalized targets are `category`, `title`, `severity`, `host`, `port`, `protocol`, `location`, `description`, `evidence`, `identifiers`, and `remediation`. Columns with names indicating passwords, secrets, tokens, API keys, or private keys are redacted from supplementary evidence.

The parser produces a common schema containing tool, category, title, severity, host, port, protocol, location, description, evidence, identifiers, and remediation. Gitleaks secret values are never returned or written; only a short SHA-256 fingerprint is retained for correlation.

## Database connections

Local SQLite databases can be placed anywhere under `workspace/input/`. They are opened using SQLite `mode=ro` and `PRAGMA query_only`.

For PostgreSQL, MySQL/MariaDB, or another SQLite database, set the database tool's `database_url` valve in Open WebUI. The database account should also have read-only privileges. Remote queries use database-side read-only transactions, rollback after every call, reject write/administrative SQL, and cap returned rows.

Example valve value:

```text
postgresql+psycopg2://report_reader:password@database.example:5432/security
```

The matching Python database driver must already be installed in the Open WebUI container.
