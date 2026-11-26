# Acknowledgements

Blacksite packages and configures tools created by the projects below. Their
maintainers and contributors deserve credit for the applications, reference
material, and infrastructure used here.

## Included applications

| Project | Contribution to Blacksite | Upstream |
| --- | --- | --- |
| Open WebUI | AI chat interface and runtime for Blacksite's workspace tools | [open-webui/open-webui](https://github.com/open-webui/open-webui) |
| Hoppscotch | API client and administration interface | [hoppscotch/hoppscotch](https://github.com/hoppscotch/hoppscotch) |
| Proxyscotch | Hoppscotch's HTTP proxy interceptor | [hoppscotch/proxyscotch](https://github.com/hoppscotch/proxyscotch) |
| CloudBeaver by DBeaver | Browser database client | [dbeaver/cloudbeaver](https://github.com/dbeaver/cloudbeaver) |
| CyberChef by GCHQ | Data conversion, encoding, and analysis | [gchq/CyberChef](https://github.com/gchq/CyberChef) |
| Reverse Shell Generator | Local reverse-shell reference and generator | [0dayCTF/reverse-shell-generator](https://github.com/0dayCTF/reverse-shell-generator) |
| HackTricks | Locally built security reference by Carlos Polop and contributors | [HackTricks-wiki/hacktricks](https://github.com/HackTricks-wiki/hacktricks) |
| SearXNG | Search engine used by Open WebUI | [searxng/searxng](https://github.com/searxng/searxng) |
| Ollama | Optional local model server | [ollama/ollama](https://github.com/ollama/ollama) |

## Supporting projects

- [PostgreSQL](https://www.postgresql.org/) stores Hoppscotch data.
- [NGINX](https://nginx.org/) serves the local reference sites.
- [mdBook](https://github.com/rust-lang/mdBook) and
  [mdbook-tabs](https://github.com/RustForWeb/mdbook-tabs) build HackTricks.
- [Rust](https://www.rust-lang.org/) and [Alpine Linux](https://alpinelinux.org/)
  provide the local build toolchain and container bases.
- [Docker Compose](https://github.com/docker/compose),
  [Podman](https://podman.io/), and
  [podman-compose](https://github.com/containers/podman-compose) run the stack.
- [Python](https://www.python.org/), [Pydantic](https://github.com/pydantic/pydantic),
  [SQLAlchemy](https://github.com/sqlalchemy/sqlalchemy), and
  [pypdf](https://github.com/py-pdf/pypdf) support the workspace tools and integrations.

Each upstream project retains its own copyright, license, attribution requirements,
and trademarks. Consult the license and notices shipped with the version you use.
Blacksite's inclusion of a project does not imply endorsement by its authors.
