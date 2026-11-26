# Acknowledgements

Blacksite packages and configures tools created by the projects below. Their
maintainers and contributors deserve credit for the applications, reference
material, and infrastructure used here.

Credits do not replace license terms. The [license review](docs/licensing-review.md)
records the checked upstream terms and unresolved permissions. In particular,
HackTricks asks users to contact its author about commercial use.

## Included applications

| Project | Contribution to Blacksite | Upstream terms |
| --- | --- | --- |
| [Open WebUI](https://github.com/open-webui/open-webui) | AI chat interface and runtime for Blacksite's workspace tools | [Open WebUI License with branding conditions](https://github.com/open-webui/open-webui/blob/main/LICENSE) |
| [Hoppscotch](https://github.com/hoppscotch/hoppscotch) | API client and administration interface | [Community repository MIT license](https://github.com/hoppscotch/hoppscotch/blob/main/LICENSE) |
| [Proxyscotch](https://github.com/hoppscotch/proxyscotch) | Hoppscotch's HTTP proxy interceptor | [MIT](https://github.com/hoppscotch/proxyscotch/blob/master/LICENSE) |
| [CloudBeaver by DBeaver](https://github.com/dbeaver/cloudbeaver) | Browser database client | [Community edition Apache-2.0](https://github.com/dbeaver/cloudbeaver/blob/devel/LICENSE) |
| [CyberChef by GCHQ](https://github.com/gchq/CyberChef) | Data conversion, encoding, and analysis | [Apache-2.0](https://github.com/gchq/CyberChef/blob/master/LICENSE) |
| [Reverse Shell Generator](https://github.com/0dayCTF/reverse-shell-generator) | Local reverse-shell reference and generator by Ryan Montgomery and contributors | [MIT](https://github.com/0dayCTF/reverse-shell-generator/blob/main/LICENSE) |
| [HackTricks](https://github.com/HackTricks-wiki/hacktricks) | Locally built security reference by Carlos Polop and contributors | [Custom terms; commercial use requires clarification](https://github.com/HackTricks-wiki/hacktricks/blob/master/src/welcome/hacktricks-values-and-faq.md#license) |
| [SearXNG](https://github.com/searxng/searxng) | Search engine used by Open WebUI | [AGPL-3.0-or-later](https://github.com/searxng/searxng/blob/master/LICENSE) |
| [Ollama](https://github.com/ollama/ollama) | Optional local model server | [MIT](https://github.com/ollama/ollama/blob/main/LICENSE); downloaded models have separate licenses |

## Supporting projects

- [PostgreSQL](https://www.postgresql.org/) stores Hoppscotch data.
- [NGINX](https://nginx.org/) serves the local reference sites.
- [mdBook](https://github.com/rust-lang/mdBook) and
  [mdbook-tabs](https://github.com/RustForWeb/mdbook-plugins) build HackTricks.
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
