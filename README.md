# Blacksite tool stack

A local-first, multi-container security consultancy toolkit for Docker Compose or
Podman Compose. All application images and local builds support `linux/amd64` and
`linux/arm64`, including Apple M-series hosts.

## Included services

| Tool | Default URL | Persistence |
| --- | --- | --- |
| Open WebUI | http://localhost:9000 | chats, users, settings |
| Hoppscotch | http://localhost:9001 | PostgreSQL database |
| Hoppscotch admin | http://localhost:9001/admin | same database |
| CloudBeaver | http://localhost:9002 | workspace and connections |
| CyberChef | http://localhost:9003 | browser local storage |
| Reverse Shell Generator | http://localhost:9004 | browser local storage |
| HackTricks | http://localhost:9005 | immutable offline snapshot |
| SearXNG | http://localhost:9006 | repository-managed configuration |

The stack binds to `127.0.0.1` by default. It does not expose the tools to the LAN.

## Quick start

```sh
./blacksite init
./blacksite up
```

The first build is large because it compiles the pinned HackTricks snapshot. Later
starts reuse the local image and persistent volumes. Run `./blacksite urls` at any
time to print the entry points.

### Local LLM in a container

```sh
./blacksite up --local-llm
./blacksite model qwen3:8b
```

The optional Ollama service is CPU-only on Docker Desktop for macOS. For Apple
Silicon GPU acceleration, install Ollama on macOS, start the ordinary stack with
`./blacksite up`, and leave `OLLAMA_BASE_URL=http://host.docker.internal:11434` in
`.env`. On Linux with an NVIDIA GPU, add the appropriate Ollama GPU device stanza
for your container engine.

### Remote AI provider

Either set these values in `.env` before first start:

```dotenv
OPENAI_API_BASE_URL=https://api.example.com/v1
OPENAI_API_KEY=replace-me
```

or add OpenAI-compatible, Ollama, or other supported connections in Open WebUI's
Admin Settings. Provider keys are secrets; keep `.env` mode `0600` and never commit
it.

Open WebUI web search is enabled by default and uses the included SearXNG instance.
SearXNG's JSON API is enabled in `config/searxng/settings.yml` for this integration.

### Open WebUI file workspace

Open WebUI tools have two persistent, host-accessible directories:

| Purpose | Host path | Container path | Access in container |
| --- | --- | --- | --- |
| Source files | `workspace/input` | `/workspace/input` | read-only |
| Generated files | `workspace/output` | `/workspace/output` | read/write |

Place evidence and data to parse in `workspace/input`. Tools should write reports,
converted files, extracted artifacts, and other results to `workspace/output`. The
container receives `BLACKSITE_INPUT_DIR` and `BLACKSITE_OUTPUT_DIR` environment
variables containing these paths. Run `./blacksite workspace` to print the resolved
locations.

The directories are bind mounts, so files remain after containers are recreated and
are directly accessible from the host. Their contents are ignored by Git. Override
either host location with `OPEN_WEBUI_INPUT_DIR` or `OPEN_WEBUI_OUTPUT_DIR` in `.env`.
Open WebUI does not automatically ingest files from these directories; an installed
tool or function must explicitly read them.

Importable tools for security-output parsing, bounded file reading, and read-only
database access are in [`openwebui-tools/`](openwebui-tools/README.md). The parser
supports 20 common formats and saves normalised results into `workspace/output/`.
They are registered automatically by a one-shot Compose service after Open WebUI
becomes healthy. Run `./blacksite tools` to force an immediate idempotent redeploy.

## Docker and Podman

The `blacksite` helper auto-detects, in order: Docker Compose, `podman compose`, and
`podman-compose`. If both engines are installed, put the intended one first on
`PATH`. Direct Compose commands also work:

```sh
docker compose up -d --build
podman compose up -d --build
```

Rootless engines can use every published port because the containers listen on
unprivileged ports internally. Named volumes avoid host UID/GID differences.

## Initial setup

1. Open Hoppscotch admin and create the first administrator. Database migrations
   run automatically before Hoppscotch starts.
2. Open CloudBeaver and complete its first-run administrator wizard. From
   CloudBeaver, the Hoppscotch database host is `hoppscotch-db`, port `5432`.
3. The first Open WebUI account becomes its administrator.

If an older Podman Compose implementation does not honour the completed migration
dependency, run `./blacksite migrate` once and then `./blacksite up` again.

## Configuration and LAN access

Ports, source revisions, provider URLs, and bind address are in `.env`. To serve
the tools on a trusted LAN, set `BIND_ADDRESS=0.0.0.0`, change
`HOPPSCOTCH_PUBLIC_URL`/`HOPPSCOTCH_WS_URL` to the address clients use, and put an
authenticated TLS reverse proxy in front of the stack. Do not expose these tools
directly to an untrusted network.

## Offline operation

After `./blacksite up` has pulled/built everything, CyberChef, RevShell Generator,
and HackTricks are fully local. Export images for an air-gapped host with your
engine's `save` command, then copy this repository and `.env`. Open WebUI can work
offline with Ollama after the model has been pulled. Hoppscotch and CloudBeaver are
local applications, though database drivers or optional integrations may require a
one-time download.

## Maintenance

```sh
./blacksite pull
./blacksite build
  ./blacksite up
```

Application versions and upstream source commits are deliberately pinned. Update
the tags in `compose.yaml` and source commit IDs in `.env` after reviewing upstream
release notes. `./blacksite down` preserves data; `docker compose down -v` (or the
Podman equivalent) permanently deletes all named-volume data.
