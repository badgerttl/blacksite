# Hoppscotch proxy

Hoppscotch's web client sends API requests from the browser. If a target API does
not allow the Hoppscotch origin, the browser blocks the request with CORS before
Hoppscotch can display the response. Proxyscotch is Hoppscotch's proxy
interceptor path for that case.

This is separate from Open WebUI's CSP hardening. In the default Blacksite
deployment, Hoppscotch is served by its own container on `localhost:9001`.
Open WebUI's CSP headers do not control Hoppscotch requests.

## Start the proxy

```sh
./blacksite up
```

The service starts with the default stack and listens on `http://localhost:9159`.
The older `--hoppscotch-proxy` flag is still accepted for compatibility.

## Configure Hoppscotch

1. Open `http://localhost:9001`.
2. Open Settings.
3. Go to Interceptors.
4. Enable the Proxy interceptor.
5. Confirm the Proxy URL is `http://localhost:9159`. Blacksite supplies this default
   through Hoppscotch's `PROXY_APP_URL` environment setting. Use Reset Default if
   an existing browser preference still points to another proxy.

Set `PROXYSCOTCH_PUBLIC_URL` in `.env` when the browser needs a different URL,
including when changing `PROXYSCOTCH_PORT`. This URL must be reachable from the
browser, so it uses the host address rather than the Docker service name.

The proxy root redirects to `https://hoppscotch.io/` for ordinary browser GET
requests. That is expected. Hoppscotch uses the URL by sending `POST` requests
with a JSON proxy payload.

`./blacksite init` generates `PROXYSCOTCH_TOKEN` in `.env`. Blacksite passes the
same value to Hoppscotch's `VITE_PROXYSCOTCH_ACCESS_TOKEN` setting. Existing
browser-side Hoppscotch settings may still hold an old proxy access token value;
use Reset Default in the Proxy interceptor settings or clear Hoppscotch site data
after changing token mode.

## Diagnostics

Run:

```sh
./blacksite doctor
```

Expected local checks:

- Hoppscotch app returns HTTP 2xx or 3xx.
- Hoppscotch admin returns HTTP 2xx or 3xx.
- Hoppscotch backend `/backend/ping` returns HTTP 2xx or 3xx.
- Proxyscotch is running and responds to the local reachability check.
- A direct `GET /` to Proxyscotch may return a redirect to `hoppscotch.io`.

If the browser console says a request was blocked by CORS, enable the proxy
interceptor. If the console explicitly says `Content Security Policy`, capture
the full blocked URL and directive, because that indicates a different issue.

## Exposure notes

Proxyscotch is a general-purpose HTTP proxy for Hoppscotch requests. Keep it
bound to `127.0.0.1` unless there is a clear operational requirement to share it.
If you set `BIND_ADDRESS=0.0.0.0`, put the stack behind an authenticated TLS
reverse proxy and review these `.env` values:

```dotenv
PROXYSCOTCH_ALLOWED_ORIGINS=http://localhost:9001,http://127.0.0.1:9001
PROXYSCOTCH_TOKEN=<generated-by-blacksite-init>
PROXYSCOTCH_BANNED_DESTS=169.254.169.254,metadata.google.internal,100.100.100.200
```

For LAN use, add the exact Hoppscotch browser origin to
`PROXYSCOTCH_ALLOWED_ORIGINS`. Keep metadata and internal control-plane hosts in
`PROXYSCOTCH_BANNED_DESTS`.
