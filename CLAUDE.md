# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Firegex is a firewall built for CTF Attack-Defense competitions: it sits in front of a vulnerable service and blocks/mangles malicious traffic before it reaches it. It ships several independent filtering modules (regex-based, Python-filter-based, port hijacking, plain nftables rules, TLS decrypt-and-reinspect) behind a single FastAPI backend and React frontend.

## Commands

### Running the whole app (Docker or standalone)
```bash
python3 run.py                      # build+start (Docker if available, else standalone chroot on Linux)
python3 run.py --standalone         # force standalone mode (no Docker)
python3 run.py stop [--clear]       # stop (optionally wipe the DB volume/rootfs)
python3 run.py restart              # recreate the container WITHOUT rebuilding (stale image if source changed)
python3 run.py status
python3 run.py config --password [newpass]   # change the running instance's password; omit the value to be prompted interactively
python3 run.py config --show        # print the persisted settings (port, host, socket dir, auth)
python3 run.py start --unsafe-disable-auth   # no authentication at all — see "Authentication" below
```
`run.py` has zero external dependencies (stdlib only) by design. `restart` runs `docker compose up -d --force-recreate`, so it re-reads the generated compose file and re-applies env vars (`ALLOWED_IPS`, `PROXY_IP_HEADER`, `UNSAFE_DISABLE_AUTH`) — a plain `docker compose restart` would keep the old container environment and silently ignore those. It still does **not** rebuild the image; after a source change use `stop` then the bare start command to force `docker compose up -d --build`.

Most `start`/`restart` flags are persisted to `.firegex-conf.json` and become the default for later runs, so a bare `python3 run.py start` inherits whatever was last passed.

### Frontend (`frontend/`)
```bash
bun install          # bun.lock is canonical
bun run dev           # vite dev server
bun run build         # tsc && vite build
npx tsc --noEmit -p . # typecheck only (no separate lint script is configured)
```

### Backend (`backend/`)
Needs Linux with `NET_ADMIN` (nftables/nfqueue) and root, so it's normally only run via `run.py` (Docker or standalone). Direct iteration on a Linux box/VM:
```bash
cd backend && DEBUG=1 python3 app.py DEBUG
```

### Tests (`tests/`)
No pytest — plain scripts driven against a **live, already-running** firegex instance (`http://127.0.0.1:4444` by default), root/Linux required.
```bash
cd tests
./run_tests.sh [password]           # full suite (defaults to "testpassword")
python3 nfregex_test.py -p <pw> -m tcp [--ipv6] [--tls]
python3 nfproxy_test.py -p <pw> [--ipv6] [--tls]
python3 ph_test.py -p <pw> -m tcp|udp [--ipv6]
python3 tls_test.py -p <pw> [--ipv6]
python3 api_test.py -p <pw>
python3 ipfilter_test.py            # access control (--allowed-ips/--proxy-ip-header/--unsafe-disable-auth)
```
`ipfilter_test.py` is the odd one out: those settings are only read at process startup, so it drives `run.py stop`/`start` itself for each scenario and restores an unrestricted instance at the end. It is **not** part of `run_tests.sh` — run it on its own, and expect it to bounce the instance.

CI (`.github/workflows/release.yml`) runs **only on `release: published`**, not on pushes or pull requests — nothing validates a PR automatically. Its `run_tests` job (`ubuntu-latest` + `ubuntu-24.04-arm`) does `python3 run.py start -P testpassword` then `cd tests && ./run_tests.sh`, and gates every publish job below it.

## Architecture

### Three tiers
React (Vite + Mantine + react-router + TanStack Query + socket.io-client) → FastAPI backend → per-module C++ binaries that do the actual packet interception via nftables/NFQUEUE. The backend mostly orchestrates: SQLite-backed config, spawning/talking to the C++ processes over unix sockets, and deploying the built React app.

### Backend router auto-discovery (`backend/utils/loader.py`)
Every `.py` file in `backend/routers/` is auto-imported and mounted at `/api/<filename>` if it exposes a module-level `app` (a `fastapi.APIRouter`). Optional module-level `startup()`, `shutdown()`, `reset(params)` async functions are collected and called by the app's lifespan/`/api/reset` handlers. **Adding a new module = adding a new file here** — nothing else needs to register it.

### Per-module pattern
Each filtering module (`nfproxy`, `nfregex`, `porthijack`, `firewall`, `tls`) follows the same shape:
- `backend/routers/<mod>.py` — FastAPI endpoints + its own SQLite DB, via `utils.sqlite.SQLite`.
- `backend/modules/<mod>/models.py` — plain `Service`/filter model, `from_dict`.
- `backend/modules/<mod>/firewall.py` — `FirewallManager`/`ServiceManager` pair: `FirewallManager` tracks one `ServiceManager` per DB row (in-memory), `ServiceManager.next(status)` starts/stops the interceptor/nft rules for that one service.
- `backend/modules/<mod>/nftables.py` — builds/tears down the module's nftables rules; the manager class extends `utils.NFTableManager` (a `Singleton`), so there's exactly one nft-rule-set owner per module.

### nfproxy vs nfregex
Both intercept via NFQUEUE, but differently:
- **nfregex** (`backend/binsrc/nfregex.cpp` → `cppregex`): pure C++, matches PCRE2/hyperscan regexes against the stream entirely in the binary. Faster, but rules are just regex+mode.
- **nfproxy** (`backend/binsrc/nfproxy.cpp`, `binsrc/pyproxy/*`, embeds libpython → `cpproxy`): user-supplied Python filter code (via the `firegex` pip package, `fgex-lib/`) runs inside the C++ process through the embedded interpreter, talking back to the backend over a unix socket for stats/exceptions. Much more flexible, slower than nfregex.

### TLS Decrypt bridge (`backend/modules/tls/`)
A `tls_streams` DB row describes one public `ip:port` to decrypt. `ssl_port`/`clear_port` are two loopback ports **deterministically derived from a hash of `ip:port`** (`get_tls_ports()`), not stored arbitrarily. nginx (config generated by `modules/tls/nginx.py`) does the actual TLS work per active stream:
1. `listen loopback:ssl_port ssl` → terminates the public TLS connection, forwards **plaintext** to `loopback:clear_port`.
2. `listen loopback:clear_port` → re-encrypts (`proxy_ssl on`) and forwards to the real `ip:port`. The real backend is expected to also speak TLS (mirrors a CTF challenge service that natively does TLS) — this is not a generic "terminate TLS in front of a plaintext service" reverse proxy.

The only unencrypted hop is the loopback leg between `ssl_port` and `clear_port` — an nfproxy/nfregex service must attach there (`target_type="tls"`, `tls_stream_id=...`) to see decrypted content. Both modules' `nftables.py` has a `resolve_target(srv)` helper that swaps in `(loopback_ip, clear_port)` for `target_type="tls"` services instead of the service's own `ip_int`/`port` (which mirror the stream's real destination for display only). Stopping a TLS stream cascades to stop dependent filter services (and vice versa on start); deleting a stream still referenced by a service is rejected. This cross-module logic lives in `routers/tls.py`, which imports `routers.nfproxy`/`routers.nfregex` directly (one-directional — those modules only import `modules.tls.*`, never `routers.tls`).

### Authentication (`backend/app.py`)
Every module router is mounted onto `api = APIRouter(prefix="/api", dependencies=[Depends(is_loggined)])`, so a new file in `routers/` is authenticated by construction. The whole auth surface is four places: that dependency, the Socket.IO `connect` handler (reads the token out of `auth`), and the three routes declared on `app` directly rather than on `api` — `/api/status`, `/api/login`, `/api/set-password`. Adding an unauthenticated route means declaring it on `app`, which should stay a deliberate, rare act.

`--unsafe-disable-auth` (env `UNSAFE_DISABLE_AUTH`) hands access control to a reverse proxy: `check_login` returns `True`, the socket.io handler skips its check, and `APP_STATUS()` reports `run` even with no password stored. The password endpoints (`/api/login`, `/api/set-password`, `/api/change-password`) answer `403` in this mode on purpose — otherwise an anonymous caller could plant a credential that keeps working once authentication is turned back on. `run.py config --password` still works, writing the hash straight into the DB from the host, and an explicit `-P` at first start is kept so that re-enabling authentication lands on a known password instead of the open initial-setup state.

Independently of that, `IPFilterMiddleware` restricts access by CIDR (`--allowed-ips`, optionally reading the client IP from `--proxy-ip-header`). It **fails closed**: a missing, unparseable, or non-matching IP is denied. Note the header variant trusts a client-supplied value, so it only holds if the proxy overwrites it.

### SQLite wrapper (`backend/utils/sqlite.py`)
Each DB file's schema is versioned by hashing the Python schema dict; on mismatch the **entire file is deleted and recreated** (not migrated) — any schema dict change wipes that DB file on next startup, including `db/firegex.db`'s `keys_values` table (password/JWT secret). `dump()`/`load()` back the export/import backup feature; `dump()` deliberately excludes `password`/`secret` from exported `keys_values` rows, so `/api/import` explicitly re-preserves the current password/secret around the import.

### Real-time frontend updates
One Socket.IO event, `"update"`, whose payload is a list of strings treated as a react-query `queryKey` prefix (e.g. `["nfproxy"]`, `["tls_streams"]`). `App.tsx` does `queryClient.invalidateQueries({ queryKey: data })` — prefix matching invalidates any query whose key starts with that array. Convention: each module's mutating endpoints emit the same tag string that module's frontend queries use as the first `queryKey` element. `staleTime: Infinity` is set globally, so this event is the **only** automatic refresh mechanism — a missing/mismatched tag means silent staleness for other clients/tabs.

### Frontend structure
`pages/<Module>/` (routes) + `components/<Module>/` (ServiceRow, AddEditService, `utils.ts` with query key + API wrapper) per module, mirroring the backend split. Detail drill-down lives at `pages/<Module>/ServiceDetails.tsx` under a nested `:srv` route (see `App.tsx`'s `PageRouting`). Theme tokens are CSS variables in `src/index.css`; Mantine `Card` defaults are set globally in `index.tsx`. Prefer Mantine `Group`/`Stack` with `gap` over the legacy `Box className="center-flex"` utility classes still present in older parts of the codebase.

### `fgex-lib/`
Separate, independently-published PyPI package (`pip install fgex`/`firegex`) — the library users write nfproxy filters against (`@pyfilter`, `RawPacket`/`HttpRequest`/etc.), plus the `fgex` CLI and a local `proxysim` for testing filters without a real firegex instance. Not part of the backend/frontend build. `fgex-lib/README.md` is a short index (PyPI-facing) linking out to `docs/*.md`; it isn't rendered anywhere itself.

### Module documentation (`docs/*.md`)
Each module's user-facing docs (`docs/nfproxy.md`, `docs/nfregex.md`, `docs/porthijack.md`, `docs/firewall.md`, `docs/tls.md`) are single markdown sources, each imported directly with Vite's `?raw` suffix by a matching `<Module>Docs.tsx` component (e.g. `components/NFProxy/NFProxyDocs.tsx`) and rendered through the shared `components/MarkdownDocs.tsx` (React Markdown + `remark-gfm`, code fences routed through `CodeHighlight`, relative `.md` cross-links rewritten to the equivalent GitHub blob URL since they'd otherwise resolve against the app's own origin). `DocsButton.tsx`'s `DocType` enum wires each module to its component. Editing a module's docs means editing its one `docs/*.md` file — never the `*Docs.tsx` component directly. Reading these files across the `frontend/`↔repo-root boundary requires `vite.config.ts`'s `server.fs.allow: ['..']` (dev) and the `Dockerfile` frontend build stage's `COPY ./docs/*.md /docs/` (prod/standalone rootfs) to stay in sync with any path changes.
