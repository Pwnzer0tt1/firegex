/**
 * In-memory stand-in for the firegex backend, used only by the public demo build
 * (`bun run build:demo`, i.e. VITE_DEMO=true).
 *
 * A normal build never ships this: `utils.tsx` guards every reference behind IS_DEMO,
 * which vite inlines as a literal `false`, so rollup drops the module and its seed data.
 * Keep it free of top-level side effects, or that tree-shaking stops working.
 *
 * It covers the subset of the API the frontend actually calls, over mutable state, so a
 * visitor can create, edit, start, stop and delete things and watch the UI react exactly
 * as it would against a real instance. Nothing is persisted: a reload restores the seed.
 */

type Json = Record<string, any>

const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(16).slice(2))

const DEMO_CERT = "-----BEGIN CERTIFICATE-----\n(demo placeholder, no real key material is shipped)\n-----END CERTIFICATE-----\n"

// Three functions in one file, because that is the normal case and it is what the
// per-function switches on the filter card are for. Nothing here declares a protocol:
// asking for an HttpRequest is what makes this an HTTP filter, and the RawPacket one
// sits beside it because HTTP provides both.
const SAMPLE_FILTER = `from firegex.pyfilters import pyfilter, ACCEPT, REJECT, UNSTABLE_MANGLE
from firegex.pyfilters.models import HttpRequest, RawPacket


@pyfilter
def block_path_traversal(http_request: HttpRequest):
    """Drop any request trying to climb out of the web root."""
    if ".." in http_request.url:
        return REJECT
    return ACCEPT


@pyfilter
def redact_flag(packet: RawPacket):
    """Never let a flag leave, whatever the request looked like."""
    if packet.is_input or b"FLAG{" not in packet.data:
        return ACCEPT
    packet.data = packet.data.replace(b"FLAG{", b"REDACTED{")
    return UNSTABLE_MANGLE


@pyfilter
def log_client(packet: RawPacket):
    """Noisy while debugging, switched off once it has served its purpose."""
    print("chunk from", packet.client_ip, packet.client_port)
    return ACCEPT
`

const b64 = (text: string) => btoa(text)

// A trimmed copy of what the backend introspects out of the library, so the demo's
// editor offers the same completion. Short on purpose: the real one is generated.
const DEMO_PYFILTER_API = {
    models: [
        {
            name: "RawPacket", protocols: ["http", "tcp"],
            doc: "One chunk of a connection, with what is known about where it came from. "
                + "Everything below the application layer is metadata, and read-only.",
            members: [
                { name: "client_ip", doc: "The client's address, whichever way this chunk is going", writable: false },
                { name: "client_port", doc: "The client's port, whichever way this chunk is going", writable: false },
                { name: "data", doc: "The application payload: the only part a filter can change", writable: true },
                { name: "data_size", doc: "How many bytes of application payload this chunk carries", writable: false },
                { name: "dst_ip", doc: "Where this chunk is going", writable: false },
                { name: "dst_port", doc: "The port this chunk is going to", writable: false },
                { name: "is_input", doc: "True if the chunk is going from the client to the service", writable: false },
                { name: "is_ipv6", doc: "True if the connection is IPv6, false if it is IPv4", writable: false },
                { name: "is_tcp", doc: "True if the connection is TCP, false if it is UDP", writable: false },
                { name: "server_ip", doc: "The protected service's address", writable: false },
                { name: "server_port", doc: "The protected service's port", writable: false },
                { name: "src_ip", doc: "Where this chunk came from", writable: false },
                { name: "src_port", doc: "The port this chunk came from", writable: false },
            ],
        },
        {
            name: "HttpRequest", protocols: ["http"],
            doc: "The current HTTP request, once its headers have been parsed.",
            members: [
                { name: "body", doc: "The request body, when it is complete", writable: false },
                { name: "get_header", doc: "One header by name", writable: false, signature: "get_header(name)" },
                { name: "headers", doc: "Every header of the request", writable: false },
                { name: "method", doc: "The request method", writable: false },
                { name: "url", doc: "The request target", writable: false },
            ],
        },
        {
            name: "TCPInputStream", protocols: ["http", "tcp"],
            doc: "The assembled client-to-service stream. A filter using it is only called for incoming data.",
            members: [
                { name: "data", doc: "The entire input-direction stream assembled so far", writable: false },
                { name: "is_ipv6", doc: "True if the connection is IPv6", writable: false },
                { name: "total_stream_size", doc: "Size of that stream", writable: false },
            ],
        },
    ],
    verdicts: [
        { name: "ACCEPT", value: 0, doc: "Forward this chunk. Returning None means the same thing.", values: [] },
        { name: "REJECT", value: 2, doc: "Refuse the connection. Everything still in the stream goes with it.", values: [] },
        { name: "DROP", value: 1, doc: "Silently drop this chunk and every one after it, without closing.", values: [] },
        { name: "UNSTABLE_MANGLE", value: 3, doc: "Forward the payload you assigned to `data`.", values: [] },
    ],
    settings: [
        { name: "FGEX_STREAM_MAX_SIZE", doc: "Bytes of one stream a model may accumulate.", values: [] },
        { name: "FGEX_FULL_STREAM_ACTION", doc: "What happens when a stream reaches that size.",
          values: ["FullStreamAction.FLUSH", "FullStreamAction.ACCEPT", "FullStreamAction.REJECT", "FullStreamAction.DROP"] },
        { name: "FGEX_INVALID_ENCODING_ACTION", doc: "What happens when a parser cannot read the traffic.",
          values: ["ExceptionAction.ACCEPT", "ExceptionAction.DROP", "ExceptionAction.REJECT", "ExceptionAction.NOACTION"] },
    ],
}

// ------------------------------------------------------------------ seed state

const svcShop = uuid(), svcScore = uuid(), svcVault = uuid(), svcArena = uuid()
const fltShopRegex = uuid(), fltShopPy = uuid(), fltScoreRegex = uuid(), fltVaultRegex = uuid()
const fltArenaRegex = uuid()
const svcWeb = uuid()
const fltWebPy = uuid()
const svcHijack = uuid()

/** The demo's services have been up for a while; a fresh one starts filtering now. */
const demoStart = Math.floor(Date.now() / 1000) - 6 * 60 * 60

const state = {
    interfaces: [
        { name: "lo", addr: "127.0.0.1" },
        { name: "eth0", addr: "10.60.3.1" },
        { name: "eth0", addr: "fd66:666:3::1" },
        { name: "wg0", addr: "10.10.0.3" },
    ],
    // One shape for every service: a network layer, and a chain of filters on it.
    services: [
        { service_id: svcShop, name: "shop-api", status: "active", proto: "tcp", transport: "proxy", fail_open: true, max_connections: 0, over_limit_forwards: false, first_byte_timeout: 0, over_limit_hits: 0, over_limit_first: null, over_limit_last: null, filtering_since: demoStart },
        { service_id: svcScore, name: "scoreboard", status: "active", proto: "tcp", transport: "nfqueue", fail_open: true, max_connections: 512, over_limit_forwards: false, first_byte_timeout: 0, over_limit_hits: 1847, over_limit_first: demoStart, over_limit_last: demoStart + 900, filtering_since: demoStart },
        { service_id: svcVault, name: "vault", status: "stop", proto: "tls", transport: "proxy", fail_open: true, max_connections: 0, over_limit_forwards: false, first_byte_timeout: 0, over_limit_hits: 0, over_limit_first: null, over_limit_last: null, filtering_since: null },
        // QUIC: UDP on the wire, terminated here because nothing else can see inside it.
        // Its filters are written against HTTP because its traffic is HTTP/3, which the
        // engine shows the chain as the HTTP/1.1 it would have been.
        { service_id: svcArena, name: "arena-h3", status: "active", proto: "quic", transport: "proxy", fail_open: true, max_connections: 0, over_limit_forwards: false, first_byte_timeout: 0, over_limit_hits: 0, over_limit_first: null, over_limit_last: null, filtering_since: demoStart },
        // One service for every version of HTTP: HTTP/1.1 and HTTP/2 on the TCP
        // addresses, in the clear on one port and under TLS on the other, and HTTP/3 on
        // the UDP one beside them. One certificate and one chain — which is the whole
        // point, because covering the three used to take two or three services with the
        // same filter copied between them by hand.
        { service_id: svcWeb, name: "shop-web", status: "active", proto: "http", transport: "proxy", fail_open: true, max_connections: 0, over_limit_forwards: false, first_byte_timeout: 0, over_limit_hits: 0, over_limit_first: null, over_limit_last: null, filtering_since: demoStart },
        // Handed to a proxy the operator wrote themselves: firegex steers, nothing here inspects.
        { service_id: svcHijack, name: "legacy-ftp", status: "active", proto: "tcp", transport: "external", fail_open: true, max_connections: 0, over_limit_forwards: false, first_byte_timeout: 0, over_limit_hits: 0, over_limit_first: null, over_limit_last: null, filtering_since: demoStart },
    ] as Json[],
    // Where each one is reachable. shop-api answers on both stacks behind one chain,
    // which is the case that used to need two services kept in step by hand — and on
    // `wg0` by name, the other half of the same idea: an address somebody else hands
    // out is still one place this service answers.
    addresses: [
        { address_id: uuid(), service_id: svcShop, ip_int: "10.60.3.1/32", port: 9000, proto: "tcp", edge: "tcp", target_port: null, upstream: "same", proxy_ip: null, proxy_port: null },
        { address_id: uuid(), service_id: svcShop, ip_int: "fd66:666:3::1/128", port: 9000, proto: "tcp", edge: "tcp", target_port: null, upstream: "same", proxy_ip: null, proxy_port: null },
        { address_id: uuid(), service_id: svcShop, ip_int: "wg0", port: 9000, proto: "tcp", edge: "tcp", target_port: null, upstream: "same", proxy_ip: null, proxy_port: null },
        { address_id: uuid(), service_id: svcScore, ip_int: "10.60.0.0/16", port: 8080, proto: "tcp", edge: "tcp", target_port: null, upstream: "same", proxy_ip: null, proxy_port: null },
        { address_id: uuid(), service_id: svcVault, ip_int: "10.60.3.1", port: 8443, proto: "tcp", edge: "tls", target_port: null, upstream: "same", proxy_ip: null, proxy_port: null },
        // `udp`, because that is what the kernel matches for a QUIC service.
        { address_id: uuid(), service_id: svcArena, ip_int: "10.60.3.1", port: 4433, proto: "udp", edge: "quic", target_port: null, upstream: "same", proxy_ip: null, proxy_port: null },
        // The three edges of one HTTP service, and what they say: in the clear on :80,
        // TLS on :443, HTTP/3 on :443/udp. The last two are *publications* — the service
        // itself only ever answered HTTP/1.1 on :80, and has not moved.
        { address_id: uuid(), service_id: svcWeb, ip_int: "10.60.3.1", port: 80, proto: "tcp", edge: "tcp", target_port: null, upstream: "same", proxy_ip: null, proxy_port: null },
        { address_id: uuid(), service_id: svcWeb, ip_int: "10.60.3.1", port: 443, proto: "tcp", edge: "tls", target_port: 80, upstream: "tcp", proxy_ip: null, proxy_port: null },
        { address_id: uuid(), service_id: svcWeb, ip_int: "10.60.3.1", port: 443, proto: "udp", edge: "quic", target_port: 80, upstream: "tcp", proxy_ip: null, proxy_port: null },
        { address_id: uuid(), service_id: svcHijack, ip_int: "10.60.3.1", port: 21, proto: "tcp", edge: "tcp", target_port: null, upstream: "same", proxy_ip: "127.0.0.1", proxy_port: 12021 },
    ] as Json[],
    filters: [
        // shop-api shows what only the proxy layer can do: two kinds, in an order.
        { filter_id: fltShopRegex, service_id: svcShop, position: 0, kind: "regex", proto: "tcp", name: "patterns", active: true, blocked: 368 },
        // `http` because its code asks for an HttpRequest, not because anybody said so.
        { filter_id: fltShopPy, service_id: svcShop, position: 1, kind: "pyfilter", proto: "http", name: "python", active: true, blocked: 641 },
        { filter_id: fltScoreRegex, service_id: svcScore, position: 0, kind: "regex", proto: "tcp", name: "patterns", active: true, blocked: 1204 },
        { filter_id: fltVaultRegex, service_id: svcVault, position: 0, kind: "regex", proto: "tcp", name: "patterns", active: true, blocked: 0 },
        { filter_id: fltArenaRegex, service_id: svcArena, position: 0, kind: "regex", proto: "tcp", name: "patterns", active: true, blocked: 52 },
        // The same file that would run on a plain HTTP/1.1 service, unchanged — which is
        // the point of an `http` service: HTTP/1.1, HTTP/2 and HTTP/3 are all shown to it
        // as the same HTTP/1.1, so one filter covers the three edges below.
        { filter_id: fltWebPy, service_id: svcWeb, position: 0, kind: "pyfilter", proto: "http", name: "python", active: true, blocked: 1190 },
    ] as Json[],
    regexes: [
        { regex_id: uuid(), filter_id: fltShopRegex, regex: b64("\\.\\./"), mode: "C", case_sensitive: true, active: true, blocked: 341 },
        { regex_id: uuid(), filter_id: fltShopRegex, regex: b64("FLAG\\{[A-Za-z0-9_]+\\}"), mode: "S", case_sensitive: true, active: true, blocked: 27 },
        // A rewriting rule, so the demo shows what only the proxy layer can do.
        { regex_id: uuid(), filter_id: fltScoreRegex, regex: b64("/etc/passwd"), mode: "C", case_sensitive: true, active: true, blocked: 914 },
        { regex_id: uuid(), filter_id: fltScoreRegex, regex: b64("<script>"), mode: "C", case_sensitive: false, active: true, blocked: 233 },
        { regex_id: uuid(), filter_id: fltScoreRegex, regex: b64("[A-Z0-9]{31}="), mode: "S", case_sensitive: true, active: false, blocked: 57 },
        { regex_id: uuid(), filter_id: fltVaultRegex, regex: b64("/proc/self/"), mode: "C", case_sensitive: true, active: true, blocked: 0 },
        // Written the way it would be for an HTTP service on TCP, because that is what
        // the chain is shown: on the wire this path was a QPACK-compressed header block.
        { regex_id: uuid(), filter_id: fltArenaRegex, regex: b64("GET /internal/"), mode: "C", case_sensitive: true, active: true, blocked: 52 },
    ] as Json[],
    code: { [fltShopPy]: SAMPLE_FILTER, [fltWebPy]: SAMPLE_FILTER } as Record<string, string>,
    // One row per @pyfilter the code defines. The code says which exist; these say
    // which run — exactly the split the real backend keeps.
    functions: [
        { filter_id: fltShopPy, name: "block_path_traversal", active: true, blocked: 641 },
        { filter_id: fltWebPy, name: "block_path_traversal", active: true, blocked: 1190 },
        { filter_id: fltShopPy, name: "redact_flag", active: true, blocked: 0 },
        // Switched off rather than deleted: the code is still there to turn back on.
        { filter_id: fltShopPy, name: "log_client", active: false, blocked: 0 },
    ] as Json[],
    certs: { [svcVault]: DEMO_CERT, [svcArena]: DEMO_CERT } as Record<string, string>,
    firewall: {
        enabled: true,
        policy: "accept",
        rules: [
            { active: true, name: "allow team vpn", proto: "any", src: "10.10.0.0/16", dst: "", port_src_from: 0, port_dst_from: 0, port_src_to: 0, port_dst_to: 0, action: "accept", mode: "in", table: "filter" },
            { active: true, name: "drop ssh from outside", proto: "tcp", src: "0.0.0.0/0", dst: "", port_src_from: 0, port_dst_from: 22, port_src_to: 0, port_dst_to: 22, action: "drop", mode: "in", table: "filter" },
            { active: false, name: "reject smtp egress", proto: "tcp", src: "", dst: "0.0.0.0/0", port_src_from: 0, port_dst_from: 25, port_src_to: 0, port_dst_to: 25, action: "reject", mode: "out", table: "filter" },
        ] as Json[],
        settings: {
            keep_rules: false, allow_loopback: true, allow_established: true, allow_icmp: true,
            multicast_dns: false, allow_upnp: false, drop_invalid: true, allow_dhcp: true,
        } as Json,
    },
}

// --------------------------------------------------------------- update events
// Mirrors the backend's single "update" socket.io event: the payload is a react-query
// key prefix, and App.tsx invalidates every query starting with it.

type Listener = (payload: any) => void
const listeners: Record<string, Listener[]> = {}

// The live log, mirroring the backend's bounded per-service tail.
const logs: Record<string, Json[]> = {}
let logSeq = 0

const addLog = (service_id: string, level: string, text: string) => {
    const entry = { at: Date.now(), level, text, seq: ++logSeq }
    logs[service_id] = [...(logs[service_id] ?? []), entry].slice(-500)
    for (const cb of listeners["log"] ?? []) cb({ service_id, entries: [entry] })
}
let ticker: ReturnType<typeof setInterval> | null = null

const emit = (...tags: string[][]) => {
    for (const tag of tags) for (const cb of listeners["update"] ?? []) cb(tag)
}

/** Nudges the counters of everything that is running, so the demo looks alive. */
const startTicker = () => {
    if (ticker) return
    ticker = setInterval(() => {
        let changed = false
        const running = new Set(state.services.filter(s => s.status === "active").map(s => s.service_id))
        for (const f of state.filters) {
            if (!f.active || !running.has(f.service_id)) continue
            if (Math.random() < 0.4) {
                f.blocked += 1
                changed = true
                addLog(f.service_id, "block", `connection refused by ${f.name}`)
            }
        }
        for (const r of state.regexes) {
            const parent = state.filters.find(f => f.filter_id === r.filter_id)
            if (!r.active || !parent?.active || !running.has(parent.service_id)) continue
            if (Math.random() < 0.3) { r.blocked += 1; changed = true }
        }
        if (changed) emit(["services"])
    }, 4000)
}

let welcomed = false
const welcome = () => {
    if (welcomed) return
    welcomed = true
    // Imported lazily so this module stays free of top-level side effects.
    import("@mantine/notifications").then(({ showNotification }) => showNotification({
        title: "This is a demo",
        message: "Everything here is fake data running in your browser - no firewall is attached. " +
                 "Create, start and stop whatever you like; a reload puts it all back.",
        color: "cyan",
        autoClose: 8000,
    }))
}

export const demoSocket = {
    auth: {} as Json,
    connected: false,
    connect() {
        this.connected = true
        startTicker()
        welcome()
        for (const cb of listeners["connect"] ?? []) cb([])
    },
    disconnect() { this.connected = false },
    on(event: string, cb: Listener) { (listeners[event] ??= []).push(cb) },
    off(event: string) { delete listeners[event] },
    emit() { /* the real client sends nothing the demo needs to act on */ },
}

// -------------------------------------------------------------------- handlers

const ok = { status: "ok" }
const notFound = (what: string) => { throw `${what} not found` }

const service = (id: string) => state.services.find(s => s.service_id === id) ?? notFound("Service")
const filter = (sid: string, fid: string) =>
    state.filters.find(f => f.filter_id === fid && f.service_id === sid) ?? notFound("Filter")

const chainOf = (sid: string) =>
    state.filters.filter(f => f.service_id === sid).sort((a, b) => a.position - b.position)

const addressesOf = (sid: string) => state.addresses.filter(a => a.service_id === sid)

/** The backend's `_note_filtering`: the first moment a service could refuse something —
 *  running, with an active filter — written once and never moved. */
const noteFiltering = (sid: string) => {
    const srv = service(sid)
    if (srv.filtering_since != null) return
    if (srv.status !== "active") return
    if (!chainOf(sid).some(f => f.active)) return
    // Aligned to its bucket, like the backend: the mark names the first minute that
    // can hold one of this service's blocks.
    srv.filtering_since = Math.floor(Date.now() / 1000 / 60) * 60
}

const decorate = (s: Json) => ({
    ...s,
    // The material itself never leaves the backend; only whether there is any.
    has_tls_material: !!state.certs[s.service_id],
    addresses: addressesOf(s.service_id),
    n_filters: state.filters.filter(f => f.service_id === s.service_id).length,
    n_blocked: state.filters.filter(f => f.service_id === s.service_id).reduce((acc, f) => acc + f.blocked, 0),
})

/**
 * The demo cannot run hyperscan, so the tester falls back to JavaScript's own engine.
 *
 * That is a real difference and worth saying out loud: against a live instance the
 * tester runs the very engine that will enforce the answer, which is the whole reason
 * it is trustworthy. Here it can only approximate, so a pattern JavaScript accepts and
 * hyperscan does not will look fine in the demo and be refused on a real install.
 */
const demoDebug = (patterns: Json[], sample: string) => {
    let text = ""
    try { text = atob(sample) } catch { text = "" }
    const matches: Json[] = []
    const errors: Json[] = []
    for (const p of patterns) {
        let re: RegExp
        try {
            re = new RegExp(p.expr, p.case_sensitive ? "g" : "gi")
        } catch (err) {
            errors.push({ id: p.id, error: `${err}` })
            continue
        }
        for (const hit of text.matchAll(re)) {
            if (hit.index === undefined) continue
            matches.push({ id: p.id, start: hit.index, end: hit.index + hit[0].length })
            if (hit[0].length === 0) break // a zero-width match would never advance
            if (matches.length >= 1000) break
        }
    }
    return {
        matches, errors, error: null, unscannable: [],
        truncated: matches.length >= 1000,
    }
}

type Handler = (m: RegExpMatchArray, body: Json, query: Record<string, string>) => any
const routes: [string, RegExp, Handler][] = [

    // ---- global
    ["GET", /^status$/, () => ({ status: "run", loggined: true, version: "demo", auth_disabled: false })],
    ["POST", /^login$/, () => ({ access_token: "demo-token", token_type: "bearer" })],
    ["POST", /^set-password$/, () => ok],
    ["POST", /^change-password$/, () => ({ ...ok, access_token: "demo-token" })],
    // The demo has no authentication to turn off, and saying so is more use than
    // pretending it worked on a page anyone can open.
    ["POST", /^auth-mode$/, () => { throw "The demo has no authentication to turn off" }],
    ["GET", /^interfaces$/, () => state.interfaces],
    ["POST", /^reset$/, () => { emit(["services"], ["firewall"]); return ok }],
    ["GET", /^export$/, () => ({ "firegex.db": { keys_values: [] }, note: "demo export - not a real backup" })],
    ["POST", /^import$/, () => { emit(["services"], ["firewall"]); return ok }],

    // ---- services: the network layer
    ["GET", /^services$/, () => state.services.map(decorate)],
    ["POST", /^services$/, (_m, b) => {
        const service_id = uuid()
        state.services.push({
            service_id, name: b.name, status: "stop", proto: b.proto ?? "tcp",
            transport: b.transport ?? "proxy",
            fail_open: b.fail_open ?? true,
            max_connections: b.max_connections ?? 0,
            over_limit_forwards: b.over_limit_forwards ?? false,
            first_byte_timeout: b.first_byte_timeout ?? 0,
            over_limit_hits: 0, over_limit_first: null, over_limit_last: null,
        })
        for (const a of (b.addresses ?? [])) {
            state.addresses.push({
                address_id: uuid(), service_id, ip_int: a.ip_int, port: a.port,
                proto: b.proto === "http" ? (a.edge === "quic" ? "udp" : "tcp")
                    : b.proto === "quic" ? "udp" : b.proto === "udp" ? "udp" : "tcp",
                edge: b.proto === "http" ? (a.edge ?? "tcp") : (b.proto ?? "tcp"),
                target_port: a.target_port ?? null,
                upstream: a.upstream ?? "same",
                proxy_ip: a.proxy_ip ?? null, proxy_port: a.proxy_port ?? null,
            })
        }
        if (b.tls_cert) state.certs[service_id] = b.tls_cert
        emit(["services"])
        return { status: "ok", service_id }
    }],
    ["GET", /^services\/([^/]+)$/, m => decorate(service(m[1]))],
    ["PUT", /^services\/([^/]+)$/, (m, b) => {
        const srv = service(m[1])
        // The state the edit lands on is what has to hold: turning TLS on for a service
        // that has never been given a certificate is refused here as it is by the real
        // backend, rather than by nginx on a later start.
        const landsOnTls = (b.proto ?? srv.proto) === "tls"
        if (landsOnTls && !b.tls_cert && !state.certs[srv.service_id])
            throw "A service that speaks TLS needs a certificate and a private key."
        for (const key of ["name", "proto", "transport", "fail_open",
                           "max_connections", "over_limit_forwards",
                           "first_byte_timeout"]) {
            if (b[key] !== undefined && b[key] !== null) srv[key] = b[key]
        }
        // The addresses carry it too, so `(ip, port, proto)` stays a usable key.
        if (b.proto) for (const a of addressesOf(srv.service_id)) a.proto = b.proto
        if (b.tls_cert) state.certs[srv.service_id] = b.tls_cert
        emit(["services"]); return ok
    }],
    ["DELETE", /^services\/([^/]+)$/, m => {
        const srv = service(m[1])
        for (const f of chainOf(srv.service_id)) {
            state.regexes = state.regexes.filter(r => r.filter_id !== f.filter_id)
            delete state.code[f.filter_id]
        }
        state.filters = state.filters.filter(f => f.service_id !== srv.service_id)
        state.addresses = state.addresses.filter(a => a.service_id !== srv.service_id)
        state.services = state.services.filter(s => s.service_id !== srv.service_id)
        emit(["services"]); return ok
    }],

    // ---- services: where they are reachable
    ["GET", /^services\/([^/]+)\/addresses$/, m => { service(m[1]); return addressesOf(m[1]) }],
    ["POST", /^services\/([^/]+)\/addresses$/, (m, b) => {
        const srv = service(m[1])
        if (srv.transport === "external" && !b.proxy_port) {
            throw "This service hands its traffic to your own proxy, so the new address " +
                  "needs the port that proxy listens on for it"
        }
        if (state.addresses.some(a => a.ip_int === b.ip_int && a.port === b.port && a.proto === srv.proto))
            throw "one of these addresses is already protected by a service"
        state.addresses.push({
            address_id: uuid(), service_id: srv.service_id, ip_int: b.ip_int, port: b.port,
            proto: srv.proto, proxy_ip: b.proxy_ip ?? null, proxy_port: b.proxy_port ?? null,
        })
        addLog(srv.service_id, "info",
            `also protecting ${b.ip_int}:${b.port} (no connection was dropped)`)
        emit(["services"]); return ok
    }],
    ["PUT", /^services\/([^/]+)\/addresses\/([^/]+)$/, (m, b) => {
        service(m[1])
        const addr = state.addresses.find(a => a.address_id === m[2] && a.service_id === m[1])
            ?? notFound("Address")
        addr.ip_int = b.ip_int; addr.port = b.port
        addr.proxy_ip = b.proxy_ip ?? null; addr.proxy_port = b.proxy_port ?? null
        emit(["services"]); return ok
    }],
    ["DELETE", /^services\/([^/]+)\/addresses\/([^/]+)$/, m => {
        service(m[1])
        if (addressesOf(m[1]).length === 1)
            throw "This is the only address this service protects. Delete the service " +
                  "itself, or add another address first."
        state.addresses = state.addresses.filter(a => a.address_id !== m[2])
        emit(["services"]); return ok
    }],
    ["POST", /^services\/([^/]+)\/start$/, m => {
        const srv = service(m[1])
        // The same refusal a real instance gives, for the same reason: the NFQUEUE
        // binaries are the filter, so they cannot host a chain.
        const active = chainOf(srv.service_id).filter(f => f.active)
        if (srv.transport === "external" && active.length > 0) {
            throw `this service hands its traffic to your own proxy, so firegex inspects ` +
                  `nothing and the ${active.length} filter(s) attached to it would never run.`
        }
        if (srv.transport === "nfqueue" && active.length > 8) {
            throw `the nfqueue transport chains at most 8 filters, and this service has ` +
                  `${active.length} active. Deactivate some, or move it to the proxy ` +
                  `transport, which walks the chain inside one process.`
        }
        srv.status = "active"
        noteFiltering(srv.service_id)
        addLog(srv.service_id,
            "info",
            `started on the ${srv.transport} layer, ${active.length} filter(s) active`)
        emit(["services"]); return ok
    }],
    ["POST", /^services\/([^/]+)\/stop$/, m => {
        const srv = service(m[1])
        srv.status = "stop"
        addLog(srv.service_id, "info", "stopped")
        emit(["services"]); return ok
    }],
    ["GET", /^services\/([^/]+)\/stats$/, (m, _b, query) => {
        service(m[1])
        const chain = chainOf(m[1])
        // The real instant, not the bucket it falls in — the same reason the backend
        // stopped truncating it: the current, partial minute would otherwise be
        // reported as ending at the moment it began.
        const now = Math.floor(Date.now() / 1000)
        const keptFrom = now - 48 * 60 * 60
        const began = service(m[1]).filtering_since as number | null
        const to = Math.min(Number(query?.range_to) || now, now)
        // Two floors, like the backend: what is still kept, and when this service first
        // became able to refuse anything — hours before it existed are not quiet hours.
        // The second one applies only to a window that reaches into its life; one that
        // ended before it began is answered as asked, and is empty because it is.
        const from = Math.max(Number(query?.range_from) || to - 3600, keptFrom,
            began !== null && to >= began ? began : keptFrom)
        // The bucket widens with the range, exactly as the backend does it, so the demo
        // shows the same handful of bars whatever window is picked — unless a step was
        // asked for, which wins until it would draw more bars than a chart can carry.
        const span = Math.max(60, to - from + 60)
        const want = Number(query?.step) || 0
        const least = Math.ceil(span / 60 / 400)
        const width = 60 * Math.max(1, least, want
            ? Math.round(want / 60)
            : Math.ceil(span / 60 / 60))
        const first = Math.floor(from / width) * width
        const buckets: number[] = []
        for (let edge = first; edge <= to; edge += width) buckets.push(edge)

        // A plausible shape rather than a real history, scaled to the window so the
        // numbers move when the range does.
        const fraction = Math.min(1, (to - from) / (48 * 60 * 60))
        const scaled: Json[] = chain.map(f => ({
            ...f, ranged: Math.round(f.blocked * (0.15 + 0.85 * fraction)),
        }))
        const total = scaled.reduce((acc, f) => acc + f.ranged, 0)
        const shared = (rows: Json[]) => rows.map(r => ({
            ...r, share: total ? Math.round((1000 * r.blocked) / total) / 10 : 0,
        }))
        const spread = (amount: number, seed: number) => {
            const raw = buckets.map((_, i) => Math.abs(Math.sin((i + seed) / 5)) + 0.05)
            const sum = raw.reduce((a, b) => a + b, 0)
            return raw.map(v => Math.round((v / sum) * amount))
        }
        const busy = scaled.filter(f => f.ranged > 0)
        const patterns = state.regexes
            .filter(r => chain.some(f => f.filter_id === r.filter_id))
            .map(r => ({
                id: r.regex_id, name: atob(r.regex), kind: "regex",
                filter_id: r.filter_id,
                blocked: Math.round(r.blocked * (0.15 + 0.85 * fraction)),
            }))
        const functions = state.functions
            .filter(fn => chain.some(f => f.filter_id === fn.filter_id))
            .map(fn => ({
                id: `${fn.filter_id}/${fn.name}`, name: fn.name, kind: "pyfilter",
                filter_id: fn.filter_id,
                blocked: Math.round(fn.blocked * (0.15 + 0.85 * fraction)),
            }))
        const srv = service(m[1])
        // A proxy service counts connections, which is the unit a block is in, so its
        // refused share is exact; the nfqueue layer works per packet and reports none.
        const connections = srv.transport === "proxy" ? 30118 : null
        return {
            filters: shared(scaled.map(f => ({
                id: f.filter_id, name: f.name, kind: f.kind,
                blocked: f.ranged, all_time: f.blocked,
            }))),
            patterns: shared(patterns),
            functions: shared(functions),
            buckets,
            bucket_seconds: width,
            series: busy.map(f => ({
                id: f.filter_id, name: f.name, counts: spread(f.ranged, f.blocked),
            })),
            total,
            all_time: chain.reduce((acc, f) => acc + f.blocked, 0),
            range_from: from,
            range_to: to,
            kept_from: keptFrom,
            filtering_since: began,
            traffic: {
                packets: srv.transport === "proxy" ? 0 : 1_284_402,
                bytes: srv.transport === "proxy" ? 0 : 903_118_774,
                connections,
                connections_refused: connections === null ? null : total,
                refused_share: connections === null
                    ? null : Math.round((10000 * total) / connections) / 100,
            },
        }
    }],
    ["GET", /^services\/([^/]+)\/logs$/, m => { service(m[1]); return logs[m[1]] ?? [] }],
    ["DELETE", /^services\/([^/]+)\/logs$/, m => { service(m[1]); logs[m[1]] = []; return ok }],

    // ---- services: the filter chain
    ["GET", /^services\/([^/]+)\/filters$/, m => {
        service(m[1])
        return chainOf(m[1]).map(f => {
            const fns = state.functions.filter(fn => fn.filter_id === f.filter_id)
            return {
                ...f,
                n_regexes: state.regexes.filter(r => r.filter_id === f.filter_id).length,
                n_functions: fns.length,
                n_functions_active: fns.filter(fn => fn.active).length,
            }
        })
    }],

    // ---- services: the functions inside one pyfilter
    ["GET", /^services\/([^/]+)\/filters\/([^/]+)\/functions$/, m => {
        const f = filter(m[1], m[2])
        if (f.kind !== "pyfilter") throw "This filter is not a pyfilter"
        return state.functions.filter(fn => fn.filter_id === m[2])
    }],
    ["PUT", /^services\/([^/]+)\/filters\/([^/]+)\/functions\/([^/]+)$/, (m, b) => {
        filter(m[1], m[2])
        const fn = state.functions.find(
            x => x.filter_id === m[2] && x.name === decodeURIComponent(m[3])
        ) ?? notFound("Function")
        fn.active = b.active
        emit(["services"]); return ok
    }],
    ["POST", /^services\/([^/]+)\/filters$/, (m, b) => {
        service(m[1])
        const filter_id = uuid()
        state.filters.push({
            filter_id, service_id: m[1], position: chainOf(m[1]).length,
            // A new pyfilter asks for nothing yet, so it speaks the simplest protocol
            // there is; saving code is what settles it.
            kind: b.kind, proto: "tcp",
            name: b.name ?? b.kind, active: b.active ?? true, blocked: 0,
        })
        if (b.kind === "pyfilter") state.code[filter_id] = ""
        noteFiltering(m[1])
        emit(["services"]); return ok
    }],
    ["POST", /^services\/([^/]+)\/filters\/order$/, (m, b) => {
        service(m[1])
        const existing = chainOf(m[1]).map(f => f.filter_id).sort()
        if (JSON.stringify(existing) !== JSON.stringify([...(b.filters ?? [])].sort()))
            throw "The order must list exactly the filters this service has"
        b.filters.forEach((id: string, position: number) => {
            const f = state.filters.find(x => x.filter_id === id)
            if (f) f.position = position
        })
        emit(["services"]); return ok
    }],
    ["PUT", /^services\/([^/]+)\/filters\/([^/]+)$/, (m, b) => {
        const f = filter(m[1], m[2])
        if (b.name !== undefined && b.name !== null) f.name = b.name
        if (b.active !== undefined && b.active !== null) f.active = b.active
        emit(["services"]); return ok
    }],
    ["DELETE", /^services\/([^/]+)\/filters\/([^/]+)$/, m => {
        filter(m[1], m[2])
        state.regexes = state.regexes.filter(r => r.filter_id !== m[2])
        state.functions = state.functions.filter(fn => fn.filter_id !== m[2])
        state.filters = state.filters.filter(f => f.filter_id !== m[2])
        delete state.code[m[2]]
        chainOf(m[1]).forEach((f, position) => { f.position = position })
        emit(["services"]); return ok
    }],

    // ---- services: a pyfilter's code
    // The real instance runs the file through the process that will execute it; the
    // demo has no Python, so it approximates just enough to show what the editor does
    // with the answer — and never claims a file is fine when it obviously is not.
    ["POST", /^services\/([^/]+)\/filters\/([^/]+)\/check$/, (m, b) => {
        filter(m[1], m[2])
        const code: string = b.code ?? ""
        const lines = code.split("\n")
        const bad = lines.findIndex(l => /@pyfilter\s*$/.test(l.trim()) === false
            && /^\s*def\s+\w+\s*\([^)]*\)\s*:/.test(l)
            && !/:\s*\w+\s*[,)]/.test(l))
        if (bad >= 0 && /@pyfilter/.test(lines[bad - 1] ?? "")) {
            const name = lines[bad].match(/def\s+(\w+)/)?.[1] ?? "?"
            const param = lines[bad].match(/\(\s*(\w+)/)?.[1] ?? "?"
            return {
                ok: false, filters: [],
                error: {
                    type: "Exception",
                    message: `Parameter '${param}' of ${name} has no type annotation. `
                        + "Annotate it with what the filter wants to be given — RawPacket, "
                        + "a TCP stream, an HTTP model — because that is what decides when "
                        + "it is called.",
                    line: bad + 1, column: 0, text: lines[bad], traceback: "",
                },
            }
        }
        const defined = [...code.matchAll(/@pyfilter\s*\n\s*def\s+([A-Za-z_]\w*)/g)].map(x => x[1])
        const http = /\bHttp(Request|Response|RequestHeader|ResponseHeader|FullRequest|FullResponse|History|StreamHistory)\b/.test(code)
        return { ok: true, proto: http ? "http" : "tcp", filters: defined, error: null }
    }],

    ["GET", /^services\/pyfilter-api$/, () => DEMO_PYFILTER_API],

    ["GET", /^services\/([^/]+)\/filters\/([^/]+)\/code$/, m => {
        filter(m[1], m[2])
        return state.code[m[2]] ?? ""
    }],
    ["PUT", /^services\/([^/]+)\/filters\/([^/]+)\/code$/, (m, b) => {
        const f = filter(m[1], m[2])
        const code: string = b.code ?? ""
        // The real instance asks the library which protocol the file speaks, by looking
        // at what its filters are annotated with. Here that is approximated by the model
        // names the file mentions — enough to demonstrate that it is read, not chosen,
        // and that mixing two application protocols is refused.
        const http = /\bHttp(Request|Response|RequestHeader|ResponseHeader|FullRequest|FullResponse|History|StreamHistory)\b/.test(code)
        state.code[m[2]] = code
        f.proto = http ? "http" : "tcp"
        // Reconciled with the code, like the real backend: a function that has gone is
        // dropped, a new one arrives switched on, and one that survives keeps whatever
        // the operator had set for it.
        const defined = [...code.matchAll(/@pyfilter\s*\n\s*def\s+([A-Za-z_]\w*)/g)].map(x => x[1])
        state.functions = state.functions.filter(
            fn => fn.filter_id !== m[2] || defined.includes(fn.name)
        )
        for (const name of defined) {
            if (!state.functions.some(fn => fn.filter_id === m[2] && fn.name === name))
                state.functions.push({ filter_id: m[2], name, active: true, blocked: 0 })
        }
        emit(["services"]); return ok
    }],

    // ---- services: a regex filter's patterns
    ["GET", /^services\/([^/]+)\/filters\/([^/]+)\/regexes$/, m => {
        filter(m[1], m[2])
        return state.regexes.filter(r => r.filter_id === m[2])
    }],
    ["POST", /^services\/([^/]+)\/filters\/([^/]+)\/regexes$/, (m, b) => {
        const f = filter(m[1], m[2])
        if (f.kind !== "regex") throw "This filter does not hold patterns"
        let expr = ""
        try { expr = atob(b.regex) } catch { throw "The pattern must be base64-encoded" }
        try { new RegExp(expr) } catch (err) { throw `Invalid pattern: ${err}` }
        state.regexes.push({
            regex_id: uuid(), filter_id: m[2], regex: b.regex, mode: b.mode ?? "B",
            case_sensitive: b.case_sensitive ?? true, active: b.active ?? true, blocked: 0,
        })
        emit(["services"]); return ok
    }],
    ["PUT", /^services\/([^/]+)\/filters\/([^/]+)\/regexes\/([^/]+)$/, (m, b) => {
        filter(m[1], m[2])
        const rx = state.regexes.find(r => r.regex_id === m[3]) ?? notFound("Pattern")
        if (b.active !== undefined && b.active !== null) rx.active = b.active
        if (b.regex != null && b.regex !== rx.regex) {
            let expr = ""
            try { expr = atob(b.regex) } catch { throw "The pattern must be base64-encoded" }
            try { new RegExp(expr) } catch (err) { throw `Invalid pattern: ${err}` }
            if (state.regexes.some(r => r.filter_id === m[2] && r.regex_id !== rx.regex_id
                && r.regex === b.regex && r.case_sensitive === (b.case_sensitive ?? rx.case_sensitive)))
                throw "This filter already holds that exact pattern"
            rx.regex = b.regex
            // The counters belonged to the old pattern, so they do not carry over.
            rx.blocked = 0
        }
        if (b.mode != null) rx.mode = b.mode
        if (b.case_sensitive != null) rx.case_sensitive = b.case_sensitive
        emit(["services"]); return ok
    }],
    ["DELETE", /^services\/([^/]+)\/filters\/([^/]+)\/regexes\/([^/]+)$/, m => {
        filter(m[1], m[2])
        state.regexes = state.regexes.filter(r => r.regex_id !== m[3])
        emit(["services"]); return ok
    }],

    // ---- services: the pattern tester
    ["POST", /^services\/debug-regex$/, (_m, b) => demoDebug(b.patterns ?? [], b.sample ?? "")],

    // ---- firewall
    ["GET", /^firewall\/rules$/, () => ({ rules: state.firewall.rules, policy: state.firewall.policy, enabled: state.firewall.enabled })],
    ["POST", /^firewall\/rules$/, (_m, b) => {
        state.firewall.rules = b?.rules ?? []
        if (b?.policy) state.firewall.policy = b.policy
        emit(["firewall"]); return { status: state.firewall.rules.map((_r, i) => ({ status: "ok", rule_id: i })) }
    }],
    ["GET", /^firewall\/settings$/, () => state.firewall.settings],
    ["PUT", /^firewall\/settings$/, (_m, b) => { Object.assign(state.firewall.settings, b); emit(["firewall"]); return ok }],
    ["POST", /^firewall\/(enable|disable)$/, m => { state.firewall.enabled = m[1] === "enable"; emit(["firewall"]); return ok }],

]

/** Same contract as genericapi(): resolves with the parsed body, rejects with a message. */
export async function demoApi(method: string, path: string, body: Json | undefined): Promise<any> {
    const trimmed = path.replace(/^\/+|\/+$/g, "")
    const clean = trimmed.split("?")[0]
    // The query string reaches the handlers too, now that a range is asked for in it.
    const query = Object.fromEntries(new URLSearchParams(trimmed.split("?")[1] ?? ""))
    await new Promise(r => setTimeout(r, 60 + Math.random() * 120)) // a plausible round trip
    for (const [verb, pattern, handler] of routes) {
        if (verb !== method.toUpperCase()) continue
        const match = clean.match(pattern)
        if (match) return handler(match, body ?? {}, query)
    }
    throw `This endpoint is not available in the demo (${method} /api/${clean})`
}
