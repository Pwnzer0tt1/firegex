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

const SAMPLE_FILTER = `from firegex.nfproxy import pyfilter, ACCEPT, REJECT
from firegex.nfproxy.models import HttpRequest


@pyfilter
def block_path_traversal(packet: HttpRequest):
    """Drop any request trying to climb out of the web root."""
    if ".." in packet.url:
        return REJECT
    return ACCEPT


@pyfilter
def strip_debug_header(packet: HttpRequest):
    if "X-Debug" in packet.headers:
        del packet.headers["X-Debug"]
    return ACCEPT
`

// ------------------------------------------------------------------ seed state

const tlsStreamId = uuid()
const svcWeb = uuid(), svcApi = uuid(), svcTls = uuid()
const svcProxy = uuid(), svcQuiz = uuid()
const svcHijack = uuid()

const state = {
    interfaces: [
        { name: "lo", addr: "127.0.0.1" },
        { name: "eth0", addr: "10.60.3.1" },
        { name: "eth0", addr: "fd66:666:3::1" },
    ],
    nfregex: {
        services: [
            { name: "scoreboard", service_id: svcWeb, status: "active", port: 8080, proto: "tcp", ip_int: "10.60.3.1", n_packets: 128437, n_regex: 3, fail_open: true, target_type: "internal", tls_stream_id: null },
            { name: "flag-submitter", service_id: svcApi, status: "active", port: 5000, proto: "tcp", ip_int: "10.60.3.1", n_packets: 41022, n_regex: 1, fail_open: false, target_type: "internal", tls_stream_id: null },
            { name: "vault (behind TLS)", service_id: svcTls, status: "stop", port: 8443, proto: "tcp", ip_int: "10.60.3.1", n_packets: 0, n_regex: 1, fail_open: true, target_type: "tls", tls_stream_id: tlsStreamId },
        ] as Json[],
        regexes: [
            { id: 1, service_id: svcWeb, regex: "L2V0Yy9wYXNzd2Q=", is_case_sensitive: true, mode: "C", n_packets: 914, active: true },
            { id: 2, service_id: svcWeb, regex: "PHNjcmlwdD4=", is_case_sensitive: false, mode: "C", n_packets: 233, active: true },
            { id: 3, service_id: svcWeb, regex: "W0EtWjAtOV17MzF9PQ==", is_case_sensitive: true, mode: "S", n_packets: 57, active: false },
            { id: 4, service_id: svcApi, regex: "dW5pb24Ic2VsZWN0", is_case_sensitive: false, mode: "C", n_packets: 1180, active: true },
            { id: 5, service_id: svcTls, regex: "L3Byb2Mvc2VsZi8=", is_case_sensitive: true, mode: "C", n_packets: 0, active: true },
        ] as Json[],
    },
    nfproxy: {
        services: [
            { service_id: svcProxy, name: "shop-api", status: "active", port: 9000, proto: "tcp", ip_int: "10.60.3.1", n_filters: 2, edited_packets: 3401, blocked_packets: 762, fail_open: true, target_type: "internal", tls_stream_id: null },
            { service_id: svcQuiz, name: "quiz", status: "stop", port: 1337, proto: "tcp", ip_int: "10.60.3.1", n_filters: 2, edited_packets: 0, blocked_packets: 0, fail_open: false, target_type: "internal", tls_stream_id: null },
        ] as Json[],
        pyfilters: [
            { name: "block_path_traversal", service_id: svcProxy, blocked_packets: 641, edited_packets: 0, active: true },
            { name: "strip_debug_header", service_id: svcProxy, blocked_packets: 0, edited_packets: 3401, active: true },
            { name: "block_path_traversal", service_id: svcQuiz, blocked_packets: 0, edited_packets: 0, active: true },
            { name: "strip_debug_header", service_id: svcQuiz, blocked_packets: 0, edited_packets: 0, active: false },
        ] as Json[],
        code: { [svcProxy]: SAMPLE_FILTER, [svcQuiz]: SAMPLE_FILTER } as Record<string, string>,
        tls: {} as Record<string, Json>,
    },
    porthijack: [
        { name: "legacy ftp -> proxy", service_id: svcHijack, active: true, proto: "tcp", ip_src: "10.60.3.1", ip_dst: "127.0.0.1", public_port: 21, proxy_port: 12021 },
    ] as Json[],
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
    tls: [
        { id: tlsStreamId, name: "vault", ip_int: "10.60.3.1", port: 8443, cert: DEMO_CERT, key: "", status: "active", ssl_port: 41337, clear_port: 41338 },
    ] as Json[],
}

// --------------------------------------------------------------- update events
// Mirrors the backend's single "update" socket.io event: the payload is a react-query
// key prefix, and App.tsx invalidates every query starting with it.

type Listener = (payload: string[]) => void
const listeners: Record<string, Listener[]> = {}
let ticker: ReturnType<typeof setInterval> | null = null

const emit = (...tags: string[][]) => {
    for (const tag of tags) for (const cb of listeners["update"] ?? []) cb(tag)
}

/** Nudges the counters of everything that is running, so the demo looks alive. */
const startTicker = () => {
    if (ticker) return
    ticker = setInterval(() => {
        let changed = false
        for (const s of state.nfregex.services) {
            if (s.status !== "active") continue
            s.n_packets += Math.floor(Math.random() * 40)
            changed = true
        }
        for (const r of state.nfregex.regexes) {
            if (r.active && Math.random() < 0.3) r.n_packets += 1
        }
        for (const s of state.nfproxy.services) {
            if (s.status !== "active") continue
            s.edited_packets += Math.floor(Math.random() * 12)
            s.blocked_packets += Math.random() < 0.4 ? 1 : 0
            changed = true
        }
        if (changed) emit(["nfregex"], ["nfproxy"])
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

const nfregexService = (id: string) => state.nfregex.services.find(s => s.service_id === id) ?? notFound("Service")
const nfproxyService = (id: string) => state.nfproxy.services.find(s => s.service_id === id) ?? notFound("Service")
const hijackService = (id: string) => state.porthijack.find(s => s.service_id === id) ?? notFound("Service")
const tlsStream = (id: string) => state.tls.find(s => s.id === id) ?? notFound("Stream")

const countRegexes = (id: string) => state.nfregex.regexes.filter(r => r.service_id === id).length

type Handler = (m: RegExpMatchArray, body: Json) => any
const routes: [string, RegExp, Handler][] = [

    // ---- global
    ["GET", /^status$/, () => ({ status: "run", loggined: true, version: "demo", auth_disabled: false })],
    ["POST", /^login$/, () => ({ access_token: "demo-token", token_type: "bearer" })],
    ["POST", /^set-password$/, () => ok],
    ["POST", /^change-password$/, () => ({ ...ok, access_token: "demo-token" })],
    ["GET", /^interfaces$/, () => state.interfaces],
    ["POST", /^reset$/, () => { emit(["nfregex"], ["nfproxy"], ["porthijack"], ["firewall"], ["tls_streams"]); return ok }],
    ["GET", /^export$/, () => ({ "firegex.db": { keys_values: [] }, note: "demo export - not a real backup" })],
    ["POST", /^import$/, () => { emit(["nfregex"], ["nfproxy"], ["porthijack"], ["firewall"], ["tls_streams"]); return ok }],

    // ---- nfregex
    ["GET", /^nfregex\/services$/, () => state.nfregex.services],
    ["POST", /^nfregex\/services$/, (_m, b) => {
        const service_id = uuid()
        state.nfregex.services.push({ status: "active", n_packets: 0, n_regex: 0, target_type: "internal", tls_stream_id: null, ...b, service_id })
        emit(["nfregex"])
        return { ...ok, service_id }
    }],
    ["GET", /^nfregex\/services\/([^/]+)$/, m => nfregexService(m[1])],
    ["DELETE", /^nfregex\/services\/([^/]+)$/, m => {
        state.nfregex.services = state.nfregex.services.filter(s => s.service_id !== m[1])
        state.nfregex.regexes = state.nfregex.regexes.filter(r => r.service_id !== m[1])
        emit(["nfregex"]); return ok
    }],
    ["POST", /^nfregex\/services\/([^/]+)\/(start|stop)$/, m => {
        nfregexService(m[1]).status = m[2] === "start" ? "active" : "stop"
        emit(["nfregex"]); return ok
    }],
    ["PUT", /^nfregex\/services\/([^/]+)\/rename$/, (m, b) => { nfregexService(m[1]).name = b.name; emit(["nfregex"]); return ok }],
    ["PUT", /^nfregex\/services\/([^/]+)\/settings$/, (m, b) => { Object.assign(nfregexService(m[1]), b); emit(["nfregex"]); return ok }],
    ["PUT", /^nfregex\/services\/([^/]+)\/tls-config$/, () => ok],
    ["GET", /^nfregex\/services\/([^/]+)\/regexes$/, m => state.nfregex.regexes.filter(r => r.service_id === m[1])],
    ["GET", /^nfregex\/services\/([^/]+)\/export$/, m => state.nfregex.regexes.filter(r => r.service_id === m[1])],
    ["POST", /^nfregex\/services\/([^/]+)\/import$/, m => { emit(["nfregex"]); return ok }],
    ["POST", /^nfregex\/regexes$/, (_m, b) => {
        const id = Math.max(0, ...state.nfregex.regexes.map(r => r.id)) + 1
        state.nfregex.regexes.push({ n_packets: 0, active: true, ...b, id })
        nfregexService(b.service_id).n_regex = countRegexes(b.service_id)
        emit(["nfregex"]); return ok
    }],
    ["DELETE", /^nfregex\/regexes\/(\d+)$/, m => {
        const r = state.nfregex.regexes.find(x => x.id === Number(m[1]))
        state.nfregex.regexes = state.nfregex.regexes.filter(x => x.id !== Number(m[1]))
        if (r) nfregexService(r.service_id).n_regex = countRegexes(r.service_id)
        emit(["nfregex"]); return ok
    }],
    ["POST", /^nfregex\/regexes\/(\d+)\/(enable|disable)$/, m => {
        const r = state.nfregex.regexes.find(x => x.id === Number(m[1])) ?? notFound("Regex")
        r.active = m[2] === "enable"
        emit(["nfregex"]); return ok
    }],

    // ---- nfproxy
    ["GET", /^nfproxy\/services$/, () => state.nfproxy.services],
    ["POST", /^nfproxy\/services$/, (_m, b) => {
        const service_id = uuid()
        state.nfproxy.services.push({ status: "stop", n_filters: 0, edited_packets: 0, blocked_packets: 0, target_type: "internal", tls_stream_id: null, ...b, service_id })
        state.nfproxy.code[service_id] = ""
        emit(["nfproxy"]); return { ...ok, service_id }
    }],
    ["GET", /^nfproxy\/services\/([^/]+)$/, m => nfproxyService(m[1])],
    ["DELETE", /^nfproxy\/services\/([^/]+)$/, m => {
        state.nfproxy.services = state.nfproxy.services.filter(s => s.service_id !== m[1])
        state.nfproxy.pyfilters = state.nfproxy.pyfilters.filter(f => f.service_id !== m[1])
        emit(["nfproxy"]); return ok
    }],
    ["POST", /^nfproxy\/services\/([^/]+)\/(start|stop)$/, m => {
        nfproxyService(m[1]).status = m[2] === "start" ? "active" : "stop"
        emit(["nfproxy"]); return ok
    }],
    ["PUT", /^nfproxy\/services\/([^/]+)\/rename$/, (m, b) => { nfproxyService(m[1]).name = b.name; emit(["nfproxy"]); return ok }],
    ["PUT", /^nfproxy\/services\/([^/]+)\/settings$/, (m, b) => { Object.assign(nfproxyService(m[1]), b); emit(["nfproxy"]); return ok }],
    ["PUT", /^nfproxy\/services\/([^/]+)\/tls-config$/, () => ok],
    ["GET", /^nfproxy\/services\/([^/]+)\/tls-config$/, () => ({ tls_enabled: false, tls_cert: null, tls_key: null })],
    ["GET", /^nfproxy\/services\/([^/]+)\/pyfilters$/, m => state.nfproxy.pyfilters.filter(f => f.service_id === m[1])],
    ["GET", /^nfproxy\/services\/([^/]+)\/code$/, m => ({ code: state.nfproxy.code[m[1]] ?? "" })],
    ["POST", /^nfproxy\/services\/([^/]+)\/code$/, (m, b) => {
        state.nfproxy.code[m[1]] = b?.code ?? ""
        emit(["nfproxy"]); return ok
    }],
    ["POST", /^nfproxy\/services\/([^/]+)\/pyfilters\/([^/]+)\/(enable|disable)$/, m => {
        const f = state.nfproxy.pyfilters.find(x => x.service_id === m[1] && x.name === m[2]) ?? notFound("Filter")
        f.active = m[3] === "enable"
        emit(["nfproxy"]); return ok
    }],

    // ---- porthijack
    ["GET", /^porthijack\/services$/, () => state.porthijack],
    ["POST", /^porthijack\/services$/, (_m, b) => {
        const service_id = uuid()
        state.porthijack.push({ active: false, ...b, service_id })
        emit(["porthijack"]); return { ...ok, service_id }
    }],
    ["GET", /^porthijack\/services\/([^/]+)$/, m => hijackService(m[1])],
    ["DELETE", /^porthijack\/services\/([^/]+)$/, m => {
        state.porthijack = state.porthijack.filter(s => s.service_id !== m[1])
        emit(["porthijack"]); return ok
    }],
    ["POST", /^porthijack\/services\/([^/]+)\/(start|stop)$/, m => {
        hijackService(m[1]).active = m[2] === "start"
        emit(["porthijack"]); return ok
    }],
    ["PUT", /^porthijack\/services\/([^/]+)\/rename$/, (m, b) => { hijackService(m[1]).name = b.name; emit(["porthijack"]); return ok }],
    ["PUT", /^porthijack\/services\/([^/]+)\/change-destination$/, (m, b) => { Object.assign(hijackService(m[1]), b); emit(["porthijack"]); return ok }],

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

    // ---- tls decrypt
    ["GET", /^tls\/streams$/, () => state.tls],
    ["POST", /^tls\/streams$/, (_m, b) => {
        const id = uuid()
        // The real backend derives both loopback ports from a hash of ip:port.
        const h = Math.abs([...`${b.ip_int}:${b.port}`].reduce((a, c) => a * 31 + c.charCodeAt(0) | 0, 7))
        state.tls.push({ status: "active", ssl_port: 40000 + (h % 10000), clear_port: 40001 + (h % 10000), ...b, id })
        emit(["tls_streams"]); return { ...ok, id }
    }],
    ["PUT", /^tls\/streams\/([^/]+)$/, (m, b) => { Object.assign(tlsStream(m[1]), b); emit(["tls_streams"]); return ok }],
    ["DELETE", /^tls\/streams\/([^/]+)$/, m => {
        if (state.nfregex.services.some(s => s.tls_stream_id === m[1]) || state.nfproxy.services.some(s => s.tls_stream_id === m[1]))
            throw "Stream is still used by a service"
        state.tls = state.tls.filter(s => s.id !== m[1])
        emit(["tls_streams"]); return ok
    }],
    ["POST", /^tls\/streams\/([^/]+)\/(start|stop)$/, m => {
        const stream = tlsStream(m[1])
        stream.status = m[2] === "start" ? "active" : "stop"
        // Stopping a stream cascades to the filter services attached to it.
        if (m[2] === "stop") {
            for (const s of state.nfregex.services) if (s.tls_stream_id === m[1]) s.status = "stop"
            for (const s of state.nfproxy.services) if (s.tls_stream_id === m[1]) s.status = "stop"
        }
        emit(["tls_streams"], ["nfregex"], ["nfproxy"]); return ok
    }],
]

/** Same contract as genericapi(): resolves with the parsed body, rejects with a message. */
export async function demoApi(method: string, path: string, body: Json | undefined): Promise<any> {
    const clean = path.replace(/^\/+|\/+$/g, "").split("?")[0]
    await new Promise(r => setTimeout(r, 60 + Math.random() * 120)) // a plausible round trip
    for (const [verb, pattern, handler] of routes) {
        if (verb !== method.toUpperCase()) continue
        const match = clean.match(pattern)
        if (match) return handler(match, body ?? {})
    }
    throw `This endpoint is not available in the demo (${method} /api/${clean})`
}
