import { useQuery } from "@tanstack/react-query"
import { ServerResponse } from "../../js/models"
import { deleteapi, getapi, postapi, putapi } from "../../js/utils"

/** How a service's traffic is intercepted. Independent of what filters it runs. */
export enum Transport {
    /** Packets queued to userspace, verdict handed back. Nothing is terminated. */
    NFQUEUE = "nfqueue",
    /** The connection is terminated and reopened towards the service. */
    PROXY = "proxy",
    /**
     * The traffic is handed to a proxy the operator runs themselves. Firegex inspects
     * nothing — it only arranges for their proxy to be in the path — so no filter can
     * be attached.
     */
    EXTERNAL = "external",
}

/** What a filter is. */
export enum FilterKind {
    /** Patterns matched by hyperscan — the same engine on either transport. */
    REGEX = "regex",
    /** The user's own Python, running out of process. */
    PYFILTER = "pyfilter",
}

/**
 * Which application protocol a Python filter speaks.
 *
 * Never chosen — read off the code when it is saved. The library decides when a filter
 * is called from what its parameters are annotated with, so asking for an `HttpRequest`
 * is what makes a file an HTTP filter and asking only for a `RawPacket` is what makes
 * one run on anything. Shown here, never set.
 */
export enum FilterProto {
    TCP = "tcp",
    HTTP = "http",
}

/**
 * What a service speaks on the wire.
 *
 * `TLS` sits beside the other two rather than being a switch on top of one, because that
 * is the shape of the thing. As a boolean it made three combinations expressible that
 * are not real — TLS on a UDP service, on the NFQUEUE layer, and on a hand-off — each of
 * which had to be caught and explained after the fact.
 */
export enum L4 {
    TCP = "tcp",
    UDP = "udp",
    /** TLS over TCP, decrypted by the engine. Only on the proxy layer. */
    TLS = "tls",
}

/** Whether a service's traffic is decrypted before the filters see it. */
export const decrypts = (service: { proto: string }) => service.proto === L4.TLS

/**
 * Whether a network layer can carry a protocol at all.
 *
 * One fact, read by both controls that depend on it: the protocol picker hides what the
 * chosen layer cannot carry, and the layer picker disables what cannot carry the chosen
 * protocol. Written twice, the two would drift and the form would offer a combination
 * the backend refuses — which it does refuse, in `Transport.check()`, and being told no
 * after filling in a form is a worse way to learn it.
 *
 * Only TLS constrains anything today: decrypting means terminating the connection, which
 * is what the proxy layer does and the other two deliberately do not.
 */
export const carries = (transport: string, proto: string): boolean =>
    proto !== L4.TLS || transport === Transport.PROXY



/** Which half of the traffic a pattern is matched against. */
export enum Mode {
    CLIENT_TO_SERVER = "C",
    SERVER_TO_CLIENT = "S",
    BOTH = "B",
}

export const modeLabel = (mode: string) => ({
    C: "client → service",
    S: "service → client",
    B: "both ways",
}[mode] ?? mode)

/** One place a service is reachable. A service has a list of them. */
export type Address = {
    address_id: string,
    service_id: string,
    ip_int: string,
    port: number,
    proto: string,
    /** `external` only: where your own proxy listens for this address. */
    proxy_ip: string | null,
    proxy_port: number | null,
}

export type AddressForm = {
    ip_int: string,
    port: number,
    proxy_ip?: string | null,
    proxy_port?: number | null,
}

export type Service = {
    service_id: string,
    name: string,
    status: string,
    proto: string,
    transport: string,
    fail_open: boolean,
    /** How many connections or UDP flows may be carried at once; 0 means no limit. */
    max_connections: number,
    /** Whether what does not fit is forwarded unfiltered rather than refused. */
    over_limit_forwards: boolean,
    /** Seconds a connection may carry nothing at all before it is closed; 0 means never. */
    first_byte_timeout: number,
    /** How many times the limit has turned something away, ever. Survives a restart. */
    over_limit_hits: number,
    over_limit_first: number | null,
    over_limit_last: number | null,
    /**
     * Whether a certificate and a key are already stored. The material never comes back
     * from the API, so this is what tells an empty field in the edit form apart: unchanged,
     * or never set at all.
     */
    has_tls_material: boolean,
    addresses: Address[],
    n_filters: number,
    n_blocked: number,
}

export type ServiceAddForm = {
    name: string,
    proto: string,
    addresses: AddressForm[],
    transport: string,
    fail_open?: boolean,
    max_connections?: number,
    over_limit_forwards?: boolean,
    first_byte_timeout?: number,
    tls_cert?: string | null,
    tls_key?: string | null,
}

/** Editing never touches the addresses: those have endpoints of their own, because
 * changing one costs at most the connections on that address. */
export type ServiceSettings = {
    name?: string,
    proto?: string,
    transport?: string,
    fail_open?: boolean,
    max_connections?: number,
    over_limit_forwards?: boolean,
    first_byte_timeout?: number,
    tls_cert?: string | null,
    tls_key?: string | null,
}

export type ServiceAddResponse = {
    status: string,
    service_id?: string,
}

export type Filter = {
    filter_id: string,
    service_id: string,
    position: number,
    kind: string,
    /** Detected from the code, not set. */
    proto: string,
    name: string,
    active: boolean,
    blocked: number,
    n_regexes: number,
    /** How many `@pyfilter` functions the code defines, and how many are switched on. */
    n_functions: number,
    n_functions_active: number,
}

/**
 * One `@pyfilter` function inside a pyfilter's code.
 *
 * The code decides which exist; the operator decides which run. Switching one off
 * leaves the code untouched — only the list of names handed to the library changes,
 * and that list is what decides whether a function is ever called.
 */
export type PyFunction = {
    filter_id: string,
    name: string,
    active: boolean,
    blocked: number,
}

export type Regex = {
    regex_id: string,
    filter_id: string,
    /** base64: a pattern is bytes, and not every useful one is text. */
    regex: string,
    mode: string,
    case_sensitive: boolean,
    active: boolean,
    action: string,
    /** base64, and only meaningful when the action is `rewrite`. */
    replace_with: string | null,
    blocked: number,
}

export type LogEntry = {
    /** Unix milliseconds. */
    at: number,
    /** info | block | output | warn | error */
    level: string,
    text: string,
    /** Monotonic per service; the browser dedupes on it across reconnects. */
    seq: number,
}

/** What one filter — or one pattern or `@pyfilter` function inside it — has refused. */
export type StatsEntry = {
    id: string,
    name: string,
    kind: string,
    /** Present for a pattern or a function, absent for a filter. */
    filter_id?: string | null,
    /** Refused in the selected range. */
    blocked: number,
    /** Refused since it was created. Filters only. */
    all_time?: number | null,
    /** Its share of everything this service refused in the range, 0–100. */
    share: number,
    /**
     * True for the one entry per filter standing for blocks no rule still in it accounts
     * for — a pattern deleted, or one whose text was edited. Its `name` is prose, not a
     * pattern, so it is not printed as one.
     */
    residual?: boolean,
}

/**
 * How much arrived, in the units each layer can honestly report.
 *
 * Packets come from the kernel's counters on the intercept rules and exist on every
 * layer. Connections come from the proxy engine, the only layer that works in them —
 * and therefore the only one where the refused share is a division of like by like.
 */
export type Traffic = {
    packets: number,
    bytes: number,
    connections: number | null,
    connections_refused: number | null,
    refused_share: number | null,
}

export type ServiceStats = {
    filters: StatsEntry[],
    patterns: StatsEntry[],
    /** One per `@pyfilter` function, across every pyfilter in the chain. */
    functions: StatsEntry[],
    /** Unix seconds, one per bucket, oldest first. */
    buckets: number[],
    /** How wide each bucket is, in seconds. */
    bucket_seconds: number,
    /** Per filter id, one count per bucket — the same length as `buckets`. */
    series: { id: string, name: string, counts: number[] }[],
    /** Refused in the selected range — the number every list above is a share of. */
    total: number,
    /** Refused since each rule was created, which is what the cards show. */
    all_time: number,
    /** The range actually served, after clamping to what is still kept. */
    range_from: number,
    range_to: number,
    /** The oldest instant anything is known about. */
    kept_from: number,
    /** When this service first became able to refuse anything: running, with a filter
     *  attached. The floor of every range, the same way `kept_from` is. Null if it
     *  never has been. */
    filtering_since: number | null,
    traffic: Traffic,
}

/** Why a filter file will not load, and where. */
export type CodeCheck = {
    ok: boolean,
    /** Present when it loads: the protocol read off the code. */
    proto?: string | null,
    filters: string[],
    error?: {
        type: string,
        message: string,
        /** 1-based, or 0 when nothing in the file could be pointed at. */
        line: number,
        column: number,
        text: string,
        traceback: string,
    } | null,
}

/** The library's own description of itself, for the editor's hints. */
export type ApiMember = { name: string, doc: string, writable: boolean, signature?: string | null }
export type ApiModel = { name: string, doc: string, members: ApiMember[], protocols: string[] }
export type ApiEntry = { name: string, doc: string, value?: number | null, values: string[] }
export type PyFilterApi = { models: ApiModel[], verdicts: ApiEntry[], settings: ApiEntry[] }

export type DebugMatch = { id: string, start: number, end: number }
export type DebugError = { id: string, error: string }
export type DebugResult = {
    matches: DebugMatch[],
    errors: DebugError[],
    error?: string | null,
    /** Valid and will run, but cannot be highlighted here. */
    unscannable: DebugError[],
    /** base64: what the sample becomes, computed by the engine's own rewriting code. */
    rewritten?: string | null,
    truncated: boolean,
}

/** Must stay in step with the tag the backend emits on every mutation. */
export const serviceQueryKey = ["services"]

export const servicesQuery = () => useQuery({
    queryKey: serviceQueryKey,
    queryFn: services.list,
})

export const serviceAddressesQuery = (service_id: string) => useQuery({
    queryKey: [...serviceQueryKey, service_id, "addresses"],
    queryFn: () => services.addresses(service_id),
    enabled: !!service_id,
})

/**
 * The statistics for one window.
 *
 * The range is part of the key, so switching to another one is a different query rather
 * than a refetch that momentarily shows the old numbers under the new label. A relative
 * range is keyed by its length, not by the instants it resolves to, or every socket
 * event would land on a key nobody is holding.
 */
export const serviceStatsQuery = (
    service_id: string, range: { from?: number, to?: number, seconds?: number, step?: number | null },
) => useQuery({
    queryKey: [...serviceQueryKey, service_id, "stats",
        range.seconds ?? `${range.from}-${range.to}`, range.step ?? "auto"],
    queryFn: () => services.stats(service_id, range),
    enabled: !!service_id,
})

export const serviceFiltersQuery = (service_id: string) => useQuery({
    queryKey: [...serviceQueryKey, service_id, "filters"],
    queryFn: () => services.filters(service_id),
    enabled: !!service_id,
})

export const filterFunctionsQuery = (service_id: string, filter_id: string) => useQuery({
    queryKey: [...serviceQueryKey, service_id, "filters", filter_id, "functions"],
    queryFn: () => services.functions(service_id, filter_id),
    enabled: !!service_id && !!filter_id,
})

export const pyfilterApiQuery = () => useQuery({
    // The library does not change while the page is open, so this is fetched once.
    queryKey: ["pyfilter-api"],
    queryFn: services.pyfilterApi,
})

export const filterCodeQuery = (service_id: string, filter_id: string) => useQuery({
    queryKey: [...serviceQueryKey, service_id, "filters", filter_id, "code"],
    queryFn: () => services.code(service_id, filter_id),
    enabled: !!service_id && !!filter_id,
})

export const filterRegexesQuery = (service_id: string, filter_id: string) => useQuery({
    queryKey: [...serviceQueryKey, service_id, "filters", filter_id, "regexes"],
    queryFn: () => services.regexes(service_id, filter_id),
    enabled: !!service_id && !!filter_id,
})

const done = ({ status }: ServerResponse) => status === "ok" ? undefined : status

export const services = {
    list: async () => await getapi("services") as Service[],
    info: async (id: string) => await getapi(`services/${id}`) as Service,
    add: async (data: ServiceAddForm) => await postapi("services", data) as ServiceAddResponse,
    edit: async (id: string, data: ServiceSettings) =>
        done(await putapi(`services/${id}`, data) as ServerResponse),
    remove: async (id: string) => done(await deleteapi(`services/${id}`) as ServerResponse),
    start: async (id: string) => done(await postapi(`services/${id}/start`) as ServerResponse),
    stop: async (id: string) => done(await postapi(`services/${id}/stop`) as ServerResponse),

    addresses: async (id: string) => await getapi(`services/${id}/addresses`) as Address[],
    addAddress: async (id: string, data: AddressForm) =>
        done(await postapi(`services/${id}/addresses`, data) as ServerResponse),
    editAddress: async (id: string, aid: string, data: AddressForm) =>
        done(await putapi(`services/${id}/addresses/${aid}`, data) as ServerResponse),
    deleteAddress: async (id: string, aid: string) =>
        done(await deleteapi(`services/${id}/addresses/${aid}`) as ServerResponse),

    filters: async (id: string) => await getapi(`services/${id}/filters`) as Filter[],
    addFilter: async (id: string, data: { kind: string, name?: string }) =>
        done(await postapi(`services/${id}/filters`, data) as ServerResponse),
    editFilter: async (id: string, fid: string, data: { name?: string, active?: boolean }) =>
        done(await putapi(`services/${id}/filters/${fid}`, data) as ServerResponse),
    deleteFilter: async (id: string, fid: string) =>
        done(await deleteapi(`services/${id}/filters/${fid}`) as ServerResponse),
    /** The whole order at once: a partial move cannot be reconciled between two tabs. */
    reorder: async (id: string, filters: string[]) =>
        done(await postapi(`services/${id}/filters/order`, { filters }) as ServerResponse),

    functions: async (id: string, fid: string) =>
        await getapi(`services/${id}/filters/${fid}/functions`) as PyFunction[],
    editFunction: async (id: string, fid: string, name: string, data: { active: boolean }) =>
        done(await putapi(`services/${id}/filters/${fid}/functions/${encodeURIComponent(name)}`, data) as ServerResponse),

    code: async (id: string, fid: string) =>
        await getapi(`services/${id}/filters/${fid}/code`) as string,
    /** Would this code load? Answered without saving it, by the process that runs it. */
    checkCode: async (id: string, fid: string, code: string) =>
        await postapi(`services/${id}/filters/${fid}/check`, { code }) as CodeCheck,
    /** What the filter library offers, introspected from the library itself. */
    pyfilterApi: async () => await getapi("services/pyfilter-api") as PyFilterApi,
    setCode: async (id: string, fid: string, code: string) =>
        done(await putapi(`services/${id}/filters/${fid}/code`, { code }) as ServerResponse),

    regexes: async (id: string, fid: string) =>
        await getapi(`services/${id}/filters/${fid}/regexes`) as Regex[],
    addRegex: async (id: string, fid: string, data: {
        regex: string, mode: string, case_sensitive: boolean,
        action?: string, replace_with?: string | null,
    }) =>
        done(await postapi(`services/${id}/filters/${fid}/regexes`, data) as ServerResponse),
    editRegex: async (id: string, fid: string, rid: string, data: {
        active?: boolean, regex?: string, mode?: string, case_sensitive?: boolean,
        action?: string, replace_with?: string | null,
    }) =>
        done(await putapi(`services/${id}/filters/${fid}/regexes/${rid}`, data) as ServerResponse),
    deleteRegex: async (id: string, fid: string, rid: string) =>
        done(await deleteapi(`services/${id}/filters/${fid}/regexes/${rid}`) as ServerResponse),

    /** What each filter has refused, and when, over a window you choose. */
    stats: async (
        id: string,
        range: { from?: number, to?: number, seconds?: number, step?: number | null } = {},
    ) => {
        // A relative range is resolved here rather than sent as a length: the server
        // takes two instants, and one meaning for a range is better than two.
        const now = Math.floor(Date.now() / 1000)
        const parts = range.seconds
            ? [`range_from=${now - range.seconds}`, `range_to=${now}`]
            : (range.from && range.to ? [`range_from=${range.from}`, `range_to=${range.to}`] : [])
        // Absent means "fit the range", which is the server's own default.
        if (range.step) parts.push(`step=${range.step}`)
        const params = parts.join("&")
        return await getapi(`services/${id}/stats${params ? "?" + params : ""}`) as ServiceStats
    },

    /** The tail. New lines arrive over the `log` socket event, not by polling. */
    logs: async (id: string) => await getapi(`services/${id}/logs`) as LogEntry[],
    clearLogs: async (id: string) =>
        done(await deleteapi(`services/${id}/logs`) as ServerResponse),

    /** Ask the matching engine itself what a pattern would do. */
    debug: async (
        patterns: {
            id: string, expr: string, case_sensitive: boolean,
            action?: string, replace_with?: string,
        }[],
        sample: string,
    ) =>
        await postapi("services/debug-regex", { patterns, sample }) as DebugResult,
}
