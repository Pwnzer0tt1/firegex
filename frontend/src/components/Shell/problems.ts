import { addressSummary } from '../Services/ServiceRow'
import { Service, Transport } from '../Services/utils'
import { Tone } from './ui'

/** How long a logged warning keeps a place in the strip, matching the badge on the row. */
export const PROBLEM_SHOWN_MS = 60 * 60 * 1000

export type StripProblem = {
    /**
     * Identifies the situation, not just the service: dismissing "polls is stopped
     * with filters" must not also hide "polls logged an error" a minute later.
     */
    key: string,
    tone: Tone,
    kind: string,
    text: string,
    service: Service,
    /** What one click does about it. */
    action: "start" | "open",
    /** Unix milliseconds, for a problem read from a log; states have no moment. */
    at?: number,
    /**
     * A logged problem older than {@link PROBLEM_SHOWN_MS}: past the point of being
     * pushed at anyone, still worth finding in the summary.
     */
    stale?: boolean,
}

/**
 * Everything worth an operator's attention right now, worst first.
 *
 * Only states that cost protection are listed — a stopped service with filters (its
 * traffic is passing unfiltered), a running one with none (reachable and protected by
 * nothing), and a warning or error from a service's own log. A stopped service with
 * nothing attached is not a problem: it is switched off, which is a choice.
 *
 * Logged problems older than an hour are left out unless `includeStale` asks for
 * them: the floating cards are for what is happening, the summary for what happened.
 */
export function problemsOf(
    services: Service[],
    { now = Date.now(), includeStale = false }: { now?: number, includeStale?: boolean } = {},
): StripProblem[] {
    const found: StripProblem[] = []
    for (const service of services) {
        const where = addressSummary(service.addresses)
        if (service.status !== "active" && service.n_filters > 0) {
            found.push({
                key: `unfiltered:${service.service_id}`,
                tone: "danger",
                kind: "unfiltered",
                text: `${service.name} is stopped with ${service.n_filters} filter${service.n_filters === 1 ? "" : "s"} attached — ${where} passes unfiltered.`,
                service,
                action: "start",
            })
        } else if (service.status === "active" && service.n_filters === 0 && service.transport !== Transport.EXTERNAL) {
            found.push({
                key: `no-filters:${service.service_id}`,
                tone: "warn",
                kind: "no filters",
                text: `${service.name} on ${where} is running with no filters attached.`,
                service,
                action: "open",
            })
        }
        const logged = service.problem
        const stale = !!logged && now - logged.at > PROBLEM_SHOWN_MS
        if (logged && (!stale || includeStale)) {
            const error = logged.level === "error"
            found.push({
                // The timestamp is part of the key, so a new problem is never
                // swallowed by the dismissal of an older one.
                key: `logged:${service.service_id}:${logged.at}`,
                tone: error ? "danger" : "warn",
                kind: error ? "error" : "warning",
                text: `${service.name}: ${logged.text}`,
                service,
                action: "open",
                at: logged.at,
                stale,
            })
        }
    }
    const rank = (p: StripProblem) => (p.tone === "danger" ? 0 : 1)
    return found.sort((a, b) => rank(a) - rank(b))
}
