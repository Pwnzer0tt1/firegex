import { showNotification } from '@mantine/notifications';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef } from 'react';
import { useNavigate } from 'react-router';
import { socketio } from '../../js/utils';
import { LogEntry, serviceQueryKey, services } from './utils';

/** How long one service's warnings are folded into the one already on screen. */
const QUIET_MS = 20_000

/**
 * Says so, wherever the operator is, when a service reports a problem.
 *
 * The live log is on the service's own page, and it was the only place a warning went:
 * an engine that died and came back, a filter raising on every packet, a fallback that
 * cost the service its clients' addresses — each of them waited for somebody to open that
 * page. Warnings and errors now also arrive as a notification, one per service per
 * `QUIET_MS` with the rest counted into the next, because a flood arriving twice — once
 * in the log and once as a stack of toasts — informs nobody. Blocks are not problems and
 * never notify.
 */
export default function ProblemNotifier() {
    const queryClient = useQueryClient()
    const navigate = useNavigate()
    const told = useRef(new Map<string, { at: number, held: number, worst: string }>())

    useEffect(() => {
        const onLog = (payload: { service_id: string, entries: LogEntry[] }) => {
            const problems = payload.entries.filter(e => e.level === "warn" || e.level === "error")
            if (problems.length === 0) return
            const now = Date.now()
            const worst = problems.some(e => e.level === "error") ? "error" : "warn"
            const was = told.current.get(payload.service_id) ?? { at: 0, held: 0, worst }
            // An error is not folded into a warning already on screen: "restarting it"
            // followed by "could not restart it" is the second one that matters, and
            // folded it waited for a third that need never come.
            const escalates = worst === "error" && was.worst !== "error"
            if (now - was.at < QUIET_MS && !escalates) {
                told.current.set(payload.service_id, { ...was, held: was.held + problems.length })
                return
            }
            told.current.set(payload.service_id, { at: now, held: 0, worst })
            const last = problems[problems.length - 1]
            const more = was.held + problems.length - 1
            // By name, which on a page that never listed the services means asking for
            // them first: an id is not something an operator recognises mid-round.
            queryClient.ensureQueryData({ queryKey: serviceQueryKey, queryFn: services.list })
                .catch(() => [])
                .then(listed => show(
                    listed.find(s => s.service_id === payload.service_id)?.name
                        ?? payload.service_id,
                    worst, last.text, more, payload.service_id))
        }
        const show = (name: string, worst: string, text: string, more: number, id: string) =>
            showNotification({
                autoClose: 8000,
                color: worst === "error" ? "red" : "orange",
                title: `${name}: ${worst === "error" ? "something went wrong" : "a warning"}`,
                message: text + (more > 0 ? ` (and ${more} more — see its log)` : ""),
                style: { cursor: "pointer" },
                onClick: () => navigate(`/services/${id}`),
            })
        socketio.on("log", onLog)
        return () => { socketio.off("log", onLog) }
    }, [queryClient, navigate])

    return null
}
