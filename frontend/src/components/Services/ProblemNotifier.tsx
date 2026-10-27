import { useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { socketio } from '../../js/utils';
import { LogEntry, serviceQueryKey } from './utils';

/**
 * Brings a service's new warning or error to the floating cards, wherever the
 * operator is.
 *
 * The live log is on the service's own page, and it used to be the only place a
 * warning went: an engine that died and came back, a filter raising on every packet,
 * a fallback that cost the service its clients' addresses — each waited for somebody
 * to open that page. The services list carries each service's newest problem, and the
 * cards and the summary read it from there; a log line emits no `update`, so this asks
 * for the list again when one arrives. It used to raise a toast of its own as well,
 * which now would say the same thing twice in two corners of the screen.
 */
export default function ProblemNotifier() {
    const queryClient = useQueryClient()

    useEffect(() => {
        const onLog = (payload: { service_id: string, entries: LogEntry[] }) => {
            if (payload.entries.some(e => e.level === "warn" || e.level === "error")) {
                // Exact, so the per-service queries under the same prefix are left alone.
                queryClient.invalidateQueries({ queryKey: serviceQueryKey, exact: true })
            }
        }
        socketio.on("log", onLog)
        return () => { socketio.off("log", onLog) }
    }, [queryClient])

    return null
}
