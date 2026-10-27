import { Button } from '@mantine/core'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { errorNotify } from '../../js/utils'
import { useProblemStripStore } from '../../js/store'
import { serviceQueryKey, services } from '../Services/utils'
import { StripProblem } from './problems'
import { Dot, toneColor } from './ui'

/** At most this many rows, so the strip never pushes the page off the screen. */
const MAX_ROWS = 4

/**
 * The strip across the top of every page: what is costing protection right now.
 *
 * It exists because the services list is not always the page that is open — an
 * operator writing a filter on one service should still see that another one stopped.
 * Each row carries the one action that fixes it, and can be closed for this tab.
 */
export default function ProblemStrip({ problems }: { problems: StripProblem[] }) {
    const dismissed = useProblemStripStore(s => s.dismissed)
    const dismiss = useProblemStripStore(s => s.dismiss)
    const navigate = useNavigate()
    const queryClient = useQueryClient()
    const [busy, setBusy] = useState<string | null>(null)

    const visible = problems.filter(p => !dismissed.includes(p.key))
    if (visible.length === 0) return null
    const shown = visible.slice(0, MAX_ROWS)

    const start = async (problem: StripProblem) => {
        setBusy(problem.key)
        try {
            const err = await services.start(problem.service.service_id)
            if (err) errorNotify(`Could not start ${problem.service.name}`, err)
            else queryClient.invalidateQueries({ queryKey: serviceQueryKey })
        } catch (err) {
            errorNotify(`Could not start ${problem.service.name}`, `${err}`)
        }
        setBusy(null)
    }

    return <div className="fg-strip" role="status">
        {shown.map(problem => <div className="fg-strip-row" key={problem.key}>
            <Dot tone={problem.tone} />
            <span className="fg-strip-kind" style={{ color: toneColor[problem.tone] }}>{problem.kind}</span>
            <span className="fg-strip-text" title={problem.text}>{problem.text}</span>
            {problem.action === "start"
                ? <Button size="compact-sm" variant="default" loading={busy === problem.key}
                    onClick={() => start(problem)}>Start</Button>
                : <Button size="compact-sm" variant="default"
                    onClick={() => navigate(`/services/${problem.service.service_id}`)}>Open</Button>}
            <button type="button" className="fg-strip-close" aria-label="Dismiss"
                onClick={() => dismiss(problem.key)}>×</button>
        </div>)}
        {visible.length > MAX_ROWS
            ? <div className="fg-strip-row" style={{ color: "var(--fg-text-muted)" }}>
                and {visible.length - MAX_ROWS} more — see the services list
            </div>
            : null}
    </div>
}
