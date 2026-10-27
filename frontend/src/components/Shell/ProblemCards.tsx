import { Button } from '@mantine/core'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { useNavbarStore, useProblemStripStore } from '../../js/store'
import { errorNotify } from '../../js/utils'
import { serviceQueryKey, services } from '../Services/utils'
import { StripProblem } from './problems'
import { Dot, toneColor } from './ui'

/** At most this many cards float at once; the rest are counted into one more. */
const MAX_CARDS = 3

/**
 * The one thing to do about a problem: start the service, or open it.
 *
 * Shared by the floating cards and the summary, so the same problem never offers two
 * different fixes depending on where it was read.
 */
export function ProblemAction({ problem, onDone }: { problem: StripProblem, onDone?: () => void }) {
    const navigate = useNavigate()
    const queryClient = useQueryClient()
    const closeNav = useNavbarStore(s => s.closeNav)
    const [busy, setBusy] = useState(false)

    if (problem.action === "open") {
        return <Button size="compact-sm" variant="default" onClick={() => {
            navigate(`/services/${problem.service.service_id}`)
            closeNav()
            onDone?.()
        }}>Open</Button>
    }

    const start = async () => {
        setBusy(true)
        try {
            const err = await services.start(problem.service.service_id)
            if (err) errorNotify(`Could not start ${problem.service.name}`, err)
            else {
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
                onDone?.()
            }
        } catch (err) {
            errorNotify(`Could not start ${problem.service.name}`, `${err}`)
        }
        setBusy(false)
    }
    return <Button size="compact-sm" variant="default" loading={busy} onClick={start}>Start</Button>
}

/**
 * What is costing protection right now, floating over the bottom of the page.
 *
 * Over the page rather than above it, so a problem never moves what the operator was
 * reading or about to click. Each card carries the one action that fixes it and can be
 * closed; nothing closed is lost, since the bell in the sidebar lists everything,
 * dismissed or not.
 */
export default function ProblemCards({ problems }: { problems: StripProblem[] }) {
    const dismissed = useProblemStripStore(s => s.dismissed)
    const dismiss = useProblemStripStore(s => s.dismiss)
    const setSummaryOpen = useProblemStripStore(s => s.setSummaryOpen)

    const visible = problems.filter(p => !dismissed.includes(p.key))
    if (visible.length === 0) return null

    return <div className="fg-problems" role="status" aria-live="polite">
        {visible.slice(0, MAX_CARDS).map(problem =>
            <div className="fg-problem" key={problem.key} style={{ borderLeftColor: toneColor[problem.tone] }}>
                <div className="fg-problem-head">
                    <Dot tone={problem.tone} />
                    <span className="fg-problem-kind" style={{ color: toneColor[problem.tone] }}>{problem.kind}</span>
                    <span className="flex-spacer" />
                    <ProblemAction problem={problem} />
                    <button type="button" className="fg-problem-close" aria-label="Dismiss"
                        title="Dismiss — it stays in the summary" onClick={() => dismiss(problem.key)}>×</button>
                </div>
                <div className="fg-problem-text" title={problem.text}>{problem.text}</div>
            </div>)}
        {visible.length > MAX_CARDS
            ? <button type="button" className="fg-problem fg-problem-more" onClick={() => setSummaryOpen(true)}>
                and {visible.length - MAX_CARDS} more — open the summary
            </button>
            : null}
    </div>
}
