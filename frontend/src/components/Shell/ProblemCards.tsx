import { Button } from '@mantine/core'
import { TbBell } from 'react-icons/tb'
import { useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { useNavbarStore, useProblemPrefsStore, useProblemStripStore } from '../../js/store'
import { errorNotify } from '../../js/utils'
import { serviceQueryKey, services } from '../Services/utils'
import { StripProblem } from './problems'
import { Dot, toneColor } from './ui'

/** At most this many rows at once; the rest are counted into one more row. */
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
 * What is costing protection right now: the strip pinned to the bottom of the page.
 *
 * The same rows the strip used to show across the top, laid over the page instead of
 * pushing it down, so a problem appearing never moves what the operator was reading or
 * about to click. At most {@link MAX_CARDS} rows; past that one more row says how many
 * are left and opens the summary, which is also where a closed row can be found again.
 */
export default function ProblemCards({ problems }: { problems: StripProblem[] }) {
    const dismissed = useProblemStripStore(s => s.dismissed)
    const dismiss = useProblemStripStore(s => s.dismiss)
    const setSummaryOpen = useProblemStripStore(s => s.setSummaryOpen)
    const showStrip = useProblemPrefsStore(s => s.showStrip)

    const visible = problems.filter(p => !dismissed.includes(p.key))
    // Switched off in the summary: the bell still counts them.
    if (!showStrip || visible.length === 0) return null
    const more = visible.length - MAX_CARDS

    return <div className="fg-strip" role="status" aria-live="polite">
        {visible.slice(0, MAX_CARDS).map(problem => <div className="fg-strip-row" key={problem.key}>
            <Dot tone={problem.tone} />
            <span className="fg-strip-kind" style={{ color: toneColor[problem.tone] }}>{problem.kind}</span>
            <span className="fg-strip-text" title={problem.text}>{problem.text}</span>
            <ProblemAction problem={problem} />
            <button type="button" className="fg-strip-close" aria-label="Dismiss"
                title="Dismiss — it stays in the summary" onClick={() => dismiss(problem.key)}>×</button>
        </div>)}
        {more > 0
            ? <button type="button" className="fg-strip-row fg-strip-more" onClick={() => setSummaryOpen(true)}>
                <TbBell size={14} />
                <span className="fg-strip-text">
                    {more} more problem{more === 1 ? "" : "s"} not shown — see them all in the summary
                </span>
                <span className="fg-strip-open">Show all</span>
            </button>
            : null}
    </div>
}
