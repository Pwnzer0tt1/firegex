import { ActionIcon, Button, Drawer, Group, Indicator, Switch, Text, Tooltip } from '@mantine/core'
import { ReactNode } from 'react'
import { TbBell } from 'react-icons/tb'
import { useProblemPrefsStore, useProblemStripStore } from '../../js/store'
import { Service } from '../Services/utils'
import { ProblemAction } from './ProblemCards'
import { problemsOf, StripProblem } from './problems'
import { Dot, toneColor } from './ui'

/** "4 min ago" for the last hour, a time of day after that: what a round is measured in. */
const when = (at: number, now: number) => {
    const minutes = Math.round((now - at) / 60_000)
    if (minutes < 1) return "just now"
    if (minutes < 60) return `${minutes} min ago`
    return new Date(at).toLocaleString(undefined, { hour12: false, dateStyle: "short", timeStyle: "short" })
}

function Row({ problem, now, trailing }: { problem: StripProblem, now: number, trailing?: ReactNode }) {
    const setSummaryOpen = useProblemStripStore(s => s.setSummaryOpen)
    return <div className="fg-summary-row">
        <div className="fg-problem-head">
            <Dot tone={problem.tone} />
            <span className="fg-problem-kind" style={{ color: toneColor[problem.tone] }}>{problem.kind}</span>
            {problem.at ? <span className="fg-summary-when">{when(problem.at, now)}</span> : null}
            <span className="flex-spacer" />
            {trailing}
            <ProblemAction problem={problem} onDone={() => setSummaryOpen(false)} />
        </div>
        <div className="fg-summary-text">{problem.text}</div>
    </div>
}

function Section({ title, count, action, children }: {
    title: string, count: number, action?: ReactNode, children: ReactNode,
}) {
    if (count === 0) return null
    return <section className="fg-summary-section">
        <Group justify="space-between" className="fg-summary-title">
            <span>{title} <span className="fg-mono">{count}</span></span>
            {action}
        </Group>
        {children}
    </section>
}

/**
 * The bell beside the instance settings, and the list it opens.
 *
 * The floating cards show what is happening and can be closed; this is where every
 * problem can still be found afterwards — the ones on screen, the ones dismissed in
 * this tab, and warnings logged more than an hour ago that no longer float at all.
 * The count on the bell is only what still needs attention, so a dismissal quiets it.
 */
export default function ProblemSummary({ services }: { services: Service[] }) {
    const { dismissed, dismissAll, restore, restoreAll, summaryOpen, setSummaryOpen } = useProblemStripStore()
    const { showStrip, setShowStrip } = useProblemPrefsStore()
    const now = Date.now()
    const all = problemsOf(services, { now, includeStale: true })
    const active = all.filter(p => !p.stale && !dismissed.includes(p.key))
    const hidden = all.filter(p => !p.stale && dismissed.includes(p.key))
    const earlier = all.filter(p => p.stale).sort((a, b) => (b.at ?? 0) - (a.at ?? 0))
    const urgent = active.some(p => p.tone === "danger")

    return <>
        <Tooltip label={active.length ? `${active.length} problem${active.length === 1 ? "" : "s"} need attention` : "Warnings and errors"} position="top">
            <Indicator label={active.length} size={16} offset={4} disabled={active.length === 0}
                color={urgent ? "red" : "yellow"}>
                <ActionIcon variant="subtle" color="gray" size="lg" aria-label="Warnings and errors"
                    onClick={() => setSummaryOpen(true)}>
                    <TbBell size={18} />
                </ActionIcon>
            </Indicator>
        </Tooltip>
        <Drawer opened={summaryOpen} onClose={() => setSummaryOpen(false)} position="right" size={460}
            title={<Text fw={650}>Warnings and errors</Text>}
            styles={{
                content: { backgroundColor: 'var(--fg-nav)', borderLeft: '1px solid var(--fg-border)' },
                header: { backgroundColor: 'var(--fg-nav)', borderBottom: '1px solid var(--fg-border)' },
            }}>
            <Switch mt="md" mb="lg" label="Show problems on the page" checked={showStrip}
                description="Off: they are only counted on the bell and listed here."
                onChange={e => setShowStrip(e.currentTarget.checked)} />
            {all.length === 0
                ? <Text c="dimmed" size="sm" ta="center" py="xl">Nothing to report: every service is running with filters and none has logged a problem.</Text>
                : null}
            <Section title="Needs attention" count={active.length}
                action={<Button size="compact-xs" variant="subtle" color="gray"
                    onClick={() => dismissAll(active.map(p => p.key))}>Dismiss all</Button>}>
                {active.map(p => <Row key={p.key} problem={p} now={now} />)}
            </Section>
            <Section title="Dismissed" count={hidden.length}
                action={<Button size="compact-xs" variant="subtle" color="gray" onClick={restoreAll}>Show all again</Button>}>
                {hidden.map(p => <Row key={p.key} problem={p} now={now}
                    trailing={<Button size="compact-sm" variant="subtle" color="gray" onClick={() => restore(p.key)}>Show again</Button>} />)}
            </Section>
            <Section title="Earlier" count={earlier.length}>
                <Text size="xs" c="dimmed" mb={6}>
                    Logged more than an hour ago. Clearing a service's log removes its entry.
                </Text>
                {earlier.map(p => <Row key={p.key} problem={p} now={now} />)}
            </Section>
        </Drawer>
    </>
}
