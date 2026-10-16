import { ActionIcon, Badge, Box, Card, Code, Group, Popover, SegmentedControl, Select, Space, Stack, Text, TextInput, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { MdOutlineDateRange } from 'react-icons/md';
import { Chart, CHART_LABELS, ChartKind, clock, Legend, PALETTE } from './StatsCharts';
import { serviceStatsQuery, StatsEntry, Traffic } from './utils';

/**
 * What each rule has refused, over a window you choose, in the shape you find readable.
 *
 * Three parts answering three questions and all of them are needed. The share says which
 * rule is doing the work — raw counts hide a chain where one pattern accounts for almost
 * everything. The timeline says when it started, which a cumulative counter cannot. And
 * the traffic totals say how much of what arrived any of it amounts to.
 *
 * **Everything obeys the range.** The chart, the totals and the shares are all computed
 * over the same window, because a page where the chart honours a fifteen-minute range
 * and the table beside it reports all of time is a page that contradicts itself. The
 * lifetime figure is still reported, once, so a narrow range showing nothing cannot be
 * mistaken for a service that has never blocked anything.
 */

/** The ranges worth one click. Anything else is two dates. */
const RANGES: { label: string, seconds: number }[] = [
    { label: "15m", seconds: 15 * 60 },
    { label: "1h", seconds: 60 * 60 },
    { label: "6h", seconds: 6 * 60 * 60 },
    { label: "24h", seconds: 24 * 60 * 60 },
    { label: "All", seconds: 48 * 60 * 60 },
]

const stamp = (seconds: number) => {
    const d = new Date(seconds * 1000)
    return `${d.toLocaleDateString()} ${clock(seconds)}`
}

/** The steps worth offering. "Auto" fits the step to the range, which is the default. */
const STEPS = [60, 2 * 60, 5 * 60, 15 * 60, 30 * 60, 60 * 60, 6 * 60 * 60]

/** How long one bar covers, in as few characters as it can be said. */
const stepLabel = (seconds: number) =>
    seconds >= 3600 ? `${Math.round(seconds / 3600)}h` : `${Math.round(seconds / 60)}m`

/**
 * The window, as short as it can be said: the day appears only where it has to.
 *
 * The long form — "Every figure below counts 06/09/2026 23:15 → 07/09/2026 00:15, in
 * steps of 2m." — said the date twice, the year twice, and a sentence of preamble, for
 * a line that is read at a glance and then ignored.
 */
const spanLabel = (from: number, to: number) => {
    const a = new Date(from * 1000), b = new Date(to * 1000)
    const day = (d: Date) => d.toLocaleDateString(undefined, { day: '2-digit', month: '2-digit' })
    const sameDay = a.toDateString() === b.toDateString()
    const head = sameDay && a.toDateString() === new Date().toDateString() ? "" : `${day(a)} `
    return `${head}${clock(from)} → ${sameDay ? "" : `${day(b)} `}${clock(to)}`
}

/** `datetime-local` wants local wall time without a zone, which is not what toISOString gives. */
const toLocalInput = (seconds: number) => {
    const d = new Date(seconds * 1000)
    const pad = (n: number) => n.toString().padStart(2, "0")
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
        + `T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

/** Bytes, in something a human reads at a glance. */
const humanBytes = (n: number) => {
    const units = ["B", "kB", "MB", "GB", "TB"]
    let value = n, unit = 0
    while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++ }
    return `${value < 10 && unit > 0 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

function Ranked({ entries, empty }: { entries: StatsEntry[], empty: string }) {
    const top = entries.filter(e => e.blocked > 0).sort((a, b) => b.blocked - a.blocked)
    if (top.length === 0) return <Text size="xs" c="dimmed">{empty}</Text>
    // Bars are drawn against the busiest one so the smallest is still visible; the
    // number beside them is the share of the whole, which is the comparable figure.
    const peak = Math.max(...top.map(e => e.blocked))
    return <Stack gap={6}>
        {top.map((entry, i) => <Box key={entry.id}>
            <Group justify="space-between" gap="xs" wrap="nowrap">
                {/* A residual entry's name is a sentence, not a pattern: printing it
                    in a code box would read as a rule somebody wrote. */}
                {entry.residual
                    ? <Text size="xs" c="dimmed" fs="italic" style={{
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    }}>{entry.name}</Text>
                    : <Code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {entry.name}
                    </Code>}
                <Group gap={6} wrap="nowrap">
                    <Tooltip label="Its share of everything this service refused" position="left">
                        <Text size="xs" fw={600}>{entry.share}%</Text>
                    </Tooltip>
                    <Text size="xs" c="dimmed">({entry.blocked})</Text>
                </Group>
            </Group>
            <Box style={{
                height: 6, borderRadius: 3, marginTop: 2,
                background: 'var(--mantine-color-dark-5)',
            }}>
                <Box style={{
                    height: 6, borderRadius: 3,
                    width: `${(entry.blocked / peak) * 100}%`,
                    background: PALETTE[i % PALETTE.length],
                }} />
            </Box>
        </Box>)}
    </Stack>
}

/**
 * How much arrived, in the units the layer under this service can honestly report.
 *
 * Deliberately two measures rather than one ratio. The kernel counts packets on the
 * intercept rules — free, on every layer, and unskewable because no filter is involved
 * in producing it. The proxy engine counts connections, which is the unit a block is
 * in, so only there is the refused share a division of like by like. The NFQUEUE layer
 * works per packet and has no connection to count; showing an empty share there is the
 * difference between the layers, not a hole in the reporting.
 */
function TrafficSummary({ traffic }: { traffic?: Traffic }) {
    if (!traffic) return null
    const { packets, bytes, connections, connections_refused, refused_share } = traffic
    return <Group gap="lg" wrap="wrap">
        {/* Absent on the proxy layer, whose rule sits in a nat chain that conntrack
            walks once per connection: a packet label on that count would be wrong by
            the length of every flow. Its connection counters say it properly. */}
        {packets > 0 ? <Tooltip position="bottom"
            label="Counted by the kernel on the rules that intercept this service — no filter is involved in producing it">
            <Box>
                <Text size="xs" c="dimmed">Reached the service</Text>
                <Text size="sm" fw={600}>
                    {packets.toLocaleString()} pkt <Text span size="xs" c="dimmed">· {humanBytes(bytes)}</Text>
                </Text>
            </Box>
        </Tooltip> : null}
        {connections !== null && connections !== undefined ? <>
            <Box>
                <Text size="xs" c="dimmed">Connections</Text>
                <Text size="sm" fw={600}>{connections.toLocaleString()}</Text>
            </Box>
            <Tooltip position="bottom"
                label="Refused connections over connections seen — both counted by the proxy engine, so this is like divided by like">
                <Box>
                    <Text size="xs" c="dimmed">Refused</Text>
                    <Text size="sm" fw={600} c={(refused_share ?? 0) > 0 ? "yellow" : undefined}>
                        {refused_share ?? 0}%
                        <Text span size="xs" c="dimmed"> · {(connections_refused ?? 0).toLocaleString()}</Text>
                    </Text>
                </Box>
            </Tooltip>
        </> : <Tooltip position="bottom"
            label="This layer inspects packets, not connections, so there is no connection count to take a share of. Dividing refused connections by a packet count would look like a percentage and mean nothing.">
            <Box>
                <Text size="xs" c="dimmed">Refused share</Text>
                <Text size="sm" c="dimmed">per-packet layer</Text>
            </Box>
        </Tooltip>}
    </Group>
}

export default function StatsPanel({ serviceId }: { serviceId: string }) {
    const [view, setView] = useState<"filters" | "patterns" | "functions">("filters")
    const [chart, setChart] = useState<ChartKind>("bars")
    // A relative window by default, because that is what "what is happening now" means.
    // An explicit pair replaces it and stops following the clock.
    const [seconds, setSeconds] = useState<number | null>(3600)
    const [custom, setCustom] = useState<{ from: number, to: number } | null>(null)
    const [picking, setPicking] = useState(false)
    // Null is "fit the step to the range". A fixed one is what makes two ranges
    // comparable by eye: five minutes is five minutes in both.
    const [step, setStep] = useState<number | null>(null)

    const stats = serviceStatsQuery(serviceId, custom && !seconds
        ? { from: custom.from, to: custom.to, step }
        : { seconds: seconds ?? 3600, step })
    const data = stats.data

    const useRelative = (value: number) => { setSeconds(value); setCustom(null) }

    return <Card withBorder radius="md" p="md" bg="transparent"
        style={{ borderColor: 'var(--fourth_color)' }}>
        <Group justify="space-between" align="flex-start" wrap="wrap" gap="xs">
            <Box>
                <Text fw={600} size="sm">What has been refused</Text>
                <Text size="xs" c="dimmed">
                    {data
                        ? <>{spanLabel(data.range_from, data.range_to)}
                            {" · "}{stepLabel(data.bucket_seconds)} steps
                            {/* The one thing worth saying beyond the range itself: a chart
                                that ignores the button just pressed looks broken. Marked
                                rather than explained — the explanation is a hover away. */}
                            {data.filtering_since !== null && data.range_from <= data.filtering_since
                                ? <Tooltip position="bottom" multiline w={240}
                                    label="This is where the service started: before it was
                                        running with a filter there is nothing to draw.">
                                    <Text span size="xs" c="dimmed" style={{
                                        textDecoration: 'underline dotted', cursor: 'help',
                                    }}> · from its start</Text>
                                </Tooltip>
                                : null}</>
                        : "Loading…"}
                </Text>
            </Box>
            <Group gap="xs">
                <Tooltip label="Refused in this range" position="bottom">
                    <Badge color="yellow" variant="light" radius="sm">{data?.total ?? 0}</Badge>
                </Tooltip>
                <Tooltip label="Refused since these rules were created" position="bottom">
                    <Badge color="gray" variant="outline" radius="sm">
                        {data?.all_time ?? 0} all time
                    </Badge>
                </Tooltip>
            </Group>
        </Group>

        <Space h="sm" />
        <Group justify="space-between" gap="xs" wrap="wrap">
            <Group gap={6} wrap="nowrap">
                <SegmentedControl size="xs" value={custom ? "" : String(seconds ?? "")}
                    onChange={v => useRelative(Number(v))}
                    data={RANGES.map(r => ({ label: r.label, value: String(r.seconds) }))} />
                {/* Two instants, for looking at something that has already happened —
                    a round that ended, an attack somebody described afterwards. */}
                <Popover opened={picking} onChange={setPicking} width={280} position="bottom-end"
                    withArrow shadow="md" radius="md">
                    <Popover.Target>
                        <Tooltip label="Pick two instants" position="bottom">
                            <ActionIcon variant={custom ? "filled" : "subtle"} color="gray"
                                onClick={() => setPicking(o => !o)}>
                                <MdOutlineDateRange size={16} />
                            </ActionIcon>
                        </Tooltip>
                    </Popover.Target>
                    <Popover.Dropdown>
                        <Stack gap="xs">
                            <TextInput size="xs" type="datetime-local" label="From"
                                defaultValue={toLocalInput(data?.range_from ?? 0)}
                                onChange={e => {
                                    const from = Math.floor(new Date(e.currentTarget.value).getTime() / 1000)
                                    if (!isNaN(from)) setCustom(c => ({
                                        from, to: c?.to ?? Math.floor(Date.now() / 1000),
                                    }))
                                }} />
                            <TextInput size="xs" type="datetime-local" label="To"
                                defaultValue={toLocalInput(data?.range_to ?? 0)}
                                onChange={e => {
                                    const to = Math.floor(new Date(e.currentTarget.value).getTime() / 1000)
                                    if (!isNaN(to)) setCustom(c => ({
                                        from: c?.from ?? Math.floor(Date.now() / 1000) - 3600, to,
                                    }))
                                }} />
                            <Group justify="space-between">
                                <Text size="xs" c="dimmed">
                                    {data?.filtering_since
                                        ? `Filtering since ${stamp(data.filtering_since)}`
                                        : `Kept from ${data ? stamp(data.kept_from) : "—"}`}
                                </Text>
                                <Text size="xs" c={custom ? "teal" : "dimmed"}
                                    style={{ cursor: 'pointer' }}
                                    onClick={() => { setSeconds(3600); setCustom(null); setPicking(false) }}>
                                    back to live
                                </Text>
                            </Group>
                        </Stack>
                    </Popover.Dropdown>
                </Popover>
            </Group>
            <Group gap={6} wrap="nowrap">
                <Tooltip position="bottom" multiline w={230}
                    label="How much time one bar covers. A step too fine for the range is
                        widened to keep the chart readable; the header says what was drawn.">
                    <Select size="xs" w={86} allowDeselect={false} comboboxProps={{ width: 90 }}
                        value={step === null ? "auto" : String(step)}
                        onChange={v => setStep(!v || v === "auto" ? null : Number(v))}
                        data={[{ value: "auto", label: "Auto" },
                        ...STEPS.map(sec => ({ value: String(sec), label: stepLabel(sec) }))]} />
                </Tooltip>
                <SegmentedControl size="xs" value={chart} onChange={v => setChart(v as ChartKind)}
                    data={(Object.keys(CHART_LABELS) as ChartKind[])
                        .map(k => ({ label: CHART_LABELS[k], value: k }))} />
            </Group>
        </Group>

        <Space h="sm" />
        <TrafficSummary traffic={data?.traffic} />

        <Space h="md" />
        {data && data.series.length > 0
            ? <>
                <Chart kind={chart} series={data.series} steps={data.buckets.length}
                    edges={data.buckets} width={data.bucket_seconds} />
                <Group justify="space-between" mt={2} gap={0}>
                    {(data.buckets.length > 1
                        ? [0, 1, 2, 3].map(i =>
                            data.buckets[Math.round((i * (data.buckets.length - 1)) / 3)])
                        : data.buckets
                    ).map((edge, i) => <Text key={`${edge}-${i}`} size="xs" c="dimmed">
                        {clock(edge)}
                    </Text>)}
                </Group>
                <Legend series={data.series} />
            </>
            : <Text size="xs" c="dimmed">
                Nothing was refused in this range, so there is no shape to draw.
            </Text>}

        <Space h="md" />
        <SegmentedControl size="xs" value={view} onChange={v => setView(v as any)}
            data={[
                { label: 'By filter', value: 'filters' },
                { label: 'By pattern', value: 'patterns' },
                { label: 'By function', value: 'functions' },
            ]} />
        <Space h="xs" />
        {view === "filters"
            ? <Ranked entries={data?.filters ?? []}
                empty="No filter refused anything in this range." />
            : view === "patterns"
                ? <Ranked entries={data?.patterns ?? []}
                    empty="No pattern refused anything in this range — a Python filter is broken down under 'By function' instead." />
                : <Ranked entries={data?.functions ?? []}
                    empty="No @pyfilter function refused anything in this range." />}
    </Card>
}
