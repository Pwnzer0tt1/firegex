import { Box, Group, Paper, Text } from '@mantine/core';
import { useRef, useState } from 'react';

/**
 * The four shapes the same numbers can take.
 *
 * Hand-written SVG rather than a charting library: four small charts do not justify a
 * dependency several times the size of the page they sit on, and the arithmetic is a
 * hundred lines. All four read the same series, so switching between them is a change
 * of view and never of data.
 *
 * Nothing here draws text inside the plot. The bars are stretched to the container with
 * `preserveAspectRatio="none"`, which is right for rectangles and wrong for letters —
 * labels live in HTML underneath, where they keep their proportions. The hover readout
 * is HTML over the plot for the same reason.
 *
 * Hovering is tracked once, on the container, rather than per bar: it has to work for a
 * line and an area as well, where there is no shape under the cursor to attach it to,
 * and one handler for four charts means they cannot disagree about which step you are
 * pointing at.
 */

export const PALETTE = [
    "var(--mantine-color-violet-5)",
    "var(--mantine-color-teal-5)",
    "var(--mantine-color-orange-5)",
    "var(--mantine-color-blue-5)",
    "var(--mantine-color-pink-5)",
    "var(--mantine-color-lime-5)",
    "var(--mantine-color-cyan-5)",
    "var(--mantine-color-red-5)",
]

export type Series = { id: string, name: string, counts: number[] }

export type ChartKind = "bars" | "lines" | "area" | "share"

export const CHART_LABELS: Record<ChartKind, string> = {
    bars: "Bars",
    lines: "Lines",
    area: "Area",
    share: "Share",
}

const WIDTH = 720
const HEIGHT = 150

/** Sum across every series, per step. */
const totalsPerStep = (series: Series[], steps: number) =>
    Array.from({ length: steps }, (_, i) => series.reduce((acc, s) => acc + (s.counts[i] ?? 0), 0))

/** A polyline through one series, in plot coordinates. */
const points = (counts: number[], steps: number, scale: (v: number) => number) =>
    Array.from({ length: steps }, (_, i) => {
        const x = steps === 1 ? WIDTH / 2 : (i / (steps - 1)) * WIDTH
        return `${x},${scale(counts[i] ?? 0)}`
    }).join(" ")

/** Wall time, to the minute. Shared with the axis labels under the plot, so a readout
 *  and the tick it sits above can never disagree about what a step is called. */
export const clock = (seconds: number) => {
    const d = new Date(seconds * 1000)
    return `${d.getHours().toString().padStart(2, "0")}:${d.getMinutes().toString().padStart(2, "0")}`
}

/** The same, with the day in front when the step is not today — an "All" range covers
 *  two days, where a bare `03:14` says nothing about which one. */
const when = (seconds: number) => {
    const d = new Date(seconds * 1000)
    return d.toDateString() === new Date().toDateString()
        ? clock(seconds)
        : `${d.toLocaleDateString()} ${clock(seconds)}`
}

/** What the cursor is over: the step, and what every series had in it. */
function Readout({ at, series, step, width, left }: {
    at: number, series: Series[], step: number, width: number, left: number,
}) {
    const rows = series
        .map((s, k) => ({ name: s.name, value: s.counts[step] ?? 0, colour: PALETTE[k % PALETTE.length] }))
        .filter(r => r.value > 0)
        .sort((a, b) => b.value - a.value)
    const total = rows.reduce((acc, r) => acc + r.value, 0)
    // Flipped to the other side near the right edge, so the readout never leaves the card.
    const flip = left > 0.6
    return <Paper withBorder shadow="md" radius="sm" p={6} style={{
        position: 'absolute', top: 4, pointerEvents: 'none', zIndex: 3, minWidth: 150,
        ...(flip ? { right: `${(1 - left) * 100}%`, marginRight: 8 }
            : { left: `${left * 100}%`, marginLeft: 8 }),
        background: 'var(--mantine-color-body)',
    }}>
        <Group justify="space-between" gap="xs" wrap="nowrap">
            <Text size="xs" c="dimmed">{when(at)}{width > 60 ? ` +${Math.round(width / 60)}m` : ""}</Text>
            <Text size="xs" fw={600}>{total}</Text>
        </Group>
        {rows.length === 0
            ? <Text size="xs" c="dimmed">nothing refused</Text>
            : rows.map(r => <Group key={r.name} gap={6} wrap="nowrap" mt={2}>
                <Box style={{ width: 8, height: 8, borderRadius: 2, background: r.colour, flexShrink: 0 }} />
                <Text size="xs" c="dimmed" style={{ flex: 1 }}>{r.name}</Text>
                <Text size="xs">{r.value}</Text>
                {total > 0 ? <Text size="xs" c="dimmed">{Math.round((100 * r.value) / total)}%</Text> : null}
            </Group>)}
    </Paper>
}

export function Chart({ kind, series, steps, edges, width: stepWidth }: {
    kind: ChartKind, series: Series[], steps: number,
    /** The instant each step begins, for the readout. */
    edges: number[],
    /** How wide one step is, in seconds. */
    width: number,
}) {
    const totals = totalsPerStep(series, steps)
    // `share` normalises each step to its own total, so the vertical axis is a
    // percentage and the peak is always 100.
    const peak = kind === "share" ? 100 : Math.max(1, ...(
        kind === "lines"
            ? series.flatMap(s => s.counts)
            : totals
    ))
    const y = (value: number) => HEIGHT - (value / peak) * (HEIGHT - 4)
    const slot = WIDTH / Math.max(1, steps)
    const barWidth = Math.max(1, slot - 1)

    const [hover, setHover] = useState<number | null>(null)
    const plot = useRef<HTMLDivElement>(null)

    const track = (event: { clientX: number }) => {
        const box = plot.current?.getBoundingClientRect()
        if (!box || box.width === 0 || steps === 0) return
        const fraction = (event.clientX - box.left) / box.width
        setHover(Math.max(0, Math.min(steps - 1, Math.floor(fraction * steps))))
    }

    return <Box ref={plot} style={{ position: 'relative' }}
        onMouseMove={track} onMouseLeave={() => setHover(null)}>
        <Text size="xs" c="dimmed" style={{ position: 'absolute', top: 0, left: 0 }}>
            {kind === "share" ? "100%" : peak}
        </Text>
        {hover !== null && edges[hover] !== undefined
            ? <Readout at={edges[hover]} series={series} step={hover} width={stepWidth}
                left={(hover + 0.5) / steps} />
            : null}
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} width="100%" height={HEIGHT}
            preserveAspectRatio="none" role="img" aria-label="Connections refused over time">
            <line x1={0} y1={HEIGHT} x2={WIDTH} y2={HEIGHT}
                stroke="var(--mantine-color-dark-4)" vectorEffect="non-scaling-stroke" />

            {(kind === "bars" || kind === "share") && Array.from({ length: steps }, (_, i) => {
                // Stacked: the height is what this service refused in that step, and the
                // colours say which link in the chain accounted for it.
                const stepTotal = totals[i]
                if (!stepTotal) return null
                let offset = 0
                return <g key={i}>
                    {series.map((s, k) => {
                        const raw = s.counts[i] ?? 0
                        if (!raw) return null
                        const value = kind === "share" ? (raw / stepTotal) * 100 : raw
                        const h = (value / peak) * (HEIGHT - 4)
                        const top = HEIGHT - offset - h
                        offset += h
                        return <rect key={s.id} x={i * slot} y={top} width={barWidth} height={h}
                            fill={PALETTE[k % PALETTE.length]} />
                    })}
                </g>
            })}

            {kind === "area" && (() => {
                // Stacked area: the same stack as the bars, read as a shape rather than
                // as discrete steps — easier to see where a burst begins and ends.
                const running = new Array(steps).fill(0)
                return series.map((s, k) => {
                    const lower = [...running]
                    for (let i = 0; i < steps; i++) running[i] += s.counts[i] ?? 0
                    const top = points(running, steps, y)
                    const bottom = Array.from({ length: steps }, (_, i) => {
                        const idx = steps - 1 - i
                        const x = steps === 1 ? WIDTH / 2 : (idx / (steps - 1)) * WIDTH
                        return `${x},${y(lower[idx])}`
                    }).join(" ")
                    return <polygon key={s.id} points={`${top} ${bottom}`}
                        fill={PALETTE[k % PALETTE.length]} fillOpacity={0.55} />
                })
            })()}

            {kind === "lines" && series.map((s, k) => (
                // One line each, against a shared scale: for comparing filters rather
                // than for reading the total, which is what the stacked views are for.
                <polyline key={s.id} points={points(s.counts, steps, y)} fill="none"
                    stroke={PALETTE[k % PALETTE.length]} strokeWidth={2}
                    vectorEffect="non-scaling-stroke" />
            ))}

            {/* Drawn last, so it sits over every shape. A band rather than a line for
                the stacked views, where a step is a bar and not an instant. */}
            {hover !== null ? (kind === "bars" || kind === "share"
                ? <rect x={hover * slot} y={0} width={barWidth} height={HEIGHT}
                    fill="var(--mantine-color-gray-5)" fillOpacity={0.18} />
                : <line x1={steps === 1 ? WIDTH / 2 : (hover / (steps - 1)) * WIDTH} y1={0}
                    x2={steps === 1 ? WIDTH / 2 : (hover / (steps - 1)) * WIDTH} y2={HEIGHT}
                    stroke="var(--mantine-color-gray-5)" strokeOpacity={0.5}
                    vectorEffect="non-scaling-stroke" />
            ) : null}
        </svg>
    </Box>
}

export function Legend({ series }: { series: Series[] }) {
    return <Group gap="xs" mt="xs">
        {series.map((s, i) => <Group key={s.id} gap={4} wrap="nowrap">
            <Box style={{
                width: 10, height: 10, borderRadius: 2,
                background: PALETTE[i % PALETTE.length],
            }} />
            <Text size="xs" c="dimmed">{s.name}</Text>
        </Group>)}
    </Group>
}
