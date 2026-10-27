import { Tooltip } from '@mantine/core'
import { ReactNode } from 'react'
import { Service, Transport } from '../Services/utils'

/** The four things a status can mean, and nothing else. */
export type Tone = "ok" | "warn" | "danger" | "muted" | "info"

/** Each tone as a solid colour (dots, text) and as a tint (pill backgrounds). */
export const toneColor: Record<Tone, string> = {
    ok: "var(--fg-ok)",
    warn: "var(--fg-warn)",
    danger: "var(--fg-danger)",
    info: "var(--fg-info)",
    muted: "var(--fg-text-faint)",
}

const toneSoft: Record<Tone, string> = {
    ok: "var(--fg-ok-soft)",
    warn: "var(--fg-warn-soft)",
    danger: "var(--fg-danger-soft)",
    info: "var(--fg-info-soft)",
    muted: "var(--fg-muted-soft)",
}

/**
 * How worried to be about a service, read off what it is doing.
 *
 * A stopped service is only alarming when it has filters: those are protection the
 * operator set up and is not getting, while traffic goes straight to the service. A
 * stopped service with nothing attached is simply switched off.
 */
export const serviceTone = (service: Service): Tone => {
    if (service.status === "active") {
        // A running service with nothing to run is reachable and protected by nothing;
        // the hand-off layer is the exception, since a filter there is not possible.
        if (service.n_filters === 0 && service.transport !== Transport.EXTERNAL) return "warn"
        return "ok"
    }
    return service.n_filters > 0 ? "danger" : "muted"
}

export const serviceStateLabel = (service: Service) =>
    service.status === "active" ? "running" : service.status === "stop" ? "stopped" : service.status

export function Dot({ tone, pulse }: { tone: Tone, pulse?: boolean }) {
    return <span className={`fg-dot${pulse ? " pulse" : ""}`} style={{ background: toneColor[tone] }} />
}

/** A coloured state word with its dot, the way a status is shown everywhere. */
export function Pill({ tone, children }: { tone: Tone, children: ReactNode }) {
    return <span className="fg-pill" style={{ background: toneSoft[tone], color: toneColor[tone] }}>
        <Dot tone={tone} />{children}
    </span>
}

/** A labelled value in the page header, e.g. "Firewall · enabled". */
export function Chip({ tone, label, children, tooltip }: {
    tone?: Tone, label: string, children: ReactNode, tooltip?: string,
}) {
    const chip = <span className="fg-chip">
        {tone ? <Dot tone={tone} /> : null}
        {label} <b>{children}</b>
    </span>
    return tooltip ? <Tooltip label={tooltip} multiline maw={320}>{chip}</Tooltip> : chip
}

/**
 * A tiny line of how many connections were refused per bucket.
 *
 * Drawn as plain SVG for the same reason the full charts are: a charting library is
 * many times the size of what it would draw here. An all-zero series is drawn as a
 * dotted baseline, so "nothing was refused" and "no data" do not look the same.
 */
export function Sparkline({ values, width = 120, height = 26, color = "var(--fg-accent)" }: {
    values: number[], width?: number, height?: number, color?: string,
}) {
    const max = values.length ? Math.max(...values) : 0
    if (values.length < 2 || max === 0) {
        return <svg width={width} height={height} aria-hidden>
            <line x1={0} x2={width} y1={height - 1} y2={height - 1}
                stroke="var(--fg-border-strong)" strokeDasharray="2 3" />
        </svg>
    }
    const step = width / (values.length - 1)
    // One pixel of headroom at each edge, so the stroke is never clipped in half.
    const y = (v: number) => height - 1 - (v / max) * (height - 3)
    const points = values.map((v, i) => `${(i * step).toFixed(1)},${y(v).toFixed(1)}`).join(" ")
    return <svg width={width} height={height} aria-hidden>
        <polygon points={`0,${height} ${points} ${width},${height}`} fill={color} opacity={0.14} />
        <polyline points={points} fill="none" stroke={color} strokeWidth={1.5}
            strokeLinejoin="round" strokeLinecap="round" />
    </svg>
}
