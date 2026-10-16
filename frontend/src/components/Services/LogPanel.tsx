import { ActionIcon, Badge, Box, Code, Group, ScrollArea, Switch, Text, Tooltip } from '@mantine/core';
import { useEffect, useRef, useState } from 'react';
import { BsTrashFill } from 'react-icons/bs';
import { socketio } from '../../js/utils';
import { LogEntry, services } from './utils';

const COLOURS: Record<string, string> = {
    block: 'var(--mantine-color-yellow-4)',
    warn: 'var(--mantine-color-orange-4)',
    error: 'var(--mantine-color-red-4)',
    output: 'var(--mantine-color-cyan-4)',
    info: 'var(--mantine-color-dimmed)',
}

const clock = (at: number) => new Date(at).toLocaleTimeString(undefined, { hour12: false })

/**
 * What the service is doing, as it does it.
 *
 * The backend pushes lines over the `log` socket event rather than being polled, and
 * coalesces them, so a service refusing thousands of connections a minute produces a
 * readable stream instead of a browser that stops responding. The tail is bounded on
 * both sides for the same reason.
 */
export default function LogPanel({ serviceId }: { serviceId: string }) {
    const [entries, setEntries] = useState<LogEntry[]>([])
    const [follow, setFollow] = useState(true)
    const viewport = useRef<HTMLDivElement>(null)
    const followRef = useRef(follow)
    followRef.current = follow

    useEffect(() => {
        let live = true
        setEntries([])
        services.logs(serviceId).then(tail => { if (live) setEntries(tail) }).catch(() => { })

        const onLog = (payload: { service_id: string, entries: LogEntry[] }) => {
            if (payload.service_id !== serviceId) return
            setEntries(current => {
                // Keyed by seq because a reconnect can replay what we already have, and
                // the same text at the same second is not the same line.
                const seen = new Set(current.map(e => e.seq))
                const added = payload.entries.filter(e => !seen.has(e.seq))
                if (added.length === 0) return current
                // Bounded here too: the panel is a tail, not a transcript.
                return [...current, ...added].slice(-500)
            })
        }
        socketio.on("log", onLog)
        return () => { live = false; socketio.off("log", onLog) }
    }, [serviceId])

    useEffect(() => {
        if (!followRef.current || !viewport.current) return
        viewport.current.scrollTo({ top: viewport.current.scrollHeight })
    }, [entries])

    return <Box>
        <Group justify="space-between" align="center" mb="xs">
            <Group gap="xs" align="center">
                <Text fw={600} size="sm">Live log</Text>
                <Badge size="xs" variant="light" color="gray">{entries.length}</Badge>
            </Group>
            <Group gap="sm">
                <Tooltip label="Keep the newest line in view" position="bottom">
                    <Switch size="xs" label="Follow" checked={follow}
                        onChange={e => setFollow(e.currentTarget.checked)} />
                </Tooltip>
                <Tooltip label="Clear" position="bottom">
                    <ActionIcon variant="light" color="red" size="sm"
                        onClick={() => services.clearLogs(serviceId).then(() => setEntries([]))}>
                        <BsTrashFill size={12} />
                    </ActionIcon>
                </Tooltip>
            </Group>
        </Group>
        <ScrollArea h={240} viewportRef={viewport}
            style={{ border: '1px solid var(--fourth_color)', borderRadius: 8 }}>
            <Code block style={{ background: 'transparent', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {entries.length === 0
                    ? <Text size="sm" c="dimmed">
                        Nothing yet. Blocks, anything your filters print, and whatever the
                        datapath says about its own health all show up here as it happens.
                    </Text>
                    : entries.map(entry => <Box key={entry.seq} style={{ display: 'flex', gap: 8 }}>
                        <span style={{ color: 'var(--mantine-color-dimmed)', flexShrink: 0 }}>
                            {clock(entry.at)}
                        </span>
                        <span style={{ color: COLOURS[entry.level] ?? 'inherit' }}>{entry.text}</span>
                    </Box>)}
            </Code>
        </ScrollArea>
    </Box>
}
