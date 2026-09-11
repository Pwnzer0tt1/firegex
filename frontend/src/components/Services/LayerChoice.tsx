import { ActionIcon, Alert, Badge, Box, Divider, Group, Popover, SegmentedControl, Space, Stack, Text, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { FaMinus, FaPlus } from 'react-icons/fa';
import { IoInformationCircleOutline } from 'react-icons/io5';
import { carries, L4, Transport } from './utils';

/**
 * Choosing the network layer.
 *
 * Three lines in the form — the control, and one sentence about what is selected — with
 * the trade a click away in a popover. Earlier attempts put the whole comparison inline,
 * first as a three-column table and then as a list of bullets; both were permanent
 * clutter for something read once, and both pushed the form's own submit button off the
 * screen. What stays inline is what you need while choosing; what opens is what you need
 * while deciding.
 */

type Layer = {
    /** The headline, one line, carrying the reason you would pick this. */
    line: string,
    good: string[],
    bad: string[],
    /** Folded in when the service speaks UDP, where the trade moves. */
    udpGood?: string[],
    udpBad?: string[],
}

const LAYERS: Record<string, Layer> = {
    [Transport.PROXY]: {
        line: "Terminates and reopens the connection — exact rewriting, and the faster of the two.",
        good: [
            "Carries bulk traffic 2-5× faster, and scales better with threads",
            "Rewriting is exact, at any length",
            "The kernel does the reassembly",
            "Any number of filters, in one process",
            "A slow filter slows the sender; nothing is dropped",
            "Your service still sees the real client address",
        ],
        bad: [
            "Fail-open is rebuilt in userspace, not the kernel's",
        ],
        udpGood: [
            "Datagrams are rewritten exactly — no sequence numbers to break",
            "Your service still sees the real client address (transparent IP spoofing)",
        ],
    },
    [Transport.NFQUEUE]: {
        line: "Verdicts on the real packets — nothing in the path, and the kernel keeps forwarding if a filter dies.",
        good: [
            "Your service sees the original packets, from the original client",
            "If the filter process dies, traffic keeps flowing — by kernel guarantee",
            "Nothing is terminated: no relay, no second connection",
        ],
        bad: [
            "A userspace round trip per packet: a fraction of the bulk throughput",
            "Reassembly is rebuilt in userspace",
            "One process per filter, up to eight",
            "Patterns can only block, never rewrite",
        ],
        udpGood: ["Fully transparent on UDP, and Python rewrites datagrams exactly"],
    },
    [Transport.EXTERNAL]: {
        line: "Steers the traffic into a proxy you wrote — any protocol, but firegex inspects nothing.",
        good: [
            "Any protocol, however exotic",
            "Two stateless rules; firegex runs nothing",
            "Your proxy sits in the path invisibly",
        ],
        bad: [
            "No filter can be attached — your proxy does the work",
            "No blocks, no statistics, no log: firegex sees nothing",
        ],
    },
}

const LABELS: Record<string, string> = {
    [Transport.PROXY]: "Proxy",
    [Transport.NFQUEUE]: "NFQUEUE",
    [Transport.EXTERNAL]: "Your own proxy",
}

function Points({ items, good }: { items: string[], good: boolean }) {
    return <Stack gap={7} style={{ flex: 1 }}>
        <Group gap={6} wrap="nowrap">
            <Box style={{
                width: 16, height: 16, borderRadius: 8, flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: good ? 'rgba(32,201,151,0.15)' : 'rgba(253,126,20,0.15)',
                color: good ? 'var(--mantine-color-teal-4)' : 'var(--mantine-color-orange-4)',
            }}>
                {good ? <FaPlus size={8} /> : <FaMinus size={8} />}
            </Box>
            <Text size="xs" fw={600} c={good ? "teal.4" : "orange.4"}>
                {good ? "What it buys" : "What it costs"}
            </Text>
        </Group>
        {items.map(text => <Text key={text} size="xs" c="dimmed" style={{ lineHeight: 1.45 }}>
            {text}
        </Text>)}
    </Stack>
}

export default function LayerChoice({ value, onChange, proto }: {
    value: string,
    onChange: (value: string) => void,
    proto: string,
}) {
    const [open, setOpen] = useState(false)
    const layer = LAYERS[value] ?? LAYERS[Transport.PROXY]
    const udp = proto === L4.UDP
    const unavailable = Object.keys(LABELS).filter(t => !carries(t, proto))
    const good = [...layer.good, ...(udp ? layer.udpGood ?? [] : [])]
    const bad = [...layer.bad, ...(udp ? layer.udpBad ?? [] : [])]

    return <>
        <Group justify="space-between" align="center" mb={6}>
            <Box>
                <Text size="sm" fw={500}>Network layer</Text>
                <Text size="xs" c="dimmed">
                    How the traffic is intercepted. What is done with it is up to the filters.
                </Text>
            </Box>
            {/* Above the control, not beside it: the layer buttons stay clickable while
                it is open, so the comparison can be read by switching between them. */}
            <Popover opened={open} onChange={setOpen} width={420} position="top-end"
                withArrow shadow="md" radius="md">
                <Popover.Target>
                    {/* The tooltip is silenced while the popover is open, or both anchor
                        to the same target and the tooltip renders as an empty frame
                        behind it. */}
                    <Tooltip label="What this layer buys and costs" position="left" disabled={open}>
                        <ActionIcon variant="subtle" color="gray" onClick={() => setOpen(o => !o)}>
                            <IoInformationCircleOutline size={19} />
                        </ActionIcon>
                    </Tooltip>
                </Popover.Target>
                <Popover.Dropdown>
                    <Group gap="xs" mb={6}>
                        <Badge size="sm" radius="sm" variant="light" color="indigo">
                            {LABELS[value]}
                        </Badge>
                        {udp ? <Badge size="sm" radius="sm" variant="outline" color="gray">UDP</Badge> : null}
                    </Group>
                    <Text size="xs" c="dimmed" mb="sm">{layer.line}</Text>
                    <Divider mb="sm" />
                    <Group align="flex-start" gap="lg" wrap="nowrap">
                        <Points items={good} good />
                        <Points items={bad} good={false} />
                    </Group>
                </Popover.Dropdown>
            </Popover>
        </Group>
        {/* Disabled rather than hidden, unlike the protocol picker above: hiding two of
            three would leave a control with one option, which is not a control. A
            greyed-out button that says why is a button you can learn from. */}
        <SegmentedControl fullWidth value={value} onChange={onChange}
            data={Object.entries(LABELS).map(([transport, label]) => ({
                label,
                value: transport,
                disabled: !carries(transport, proto),
            }))}
        />
        <Space h={6} />
        <Text size="xs" c="dimmed">{layer.line}</Text>
        {unavailable.length > 0 ? <Text size="xs" c="dimmed" mt={4}>
            {unavailable.map(t => LABELS[t]).join(" and ")}
            {unavailable.length > 1 ? " are" : " is"} not available for a service that speaks
            TLS: decrypting means terminating the connection, and only this layer does that.
            Set the protocol to TCP to use {unavailable.length > 1 ? "them" : "it"}.
        </Text> : null}
    </>
}
