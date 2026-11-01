import { ActionIcon, Badge, Box, Divider, Group, Popover, SegmentedControl, Space, Stack, Text, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { IoInformationCircleOutline } from 'react-icons/io5';
import { TbShieldLock } from 'react-icons/tb';
import { decrypts, L4, protoLabel, Transport } from './utils';

/**
 * Choosing what the service speaks — one row of five, with the encrypted ones marked.
 *
 * A bare row of five was reported as confusing, and it deserved to be: `TCP` and `HTTP`
 * side by side gave an operator with a plain HTTP/1.1 service on `:80` no way to tell
 * which was theirs, and picking `HTTP` then asked for a certificate for something with
 * nothing encrypted about it. What fixed it was making **is the traffic encrypted?** the
 * visible division, since it is the one the certificate hangs off.
 *
 * That division is kept, but it is no longer a question of its own. Asked as two stacked
 * controls ("Is the traffic encrypted?", then "What does it speak?", then a sentence) it
 * read as two decisions for one choice. Now TCP and UDP come first, then HTTP(S), then
 * TLS and QUIC with a lock: those two are always decrypted. HTTP(S) carries no lock
 * because whether it decrypts depends on its addresses, which the form groups as HTTP,
 * HTTPS and HTTP/3 once it is picked.
 *
 * **The text stays short on purpose.** What an operator needs here is which option is
 * theirs, which is one clause each; what a protocol costs and what filters can be
 * attached to it is documentation, and it is a click away in the popover.
 */

type Protocol = {
    /** One clause. The reason this option is yours. */
    line: string,
    /** The service this is the answer for. */
    pick: string[],
    /** What a filter is handed. */
    sees: string[],
    /** What choosing it costs you in setup. */
    needs: string[],
}

const PROTOCOLS: Record<string, Protocol> = {
    [L4.TCP]: {
        line: "Any stream in the clear. For a web service, pick HTTP(S).",
        pick: [
            "Anything unencrypted on TCP that is not a web service: a game protocol, a shell, a custom binary protocol",
            "A web service, even one only on plain HTTP, is better as HTTP(S): it is built for it, and gains HTTPS and HTTP/3 ways in without becoming another service",
        ],
        sees: [
            "The bytes as they travel",
            "A filter asking for an HttpRequest gets one — HTTP/1.1 parsed, and HTTP/2 in the clear recognised from its preface and rendered as the same HTTP/1.1",
        ],
        needs: ["Nothing but the addresses to protect"],
    },
    [L4.UDP]: {
        line: "Datagrams in the clear, one filter state per client flow.",
        pick: ["Anything unencrypted on UDP: a game server, DNS, a custom protocol"],
        sees: [
            "One datagram at a time, both directions",
            "RawPacket only: every other model is built on a stream, and a datagram is not one",
        ],
        needs: ["Nothing but the addresses to protect"],
    },
    [L4.TLS]: {
        line: "TCP under TLS, decrypted here.",
        pick: ["Any protocol under TLS that is not a web service — for HTTPS, pick HTTP(S)"],
        sees: [
            "The decrypted stream, and the same models a cleartext service gives",
            "The protocol the two ends agreed on: ALPN is mirrored, so h2 is rendered as HTTP/1.1 too",
        ],
        needs: [
            "A certificate and its key, in PEM",
            "The proxy layer: decrypting means terminating the connection",
        ],
    },
    [L4.QUIC]: {
        line: "UDP with TLS 1.3 and streams inside it, decrypted here.",
        pick: ["A QUIC service — in practice HTTP/3, which is what the engine offers by default"],
        sees: [
            "One stream at a time, with its own filter state from beginning to end",
            "HTTP/3 rendered as HTTP/1.1, so one pattern covers it and the TCP service beside it",
        ],
        needs: [
            "A certificate and its key, in PEM",
            "The proxy layer, with no alternative: past its first packet QUIC encrypts the frames and the stream boundaries too",
        ],
    },
    [L4.HTTP]: {
        line: "A web service reached over HTTP, HTTPS and HTTP/3 — as many ports of each as you need, all through the same filters.",
        pick: [
            "Any web service, including one only on plain HTTP",
            "One reached more than one way — :80, :443 and :443 over UDP — which would otherwise be two or three services with the chain copied between them by hand",
        ],
        sees: [
            "Every version as the same HTTP/1.1, so one pattern and one Python filter cover all three",
            "gRPC included: the request line, the headers and the trailer section",
        ],
        needs: [
            "A certificate and its key, in PEM — only once it has an HTTPS or HTTP/3 address",
            "The proxy layer",
        ],
    },
}

/** The transports in the clear, then the web, then the two that are always decrypted —
 *  which wear a lock. HTTP(S) does not: whether it decrypts depends on its addresses. */
const ORDER = [L4.TCP, L4.UDP, L4.HTTP, L4.TLS, L4.QUIC]

function Section({ title, items }: { title: string, items: string[] }) {
    return <Stack gap={5}>
        <Text size="xs" fw={600} c="indigo.4">{title}</Text>
        {items.map(text => <Text key={text} size="xs" c="dimmed" style={{ lineHeight: 1.45 }}>
            {text}
        </Text>)}
    </Stack>
}

export default function ProtocolChoice({ value, transport, onChange }: {
    value: string,
    /** The layer chosen below: it cannot carry anything that has to be decrypted. */
    transport: string,
    onChange: (value: string) => void,
}) {
    const [open, setOpen] = useState(false)
    const proto = PROTOCOLS[value] ?? PROTOCOLS[L4.TCP]
    const encrypted = decrypts({ proto: value })
    //: One rule, asked once: a layer that does not terminate cannot decrypt.
    //  Picked while NFQUEUE is selected, the form moves the service to the proxy; only a
    //  service handed to the operator's own proxy has no layer here that could.
    const canDecrypt = transport !== Transport.EXTERNAL

    return <>
        <Group justify="space-between" align="center" mb={8}>
            <Box style={{ minWidth: 0 }}>
                <Text size="sm" fw={500}>Protocol</Text>
            </Box>
            <Popover opened={open} onChange={setOpen} width={420} position="top-end"
                withArrow shadow="md" radius="md">
                <Popover.Target>
                    <Tooltip label="What this is for, and what it needs" position="left" disabled={open}>
                        <ActionIcon variant="subtle" color="gray" onClick={() => setOpen(o => !o)}>
                            <IoInformationCircleOutline size={19} />
                        </ActionIcon>
                    </Tooltip>
                </Popover.Target>
                <Popover.Dropdown>
                    <Group gap="xs" mb={6}>
                        <Badge size="sm" radius="sm" variant="light"
                            color={encrypted ? "grape" : "indigo"}
                            leftSection={encrypted ? <TbShieldLock size={10} /> : undefined}>
                            {protoLabel(value)}
                        </Badge>
                    </Group>
                    <Text size="xs" c="dimmed" mb="sm">{proto.line}</Text>
                    <Divider mb="sm" />
                    <Stack gap="sm">
                        <Section title="Pick it when" items={proto.pick} />
                        <Section title="What the filters are shown" items={proto.sees} />
                        <Section title="What it needs" items={proto.needs} />
                    </Stack>
                </Popover.Dropdown>
            </Popover>
        </Group>

        {/* Disabled, not removed: an option that vanishes leaves nothing to ask about. */}
        <SegmentedControl fullWidth value={value} onChange={onChange}
            data={ORDER.map(p => {
                const locked = decrypts({ proto: p }) && p !== L4.HTTP
                return {
                    value: p,
                    disabled: decrypts({ proto: p }) && !canDecrypt,
                    label: locked
                        ? <Group gap={4} justify="center" wrap="nowrap">
                            <TbShieldLock size={12} style={{ flexShrink: 0 }} />
                            <span>{protoLabel(p)}</span>
                        </Group>
                        : protoLabel(p),
                }
            })}
        />
        <Space h={8} />
        <Text size="xs" c="dimmed">{proto.line}</Text>
    </>
}
