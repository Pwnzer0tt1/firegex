import { ActionIcon, Badge, Box, Divider, Group, Popover, SegmentedControl, Space, Stack, Text, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { IoInformationCircleOutline } from 'react-icons/io5';
import { TbShieldLock } from 'react-icons/tb';
import { carries, decrypts, L4, protoLabel } from './utils';

/**
 * Choosing what the service speaks — two questions, not one list of five answers.
 *
 * The list of five was reported as confusing and it deserved to be. `TCP`, `UDP`, `TLS`,
 * `QUIC` and `HTTP` side by side look like five alternatives on one axis, and they are
 * not: an operator with a plain HTTP/1.1 service on `:80` had no way to tell whether
 * `TCP` or `HTTP` was meant for them — both are true sentences about their service — and
 * picking `HTTP` then asked for a certificate for something with nothing encrypted about
 * it.
 *
 * So the first question is the one that actually divides them, and it is the one the
 * certificate hangs off: **is the traffic encrypted?** The second question is then asked
 * inside that answer, and only ever offers protocols of that kind —
 *
 *   - in the clear: `TCP` · `UDP`
 *   - encrypted: `TLS` · `QUIC` · `HTTPS`
 *
 * Nothing is derived and nothing is hidden: every option is the protocol under its own
 * name, which is what the service is stored as and what the rest of the interface calls
 * it. An earlier attempt asked "on what transport?" and computed the protocol from the
 * pair — the names then appeared only in a badge under the controls, which reads as the
 * form having decided something on your behalf.
 *
 * **The text stays short on purpose.** What an operator needs here is which option is
 * theirs, which is one clause each; what a protocol costs and what filters can be
 * attached to it is documentation, and it is a click away in the popover rather than
 * three paragraphs nobody reads twice.
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
        line: "A stream in the clear — HTTP/1.1 and HTTP/2 included.",
        pick: [
            "Anything unencrypted on TCP: a web service on :80, a game protocol, a shell",
            "The default, and the right answer unless the traffic is encrypted",
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
        pick: ["Everything reaching this port is encrypted — an HTTPS service, or any TLS protocol"],
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
        line: "Every version of HTTP through one chain — HTTP/1.1 and HTTP/2 on its TCP addresses, encrypted or in the clear, HTTP/3 on its UDP ones.",
        pick: [
            "A web service reached more than one way: :80, :443 and :443 over UDP, which would otherwise be two or three services with the chain copied between them by hand",
            "Its cleartext ports come with it — whether a connection is TLS is decided per connection, from what the client sent",
        ],
        sees: [
            "Every version as the same HTTP/1.1, so one pattern and one Python filter cover all three",
            "gRPC included: the request line, the headers and the trailer section",
        ],
        needs: [
            "A certificate and its key, in PEM — including for the cleartext addresses beside them",
            "The proxy layer, and each address saying whether it is reached over TCP or UDP",
        ],
    },
}

/** The first question. It is the one the certificate hangs off, and nothing else. */
const CLEAR = "clear"
const ENCRYPTED = "encrypted"

/** The second question, asked inside the first one's answer. */
const OFFERED: Record<string, string[]> = {
    [CLEAR]: [L4.TCP, L4.UDP],
    [ENCRYPTED]: [L4.TLS, L4.QUIC, L4.HTTP],
}

const edgeOf = (proto: string) => decrypts({ proto }) ? ENCRYPTED : CLEAR

/**
 * The same service, said the other way.
 *
 * Switching the first answer has to land on something, and the honest something is the
 * counterpart on the same transport: a TCP service that turns out to be encrypted is TLS,
 * a UDP one is QUIC, and back again. `http` is several transports at once, so it comes
 * back as the one its first address would be.
 */
const acrossEdge = (proto: string, edge: string) => edge === ENCRYPTED
    ? (proto === L4.UDP ? L4.QUIC : L4.TLS)
    : (proto === L4.QUIC ? L4.UDP : L4.TCP)

function Section({ title, items }: { title: string, items: string[] }) {
    return <Stack gap={5}>
        <Text size="xs" fw={600} c="indigo.4">{title}</Text>
        {items.map(text => <Text key={text} size="xs" c="dimmed" style={{ lineHeight: 1.45 }}>
            {text}
        </Text>)}
    </Stack>
}

/** One question: its label, and the control that answers it. */
function Question({ label, children }: { label: string, children: React.ReactNode }) {
    return <Box>
        <Text size="xs" fw={500} c="dimmed" mb={4}>{label}</Text>
        {children}
    </Box>
}

export default function ProtocolChoice({ value, transport, onChange }: {
    value: string,
    /** The layer chosen below: it cannot carry anything that has to be decrypted. */
    transport: string,
    onChange: (value: string) => void,
}) {
    const [open, setOpen] = useState(false)
    const proto = PROTOCOLS[value] ?? PROTOCOLS[L4.TCP]
    const edge = edgeOf(value)
    //: One rule, asked once: a layer that does not terminate cannot decrypt.
    const canDecrypt = carries(transport, L4.TLS)

    return <>
        <Group justify="space-between" align="center" mb={8}>
            <Box style={{ minWidth: 0 }}>
                <Text size="sm" fw={500}>What the service speaks</Text>
                <Text size="xs" c="dimmed">What is on the wire, and whether firegex has to decrypt it.</Text>
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
                            color={edge === ENCRYPTED ? "grape" : "indigo"}
                            leftSection={edge === ENCRYPTED ? <TbShieldLock size={10} /> : undefined}>
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

        <Stack gap="xs">
            {/* Disabled, not removed, the same way the layer picker below says no and from
                the same `carries` rule: an option that vanishes leaves nothing to ask
                about. The lock answers, before the click, which half of this form will
                want a certificate. */}
            <Question label="Is the traffic encrypted?">
                <SegmentedControl fullWidth value={edge}
                    onChange={e => onChange(acrossEdge(value, e))}
                    data={[
                        { value: CLEAR, label: "In the clear" },
                        {
                            value: ENCRYPTED,
                            disabled: !canDecrypt,
                            label: <Group gap={4} justify="center" wrap="nowrap">
                                <TbShieldLock size={12} style={{ flexShrink: 0 }} />
                                <span>Encrypted</span>
                            </Group>,
                        },
                    ]}
                />
            </Question>

            <Question label={edge === ENCRYPTED ? "Encrypted with what?" : "What does it speak?"}>
                <SegmentedControl fullWidth value={value} onChange={onChange}
                    data={OFFERED[edge].map(p => ({ value: p, label: protoLabel(p) }))}
                />
            </Question>
        </Stack>

        <Space h={8} />
        <Text size="xs" c="dimmed">{proto.line}</Text>
        {!canDecrypt ? <Text size="xs" c="dimmed" mt={4}>
            Encrypted traffic needs the proxy layer: decrypting means terminating the
            connection, and the layer chosen below does not.
        </Text> : null}
    </>
}
