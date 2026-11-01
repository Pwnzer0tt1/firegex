import { CodeHighlight } from '@mantine/code-highlight';
import { Badge, Box, Button, Code, Collapse, Group, Space, Stack, Text } from '@mantine/core';
import { useState } from 'react';
import { MdEdit } from 'react-icons/md';
import { TbEye, TbShieldLock } from 'react-icons/tb';
import { bareAddress, ipInterfacesQuery, isInterfaceName } from '../../js/utils';
import { addressCapabilities, addressTags } from './AddressOptions';
import { Address, decrypts, L4, protoLabel, Service } from './utils';

/** How one address is reached, in the words the form groups it under. */
const kindOf = (service: Service, address: Address) =>
    service.proto === L4.HTTP
        ? ({ [L4.TLS]: "HTTPS", [L4.QUIC]: "HTTP/3" }[address.edge] ?? "HTTP")
        : protoLabel(service.proto)

/** Whether firegex decrypts what arrives at this address. */
const opened = (service: Service, address: Address) =>
    service.proto === L4.HTTP ? address.edge === L4.TLS || address.edge === L4.QUIC : decrypts(service)

/**
 * Where clients reach the service, and how — read only.
 *
 * Addresses are changed in Settings, in the same list they were created in: a second
 * editor here, with its own words and its own dialog, described the same service two
 * ways. This only says what is in force.
 */
export default function AddressList({ service, onEdit }: { service: Service, onEdit: () => void }) {
    const addresses = service.addresses ?? []
    //: What each interface carries now, so a row named `wg0` can say where that is.
    const interfaces = ipInterfacesQuery()
    const where = (ip_int: string) => {
        if (!interfaces.data) return null
        if (isInterfaceName(ip_int)) {
            const ips = interfaces.data
                .filter(i => i.name === ip_int && !i.addr.toLowerCase().startsWith("fe80:"))
                .map(i => i.addr)
            return ips.length > 0 ? `now ${ips.join(", ")}` : "no address on it right now"
        }
        const names = interfaces.data.filter(i => i.addr === bareAddress(ip_int)).map(i => i.name)
        return names.length > 0 ? `on ${names.join(", ")}` : null
    }

    return <>
        <Group justify="space-between" align="center" wrap="nowrap">
            <Box style={{ minWidth: 0 }}>
                <Text fw={600} size="sm">Where clients reach it</Text>
                <Text size="xs" c="dimmed">The same filters run on every one of these.</Text>
            </Box>
            <Button size="xs" variant="default" leftSection={<MdEdit size={12} />}
                style={{ flexShrink: 0 }} onClick={onEdit}>Edit in Settings</Button>
        </Group>
        <Space h="sm" />
        <Stack gap={6}>
            {addresses.map(address => {
                const notes = [
                    where(address.ip_int),
                    ...addressTags(address,
                        addressCapabilities(service.proto, service.transport, address.edge))
                        .map(tag => tag.hint),
                ].filter(Boolean)
                const locked = opened(service, address)
                return <Group key={address.address_id} gap="sm" wrap="nowrap" align="baseline">
                    <Badge size="sm" radius="sm" variant="light" color={locked ? "grape" : "gray"}
                        leftSection={locked ? <TbShieldLock size={10} /> : undefined}
                        style={{ flexShrink: 0, width: 84 }}>
                        {kindOf(service, address)}
                    </Badge>
                    <Code style={{ flexShrink: 0 }}>{bareAddress(address.ip_int)}:{address.port}</Code>
                    {notes.length > 0 ? <Text size="xs" c="dimmed" style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
                        {notes.join(" · ")}
                    </Text> : null}
                </Group>
            })}
        </Stack>

        <PlaintextCapture service={service} />
    </>
}

/**
 * Where the decrypted traffic of every TLS and QUIC service can be watched.
 *
 * The engine decrypts inside the process that filters, so the plaintext never becomes
 * packets on any interface — which is exactly what removed the two loopback ports a TLS
 * service used to occupy, and would also have removed any way to watch it. So the engine
 * writes the decrypted stream out itself, onto `firegex0`: one interface carrying every
 * TLS service's plaintext and nothing else, which is what a capture tool wants to be
 * pointed at.
 *
 * What arrives there is a **reconstruction** — the engine frames the bytes it decrypted
 * as the TCP stream they were, because the stream that actually crossed the wire was
 * encrypted. Wireshark follows it normally; it is not the wire, and the interface says so.
 *
 * A QUIC service is carried there too, one TCP stream per QUIC stream, which costs one
 * more piece of invention: the streams of one connection share its four-tuple, so each is
 * given a synthetic client port to be told apart by. An operator reading a port out of
 * that capture has to know it names a stream and not a socket, which is why the panel
 * says so rather than leaving it to be discovered.
 *
 * Collapsed by default: it is a thing you go looking for while debugging a filter that is
 * not matching, not something that should sit in the way the rest of the time.
 */
function PlaintextCapture({ service }: { service: Service }) {
    const [open, setOpen] = useState(false)
    if (!(service.addresses ?? []).some(a => opened(service, a))) return null
    // An HTTPS service carries QUIC too, on whichever of its addresses say HTTP/3, and the
    // invented port needs saying there exactly as much.
    const quic = service.proto === L4.QUIC
        || (service.proto === L4.HTTP && (service.addresses ?? []).some(a => a.edge === L4.QUIC))

    return <Box mt="md">
        <Group gap="xs">
            <Button size="compact-xs" variant="subtle" leftSection={<TbEye size={13} />}
                onClick={() => setOpen(o => !o)}>
                {open ? "Hide" : "Watch the decrypted traffic"}
            </Button>
        </Group>
        <Collapse expanded={open}>
            <Space h="xs" />
            <Text size="xs" c="dimmed">
                Every decrypted service's traffic is written to <Code>firegex0</Code>, and
                nothing else is. Point Wireshark or tcpdump at it on the host running
                firegex — the container shares its network namespace, so the interface is
                there — and you get the decrypted traffic of the whole instance, both
                directions, with no filter to write.
            </Text>
            <Space h="xs" />
            <CodeHighlight language="bash" withCopyButton
                copyLabel="Copy the capture command"
                code={`sudo tcpdump -i firegex0 -w decrypted.pcap`} />
            <Space h="xs" />
            <Text size="xs" c="dimmed">
                These are reconstructed packets, not the ones that crossed the wire — what
                crossed the wire was encrypted, and the engine decrypts inside the process
                rather than putting the plaintext back on a socket. That is what lets a TLS
                service occupy no extra port at all. What is written is decrypted traffic:
                as sensitive as the private key that would have produced it, so treat the
                file the same way.
            </Text>
            {quic ? <>
                <Space h="xs" />
                <Text size="xs" c="dimmed">
                    On QUIC each stream arrives as a TCP stream of its own, and over
                    HTTP/3 that is one per request — what you see is the same HTTP/1.1
                    the filters were shown, because what crossed the wire was a
                    compressed header block inside an encrypted packet. The client
                    <b> port is invented</b>: the streams of one connection share the
                    client's real port, so each is given one of its own to be told apart
                    by. It names a stream, not a socket — the address beside it is real.
                </Text>
            </> : null}
        </Collapse>
    </Box>
}
