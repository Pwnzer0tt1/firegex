import { CodeHighlight } from '@mantine/code-highlight';
import { ActionIcon, Badge, Box, Button, Card, Code, Collapse, Group, Modal, Space, Stack, Text, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { BsPlusLg, BsTrashFill } from 'react-icons/bs';
import { MdEdit } from 'react-icons/md';
import { TbEye, TbShieldLock } from 'react-icons/tb';
import { bareAddress, errorNotify, ipInterfacesQuery, isAddressOrInterface, isInterfaceName, isIpAddress, okNotify } from '../../js/utils';
import { addressKind, BADGE_WIDTH } from '../InterfaceInput';
import PortAndInterface from '../PortAndInterface';
import YesNoModal from '../YesNoModal';
import { Address, decrypts, Service, serviceQueryKey, services, Transport } from './utils';

type Values = { ip_int: string, port: number, proxy_ip: string, proxy_port: number }

function AddressModal({ opened, onClose, service, edit }: {
    opened: boolean, onClose: () => void, service: Service, edit?: Address,
}) {
    const queryClient = useQueryClient()
    const [busy, setBusy] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const isExternal = service.transport === Transport.EXTERNAL

    const form = useForm<Values>({
        initialValues: { ip_int: "127.0.0.1", port: 80, proxy_ip: "127.0.0.1", proxy_port: 8080 },
        validate: {
            ip_int: v => !isAddressOrInterface(v, { cidr: !isExternal })
                ? "Not an IP address, and not an interface name either"
                : (isExternal && isInterfaceName(v)
                    ? "Your own proxy is handed one address: the return rule has to put the original port back, and an interface is not one address"
                    : null),
            port: v => (v > 0 && v < 65536) ? null : "Invalid port",
            proxy_ip: v => (!isExternal || isIpAddress(v)) ? null : "Not an IP address: your proxy is reached at one, never at an interface",
            proxy_port: v => (!isExternal || (v > 0 && v < 65536)) ? null : "Your proxy's port is required",
        },
    })

    useEffect(() => {
        if (!opened) return
        setError(null)
        if (edit) form.setValues({
            //: Only the prefix that means "this one address" comes off. Cutting at the
            //  first slash took a real range down to its first host and saved it as one,
            //  which is a service quietly protecting a fraction of what it did before.
            ip_int: bareAddress(edit.ip_int), port: edit.port,
            proxy_ip: edit.proxy_ip ?? "127.0.0.1", proxy_port: edit.proxy_port ?? 8080,
        })
        else form.reset()
    }, [opened, edit?.address_id])

    const submit = async (values: Values) => {
        setBusy(true)
        const payload = {
            ip_int: values.ip_int, port: values.port,
            ...(isExternal ? { proxy_ip: values.proxy_ip, proxy_port: values.proxy_port } : {}),
        }
        try {
            const err = edit
                ? await services.editAddress(service.service_id, edit.address_id, payload)
                : await services.addAddress(service.service_id, payload)
            if (err) setError(err)
            else {
                okNotify(edit ? "Address updated" : "Address added",
                    `${values.ip_int}:${values.port} is now part of ${service.name}`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
                onClose()
            }
        } catch (err) {
            setError(`${err}`)
        }
        setBusy(false)
    }

    return <Modal opened={opened} onClose={onClose} centered
        title={edit ? "Move this address" : "Protect another address"}>
        <form onSubmit={form.onSubmit(submit)}>
            <PortAndInterface form={form} int_name="ip_int" port_name="port"
                label="Where the service answers"
                description={isExternal
                    ? "One address and its port. This layer rewrites the destination and puts the original port back on the way out, which takes an address it can recognise."
                    : "An IP address, or the name of an interface — an interface protects whatever address that link is carrying, an address protects that one alone."}
                includeInterfaceNames={!isExternal} />
            {isExternal ? <>
                <Space h="md" />
                <PortAndInterface form={form} int_name="proxy_ip" port_name="proxy_port"
                    label="Where your proxy listens for it" includeInterfaceNames={false} />
                <Text size="xs" c="dimmed" mt={6}>
                    Its own port, not one another address already uses: the return rule puts
                    the original port back by recognising your proxy's, so two addresses
                    behind the same endpoint could not be told apart on the way out.
                </Text>
            </> : null}
            <Text size="xs" c="dimmed" mt="md">
                {edit
                    ? "Only this address stops being protected while the rules are replaced. The rest of the service keeps its connections."
                    : "The chain is already running, so this only points one more address at it. Nothing is dropped."}
            </Text>
            <Group justify="flex-end" mt="xl">
                <Button loading={busy} type="submit">{edit ? "Save" : "Add address"}</Button>
            </Group>
        </form>
        {error ? <Text c="red" size="sm" mt="md">{error}</Text> : null}
    </Modal>
}

/**
 * Everywhere one service is protected.
 *
 * A list rather than a field, because a service routinely answers on more than one
 * address and one chain should cover all of them — two services with hand-copied
 * chains is how one of them silently stops being protected.
 */
export default function AddressList({ service }: { service: Service }) {
    const queryClient = useQueryClient()
    const [addOpen, setAddOpen] = useState(false)
    const [editing, setEditing] = useState<Address | null>(null)
    const [removing, setRemoving] = useState<Address | null>(null)
    const addresses = service.addresses ?? []
    const only = addresses.length === 1
    //: What each interface is carrying at the moment, so a row named `wg0` can say
    //  where that actually is. An interface with nothing on it is worth seeing too:
    //  on the proxy layer a UDP relay has to bind one of these.
    const interfaces = ipInterfacesQuery()
    const carriedBy = (name: string) => (interfaces.data ?? [])
        .filter(i => i.name === name && !i.addr.toLowerCase().startsWith("fe80:"))
        .map(i => i.addr)
    //: …and the other direction, which is the same question asked of an address row.
    const arrivesOn = (addr: string) => (interfaces.data ?? [])
        .filter(i => i.addr === addr).map(i => i.name)

    /**
     * What a row says beside the address, in the words the picker used to choose it.
     *
     * The same pairing as the list it was chosen from — an interface carries addresses,
     * an address sits on an interface — because this is where an operator comes back to
     * check what they picked, and finding it described differently is a reason to wonder
     * whether it is the same thing.
     */
    const rowDetail = (ip_int: string) => {
        if (isInterfaceName(ip_int)) {
            if (!interfaces.data) return ""
            const ips = carriedBy(ip_int)
            return ips.length > 0 ? `now ${ips.join("\u00a0· ")}` : "no address on it right now"
        }
        const names = arrivesOn(bareAddress(ip_int))
        return names.length > 0 ? `on ${names.join(", ")}` : ""
    }

    const remove = async (address: Address) => {
        try {
            const err = await services.deleteAddress(service.service_id, address.address_id)
            if (err) errorNotify("Could not remove the address", err)
            else {
                okNotify("Address removed", `${address.ip_int}:${address.port} is no longer protected`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }
        } catch (err) {
            errorNotify("Could not remove the address", `${err}`)
        }
    }

    return <>
        <Group justify="space-between" align="center" wrap="nowrap">
            <Box style={{ minWidth: 0 }}>
                <Text fw={600} size="sm">Protected addresses</Text>
                <Text size="xs" c="dimmed">
                    {service.transport === Transport.EXTERNAL
                        ? "Each one handed to your own proxy. Adding one costs no connections."
                        : "Addresses, or the interfaces they arrive on. The same chain runs on every one of them, and adding one costs no connections."}
                </Text>
            </Box>
            <Button size="xs" variant="light" leftSection={<BsPlusLg size={12} />}
                style={{ flexShrink: 0 }}
                onClick={() => setAddOpen(true)}>Add an address</Button>
        </Group>
        <Space h="sm" />
        <Stack gap="xs">
            {addresses.map(address => {
            const kind = addressKind(address.ip_int)
            const detail = rowDetail(address.ip_int)
            return <Card key={address.address_id} withBorder radius="md" p="xs"
                bg="transparent" style={{ borderColor: 'var(--mantine-color-dark-4)' }}>
                <Group justify="space-between" wrap="nowrap">
                    {/* The row a service is read from is laid out like the list it was
                        chosen in: the same badge, at the same width, then the value, then
                        what is on it. No protocol badge — it is a property of the service,
                        the header already says it once, and repeating it on every row is
                        noise that grows with the list. */}
                    <Group gap="xs" wrap="nowrap" align="flex-start" style={{ minWidth: 0 }}>
                        <Tooltip position="bottom" disabled={!isInterfaceName(address.ip_int)}
                            label="An interface, not an address: the rules match on the name, so this follows whatever address the link is carrying.">
                            <Badge size="xs" variant="light" color={kind.color}
                                style={{ flexShrink: 0, width: BADGE_WIDTH, marginTop: 4 }}>
                                {kind.label}
                            </Badge>
                        </Tooltip>
                        {/* The badge is a column of its own, exactly as in the list this was
                            chosen from: everything that has to wrap wraps under the value
                            rather than under the badge. */}
                        <Group gap="xs" wrap="wrap" align="center"
                            style={{ flex: '1 1 auto', minWidth: 0, rowGap: 2 }}>
                        <Code>{bareAddress(address.ip_int)}:{address.port}</Code>
                        {decrypts(service) ? <Tooltip position="bottom"
                            label="The engine decrypts here: clients dial this address as they always did, and the filters see the plaintext inside the process.">
                            <Badge size="xs" variant="light" color="grape"
                                leftSection={<TbShieldLock size={10} />}>
                                TLS
                            </Badge>
                        </Tooltip> : null}
                        {address.proxy_port ? <Badge size="xs" variant="light" color="cyan">
                            → {address.proxy_ip ?? "127.0.0.1"}:{address.proxy_port}
                        </Badge> : null}
                        {detail ? <Text size="xs" c="dimmed" ff="monospace"
                            style={{ flex: '1 1 80px', minWidth: 80, overflowWrap: 'anywhere' }}>
                            {detail}
                        </Text> : null}
                        </Group>
                    </Group>
                    <Group gap={4} wrap="nowrap">
                        <Tooltip label="Move this address" position="bottom">
                            <ActionIcon size="sm" variant="subtle" onClick={() => setEditing(address)}>
                                <MdEdit size={14} />
                            </ActionIcon>
                        </Tooltip>
                        <Tooltip position="bottom"
                            label={only ? "A service has to be reachable somewhere" : "Stop protecting this address"}>
                            <Box>
                                <ActionIcon size="sm" variant="subtle" color="red" disabled={only}
                                    onClick={() => setRemoving(address)}>
                                    <BsTrashFill size={12} />
                                </ActionIcon>
                            </Box>
                        </Tooltip>
                    </Group>
                </Group>
            </Card>
            })}
        </Stack>

        <PlaintextCapture service={service} />

        <AddressModal opened={addOpen} onClose={() => setAddOpen(false)} service={service} />
        <AddressModal opened={!!editing} onClose={() => setEditing(null)} service={service}
            edit={editing ?? undefined} />
        <YesNoModal
            title="Stop protecting this address?"
            description={removing
                ? `${removing.ip_int}:${removing.port} keeps answering, without any filter in front of it. The rest of ${service.name} is untouched.`
                : ""}
            opened={!!removing}
            onClose={() => setRemoving(null)}
            action={async () => { if (removing) await remove(removing) }}
        />
    </>
}

/**
 * Where the decrypted traffic of every TLS service can be watched.
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
 * Collapsed by default: it is a thing you go looking for while debugging a filter that is
 * not matching, not something that should sit in the way the rest of the time.
 */
function PlaintextCapture({ service }: { service: Service }) {
    const [open, setOpen] = useState(false)
    if (!decrypts(service)) return null

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
                Every TLS service's plaintext is written to <Code>firegex0</Code>, and
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
        </Collapse>
    </Box>
}
