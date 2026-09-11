import { Badge, Box, Button, Card, Group, Menu, Text, Tooltip } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { FaPlay, FaStop, FaTrash } from 'react-icons/fa';
import { IoSettingsSharp } from 'react-icons/io5';
import { MdChevronRight, MdMoreHoriz } from 'react-icons/md';
import { TbHexagon, TbShieldLock } from 'react-icons/tb';
import { errorNotify, isMediumScreen, okNotify } from '../../js/utils';
import YesNoModal from '../YesNoModal';
import AddEditService from './AddEditService';
import { Address, decrypts, L4, Service, serviceQueryKey, services, Transport } from './utils';

/** What the network layer means, in one line, where the operator is choosing. */
export const transportLabel = (transport: string) => ({
    [Transport.PROXY]: "PROXY",
    [Transport.NFQUEUE]: "NFQUEUE",
    [Transport.EXTERNAL]: "YOUR PROXY",
}[transport] ?? transport.toUpperCase())

/**
 * What choosing this layer means, in one sentence, wherever a service is shown.
 *
 * The trade is real and neither layer is the better one, so it belongs on the service
 * itself and not only in the form where it was picked — an operator looking at a
 * running service should be able to see what it gave up without opening anything.
 */
export const transportSummary = (transport: string, proto: string) => {
    if (transport === Transport.EXTERNAL)
        return "Firegex only steers this traffic to a proxy you run; nothing here inspects it, so no filter can be attached."
    if (transport === Transport.NFQUEUE)
        return "Packets are inspected and a verdict handed back; nothing is terminated. Fully transparent, and the kernel keeps forwarding if a filter dies — at the cost of a userspace round trip per packet, userspace reassembly, a process per filter, and patterns that cannot rewrite."
    return proto === L4.UDP
        ? "Each address is relayed by a dedicated socket. Rewriting is exact, filters keep per-flow state, and source IP transparency is preserved. Adding new addresses works dynamically without restarting the service."
        : "The connection is terminated and reopened, so rewriting is exact, the kernel reassembles, and the chain has no length limit. It also carries bulk traffic several times faster than NFQUEUE, which pays a userspace round trip per packet; what it costs is fail-open being rebuilt in userspace rather than guaranteed by the kernel. The service still sees the real client address."
}

/** Whether this combination loses the client's address, which is worth saying out loud. */
export const losesClientAddress = (_transport: string, _proto: string) => false

/** Where a service is reachable, short enough to sit on one line. */
export const addressSummary = (addresses: Address[]) => {
    if (!addresses || addresses.length === 0) return "no address yet"
    const first = `${addresses[0].ip_int}:${addresses[0].port}`
    return addresses.length === 1 ? first : `${first} +${addresses.length - 1} more`
}

/**
 * Everything about a service that is not start/stop.
 *
 * One component, used both in the list and on the service's own page: the two used to
 * offer different buttons for the same service — an "Options" menu holding only
 * settings in one place, a row of separate buttons in the other — so which actions
 * existed depended on where you happened to be looking at it from.
 */
export function ServiceMenu({ onSettings, onDelete }: {
    onSettings: () => void, onDelete: () => void,
}) {
    return <Menu position="bottom-end">
        <Menu.Target>
            <Button variant="default" size="xs" leftSection={<MdMoreHoriz size={14} />}>Options</Button>
        </Menu.Target>
        <Menu.Dropdown>
            <Menu.Label>Network layer</Menu.Label>
            <Menu.Item leftSection={<IoSettingsSharp size={14} />} onClick={onSettings}>
                Settings
            </Menu.Item>
            <Menu.Divider />
            <Menu.Item color="red" leftSection={<FaTrash size={12} />} onClick={onDelete}>
                Delete this service
            </Menu.Item>
        </Menu.Dropdown>
    </Menu>
}

export default function ServiceRow({ service, onClick }: { service: Service, onClick?: () => void }) {
    const queryClient = useQueryClient()
    const [loading, setLoading] = useState(false)
    const [deleteModal, setDeleteModal] = useState(false)
    const [editModal, setEditModal] = useState(false)
    const isMedium = isMediumScreen()

    const running = service.status === "active"
    const statusColor = running ? "teal" : "red"

    const act = async (what: "start" | "stop") => {
        setLoading(true)
        try {
            const err = what === "start"
                ? await services.start(service.service_id)
                : await services.stop(service.service_id)
            if (err) errorNotify(`Could not ${what} ${service.name}`, err)
            else {
                okNotify(`Service ${service.name} ${what === "start" ? "started" : "stopped"}`,
                    addressSummary(service.addresses))
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }
        } catch (err) {
            errorNotify(`Could not ${what} ${service.name}`, `${err}`)
        }
        setLoading(false)
    }

    const remove = async () => {
        try {
            const err = await services.remove(service.service_id)
            if (err) errorNotify("Could not delete the service", err)
            else {
                okNotify("Service deleted", `${service.name} is gone`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }
        } catch (err) {
            errorNotify("Could not delete the service", `${err}`)
        }
    }

    return <>
        <Card withBorder radius="md" p="md" w="100%" bg="transparent"
            className="firegex__clickable_row"
            style={{ borderColor: 'var(--fourth_color)' }}
            onClick={onClick}>
            <Group justify="space-between" align="center" wrap={isMedium ? "nowrap" : "wrap"}>
                <Group wrap="nowrap" align="flex-start">
                    <Box style={{
                        width: 42, height: 42, borderRadius: 8,
                        backgroundColor: running ? 'rgba(32, 201, 151, 0.1)' : 'rgba(250, 82, 82, 0.1)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        color: running ? 'var(--mantine-color-teal-filled)' : 'var(--mantine-color-red-filled)',
                    }}>
                        <TbHexagon size={24} />
                    </Box>
                    <Box>
                        <Group gap="xs" align="center">
                            <Text fw={600} size="md">{service.name}</Text>
                            <Badge color={statusColor} variant="light" size="xs" radius="sm">
                                {service.status.toUpperCase()}
                            </Badge>
                            <Tooltip position="bottom" multiline w={340}
                                label={transportSummary(service.transport, service.proto)}>
                                <Badge color="indigo" variant="light" size="xs" radius="sm">
                                    {transportLabel(service.transport)}
                                </Badge>
                            </Tooltip>
                            {losesClientAddress(service.transport, service.proto) ?
                                <Tooltip position="bottom" multiline w={340}
                                    label="Relayed per address, so your service sees firegex's address instead of the client's. The NFQUEUE layer filters UDP with the real packets untouched.">
                                    <Badge color="orange" variant="light" size="xs" radius="sm">
                                        NO CLIENT IP
                                    </Badge>
                                </Tooltip> : null}
                            {decrypts(service) ? <Tooltip label="The engine decrypts this service, so the filters see the plaintext" position="bottom">
                                <Badge color="grape" variant="light" size="xs" radius="sm"
                                    leftSection={<TbShieldLock size={10} />}>TLS</Badge>
                            </Tooltip> : null}
                        </Group>
                        <Group gap="xs" mt={4}>
                            <Tooltip position="bottom" disabled={(service.addresses?.length ?? 0) < 2}
                                label={(service.addresses ?? []).map(a => `${a.ip_int}:${a.port}`).join(", ")}>
                                <Text size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
                                    {addressSummary(service.addresses)} ON {service.proto.toUpperCase()}
                                </Text>
                            </Tooltip>
                            <Text size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
                                {service.transport === Transport.EXTERNAL
                                    ? "• handed to your own proxy"
                                    : `• ${service.n_filters} filter${service.n_filters === 1 ? "" : "s"} • ${service.n_blocked} blocked`}
                            </Text>
                        </Group>
                    </Box>
                </Group>

                <Group gap="xs" wrap="nowrap">
                    <Group gap="xs" onClick={e => e.stopPropagation()}>
                        {running
                            ? <Button variant="default" size="xs" leftSection={<FaStop size={10} />}
                                onClick={() => act("stop")} loading={loading}>Stop</Button>
                            : <Button variant="default" size="xs" leftSection={<FaPlay size={10} />}
                                onClick={() => act("start")} loading={loading}>Start</Button>}
                        <ServiceMenu onSettings={() => setEditModal(true)}
                            onDelete={() => setDeleteModal(true)} />
                    </Group>
                    <Tooltip label="Filters" position="left">
                        <Box style={{ display: 'flex', alignItems: 'center', color: 'var(--text-secondary)' }}>
                            <MdChevronRight size={22} />
                        </Box>
                    </Tooltip>
                </Group>
            </Group>
        </Card>
        <YesNoModal
            title="Delete this service?"
            description={`This stops protecting ${addressSummary(service.addresses)} and deletes every filter attached to it. The service itself keeps running, unprotected.`}
            onClose={() => setDeleteModal(false)}
            action={remove}
            opened={deleteModal}
        />
        <AddEditService opened={editModal} onClose={() => setEditModal(false)} edit={service} />
    </>
}
