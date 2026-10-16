import { Badge, Box, Button, Card, Group, Menu, Text, Tooltip } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { FaPlay, FaStop, FaTrash } from 'react-icons/fa';
import { IoSettingsSharp } from 'react-icons/io5';
import { MdChevronRight, MdMoreHoriz } from 'react-icons/md';
import { TbAlertTriangle, TbHexagon, TbShieldLock } from 'react-icons/tb';
import { bareAddress, errorNotify, isMediumScreen, okNotify } from '../../js/utils';
import YesNoModal from '../YesNoModal';
import AddEditService from './AddEditService';
import { Address, decrypts, L4, protoLabel, Service, serviceQueryKey, services, Transport, Upstream } from './utils';

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
        return "Packets are inspected and a verdict handed back; nothing is terminated. Fully transparent, and the kernel keeps forwarding if a filter dies — at the cost of a userspace round trip per packet, userspace reassembly, and a process per filter."
    if (proto === L4.HTTP)
        return "Every version of HTTP through one chain: HTTP/1.1 and HTTP/2 on the TCP addresses — in the clear or under TLS, whichever each client opens with — and HTTP/3 on the UDP ones. All three are shown to the filters as the same HTTP/1.1, so one pattern and one Python filter cover them; without that, HTTP/2 and HTTP/3 put the request line and the headers in a compression format no filter could read. The service still sees the real client address."
    if (proto === L4.QUIC)
        return "QUIC is terminated here: the engine decrypts it, and each stream inside is filtered on its own with its own state. It has to be — past the first packet QUIC encrypts its frames and its stream boundaries as well as the payload, so no other layer can see anything. One endpoint per address, and the service still sees the real client address."
    return proto === L4.UDP
        ? "Each address is relayed by a dedicated socket. Filters keep per-flow state, source IP transparency is preserved, and a new address is relayed without restarting the service."
        : "The connection is terminated and reopened, so the kernel reassembles and the chain has no length limit. It also carries bulk traffic several times faster than NFQUEUE, which pays a userspace round trip per packet; what it costs is fail-open being rebuilt in userspace rather than guaranteed by the kernel. The service still sees the real client address."
}

/** How long a warning stays on the row after it happened, unless the log is cleared first. */
const PROBLEM_SHOWN_MS = 60 * 60 * 1000

/**
 * The newest warning or error in the service's log, on the row, for an hour.
 *
 * The log is on the service's own page, and a problem there waits for somebody to open
 * it — the notification says it once, this keeps saying it for whoever looks at the list
 * afterwards. Clearing the log is how it is dismissed.
 */
export function ProblemBadge({ service }: { service: Service }) {
    const problem = service.problem
    if (!problem || Date.now() - problem.at > PROBLEM_SHOWN_MS) return null
    const error = problem.level === "error"
    return <Tooltip position="bottom" multiline w={380}
        label={`${new Date(problem.at).toLocaleTimeString(undefined, { hour12: false })} — ${problem.text}. Clear the service's log to dismiss this.`}>
        <Badge color={error ? "red" : "orange"} variant="light" size="xs" radius="sm"
            leftSection={<TbAlertTriangle size={10} />}>
            {error ? "ERROR" : "WARNING"}
        </Badge>
    </Tooltip>
}

/** Where a service is reachable, short enough to sit on one line. */
export const addressSummary = (addresses: Address[]) => {
    if (!addresses || addresses.length === 0) return "no address yet"
    const first = `${bareAddress(addresses[0].ip_int)}:${addresses[0].port}`
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
                            <ProblemBadge service={service} />
                            <Tooltip position="bottom" multiline w={340}
                                label={transportSummary(service.transport, service.proto)}>
                                <Badge color="indigo" variant="light" size="xs" radius="sm">
                                    {transportLabel(service.transport)}
                                </Badge>
                            </Tooltip>
                            {/* The plaintext leg is worth saying here and not only in
                            the form: a service whose backend speaks in the clear is one
                            firegex is *adding* encryption to, which changes what stopping
                            firegex does to it. */}
                            {decrypts(service) ? <Tooltip position="bottom" multiline w={320}
                                label={(service.proto === L4.HTTP
                                    ? "Every version of HTTP, decrypted where it is encrypted and rendered to the filters as one"
                                    : "The engine decrypts this service, so the filters see the plaintext")
                                    + ((service.addresses ?? []).some(a => a.upstream === Upstream.TCP)
                                        ? ". Behind at least one of its addresses the service answers in the clear, so firegex is what encrypts it."
                                        : "")}>
                                <Badge color="grape" variant="light" size="xs" radius="sm"
                                    leftSection={<TbShieldLock size={10} />}>
                                    {protoLabel(service.proto)}
                                </Badge>
                            </Tooltip> : null}
                        </Group>
                        <Group gap="xs" mt={4}>
                            <Tooltip position="bottom" disabled={(service.addresses?.length ?? 0) < 2}
                                label={(service.addresses ?? []).map(a => `${bareAddress(a.ip_int)}:${a.port}`).join(", ")}>
                                <Text size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
                                    {addressSummary(service.addresses)} ON {protoLabel(service.proto)}
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
