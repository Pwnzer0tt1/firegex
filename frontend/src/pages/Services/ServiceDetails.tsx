import { ActionIcon, Alert, Badge, Box, Button, Card, Code, Group, LoadingOverlay, Menu, Space, Stack, Text, Title, Tooltip } from '@mantine/core';
import { DragDropContext, Draggable, Droppable } from '@hello-pangea/dnd';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { BsPlusLg } from 'react-icons/bs';
import { FaArrowLeft, FaCode, FaPlay, FaStop } from 'react-icons/fa';
import { TbAlertTriangle, TbShieldLock } from 'react-icons/tb';
import { VscRegex } from 'react-icons/vsc';
import { Navigate, useNavigate, useParams } from 'react-router';
import AddEditService from '../../components/Services/AddEditService';
import AddressList from '../../components/Services/AddressList';
import FilterCard from '../../components/Services/FilterCard';
import LogPanel from '../../components/Services/LogPanel';
import { addressSummary, losesClientAddress, ServiceMenu, transportLabel, transportSummary } from '../../components/Services/ServiceRow';
import StatsPanel from '../../components/Services/StatsPanel';
import { decrypts, Filter, FilterKind, serviceFiltersQuery, serviceQueryKey, services, servicesQuery, Transport } from '../../components/Services/utils';
import YesNoModal from '../../components/YesNoModal';
import { errorNotify, okNotify } from '../../js/utils';

/** A unix second, as a human reads it. */
const stamp = (seconds: number) => new Date(seconds * 1000).toLocaleString()

export default function ServiceDetails() {
    const { srv } = useParams()
    const navigate = useNavigate()
    const queryClient = useQueryClient()
    const allServices = servicesQuery()
    const service = allServices.data?.find(s => s.service_id === srv)
    const filters = serviceFiltersQuery(srv ?? "")
    const [editOpen, setEditOpen] = useState(false)
    const [deleteOpen, setDeleteOpen] = useState(false)
    const [busy, setBusy] = useState(false)

    if (allServices.isLoading) return <LoadingOverlay visible />
    if (!srv || !service) return <Navigate to="/services" replace />

    const chain: Filter[] = filters.data ?? []
    const running = service.status === "active"
    const refresh = () => queryClient.invalidateQueries({ queryKey: serviceQueryKey })

    const run = async (what: () => Promise<string | undefined>, failure: string, success?: [string, string]) => {
        setBusy(true)
        try {
            const err = await what()
            if (err) errorNotify(failure, err)
            else {
                if (success) okNotify(success[0], success[1])
                refresh()
            }
        } catch (err) {
            errorNotify(failure, `${err}`)
        }
        setBusy(false)
    }

    const addFilter = (kind: string) => run(
        () => services.addFilter(srv, {
            kind,
            name: kind === FilterKind.REGEX ? "patterns" : "python",
        }),
        "Could not attach the filter",
    )

    return <>
        <Space h="sm" />
        <Group justify="space-between" align="flex-start" wrap="wrap">
            <Group gap="xs" align="center">
                <Tooltip label="Back to the service list" position="bottom">
                    <ActionIcon variant="subtle" onClick={() => navigate("/services")}>
                        <FaArrowLeft />
                    </ActionIcon>
                </Tooltip>
                <Box>
                    <Group gap="xs" align="center">
                        <Title order={4}>{service.name}</Title>
                        <Badge color={running ? "teal" : "red"} variant="light" size="sm" radius="sm">
                            {service.status.toUpperCase()}
                        </Badge>
                        <Tooltip position="bottom" multiline w={360}
                            label={transportSummary(service.transport, service.proto)}>
                            <Badge color="indigo" variant="light" size="sm" radius="sm">
                                {transportLabel(service.transport)}
                            </Badge>
                        </Tooltip>
                        {losesClientAddress(service.transport, service.proto) ?
                            <Tooltip position="bottom" multiline w={360}
                                label="Relayed per address, so your service sees firegex's address instead of the client's. The NFQUEUE layer filters UDP with the real packets untouched.">
                                <Badge color="orange" variant="light" size="sm" radius="sm">
                                    NO CLIENT IP
                                </Badge>
                            </Tooltip> : null}
                        {decrypts(service) ? <Badge color="grape" variant="light" size="sm" radius="sm"
                            leftSection={<TbShieldLock size={11} />}>TLS</Badge> : null}
                    </Group>
                    <Text size="xs" c="dimmed" mt={2}>
                        {addressSummary(service.addresses)} on {service.proto.toUpperCase()}
                    </Text>
                </Box>
            </Group>
            <Group gap="xs">
                {running
                    ? <Button variant="default" size="xs" leftSection={<FaStop size={10} />} loading={busy}
                        onClick={() => run(() => services.stop(srv), "Could not stop the service")}>Stop</Button>
                    : <Button variant="default" size="xs" leftSection={<FaPlay size={10} />} loading={busy}
                        onClick={() => run(() => services.start(srv), "Could not start the service")}>Start</Button>}
                {/* The same menu the list row shows, so a service offers the same
                    actions wherever it is looked at. Trying a pattern is not among them:
                    it belongs to a regex filter, and lives on the card of the one whose
                    patterns are being tried. */}
                <ServiceMenu onSettings={() => setEditOpen(true)}
                    onDelete={() => setDeleteOpen(true)} />
            </Group>
        </Group>

        {/* Above everything else on the page, because it is the answer to the question
            an operator is asking when they open it — why are clients failing — and it is
            the one thing here that has already happened rather than being a setting. */}
        {service.over_limit_hits > 0 ? <>
            <Space h="lg" />
            <Alert color={service.over_limit_forwards ? "yellow" : "red"} variant="light"
                icon={<TbAlertTriangle size={18} />}
                title={`The connection limit has turned away ${service.over_limit_hits.toLocaleString()} ${service.over_limit_hits === 1 ? "connection" : "connections"}`}>
                <Text size="sm">
                    {service.over_limit_forwards
                        ? <>They were forwarded to the service <b>with no filter in front of them</b>.</>
                        : <>They were <b>refused</b>, so clients were turned away while the limit held.</>}
                    {" "}The limit is <Code>{service.max_connections}</Code> at once.
                </Text>
                <Text size="xs" c="dimmed" mt={6}>
                    {service.over_limit_first === service.over_limit_last
                        ? `At ${stamp(service.over_limit_last!)}.`
                        : `First at ${stamp(service.over_limit_first!)}, most recently at ${stamp(service.over_limit_last!)}.`}
                    {" "}This is kept in the database, so it outlives the log and a restart.
                    Raise the limit, or find out what is holding connections open — a client
                    that connects and then says nothing costs the same as one doing work.
                </Text>
            </Alert>
        </> : null}

        <Space h="lg" />
        <Card withBorder radius="md" p="md" bg="transparent"
            style={{ borderColor: 'var(--fourth_color)' }}>
            <AddressList service={service} />
        </Card>

        <Space h="lg" />
        <Group justify="space-between" align="center">
            <Box>
                <Title order={6}>Filter chain</Title>
                <Text size="xs" c="dimmed">
                    {service.transport === Transport.PROXY
                        ? "Run top to bottom on every chunk. Drag to reorder; nothing is dropped while you do."
                        : "Run top to bottom on every packet, one process each. Drag to reorder; the service is rebuilt to apply it."}
                </Text>
            </Box>
            <Menu>
                <Menu.Target>
                    <Button size="xs" leftSection={<BsPlusLg size={12} />}>Attach a filter</Button>
                </Menu.Target>
                <Menu.Dropdown>
                    <Menu.Label>What should it do</Menu.Label>
                    <Menu.Item leftSection={<VscRegex size={14} />} onClick={() => addFilter(FilterKind.REGEX)}>
                        Regex patterns
                        <Text size="xs" c="dimmed">matched by hyperscan, in one pass</Text>
                    </Menu.Item>
                    {/* No protocol to choose. The library reads it off the code — asking
                        for an HttpRequest is what makes a filter an HTTP one — so there
                        is nothing here that could disagree with what was written. */}
                    <Menu.Item leftSection={<FaCode size={13} />}
                        onClick={() => addFilter(FilterKind.PYFILTER)}>
                        Python filter
                        <Text size="xs" c="dimmed">raw payloads, TCP streams or parsed HTTP</Text>
                    </Menu.Item>
                </Menu.Dropdown>
            </Menu>
        </Group>

        <Space h="md" />
        {chain.length === 0
            ? <Box className="center-flex-row">
                <Space h="lg" />
                <Text ta="center">Nothing is inspecting this service yet.</Text>
                <Text ta="center" size="sm" c="dimmed">
                    Attach a filter above. The network layer stays as it is.
                </Text>
            </Box>
            : <DragDropContext onDragEnd={({ destination, source }) => {
                // A drop outside the list, or back where it started, is not a reorder.
                if (!destination || destination.index === source.index) return
                const next = chain.map(f => f.filter_id)
                next.splice(destination.index, 0, ...next.splice(source.index, 1))
                run(() => services.reorder(srv, next), "Could not reorder the chain")
            }}>
                <Droppable droppableId="chain" direction="vertical">
                    {provided => <Stack gap="sm" ref={provided.innerRef} {...provided.droppableProps}>
                        {chain.map((filter, index) => (
                            // The index has to be the position in this list, counted
                            // from zero with no gaps, or the library mismeasures the drop.
                            <Draggable key={filter.filter_id} index={index} draggableId={filter.filter_id}>
                                {(dragProvided, snapshot) => <Box
                                    ref={dragProvided.innerRef}
                                    {...dragProvided.draggableProps}
                                    style={{
                                        // Not the `w` prop: Mantine's style props land after
                                        // this object and would beat the width dnd measured.
                                        width: '100%',
                                        opacity: snapshot.isDragging ? 0.9 : 1,
                                        ...dragProvided.draggableProps.style,
                                    }}
                                >
                                    <FilterCard
                                        filter={filter}
                                        serviceId={srv}
                                        position={index}
                                        transport={service.transport}
                                        proto={service.proto}
                                        dragHandle={dragProvided.dragHandleProps}
                                    />
                                </Box>}
                            </Draggable>
                        ))}
                        {provided.placeholder}
                    </Stack>}
                </Droppable>
            </DragDropContext>}

        <Space h="xl" />
        <StatsPanel serviceId={srv} />

        <Space h="xl" />
        <LogPanel serviceId={srv} />

        <AddEditService opened={editOpen} onClose={() => setEditOpen(false)} edit={service} />
        <YesNoModal
            title="Delete this service?"
            description={`This stops protecting ${addressSummary(service.addresses)} and deletes every filter attached to it.`}
            opened={deleteOpen}
            onClose={() => setDeleteOpen(false)}
            action={async () => {
                await run(() => services.remove(srv), "Could not delete the service",
                    ["Service deleted", `${service.name} is gone`])
                navigate("/services")
            }}
        />
    </>
}
