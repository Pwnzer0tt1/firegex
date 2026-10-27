import { ActionIcon, Button, Group, LoadingOverlay, Text, TextInput, Title, Tooltip } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { ReactNode, useEffect, useState } from 'react';
import { BsPlusLg } from 'react-icons/bs';
import { TbReload, TbSearch } from 'react-icons/tb';
import { useNavigate, useParams } from 'react-router';
import { DocsButton } from '../../components/DocsButton';
import { firewallRulesQuery } from '../../components/Firewall/utils';
import AddEditService from '../../components/Services/AddEditService';
import ServiceTableRow from '../../components/Services/ServiceRow';
import { Service, serviceQueryKey, servicesQuery } from '../../components/Services/utils';
import { backendLink, BACKEND_LINK_HELP, Chip } from '../../components/Shell/ui';
import { useSystemStore } from '../../js/store';
import { bareAddress, errorNotify, getErrorMessage } from '../../js/utils';

/**
 * Whether a service answers to what was typed in the filter box: its name, any of its
 * ports, or any of its addresses — the three things an operator knows a service by.
 */
const matches = (service: Service, query: string) => {
    const q = query.trim().toLowerCase()
    if (!q) return true
    if (service.name.toLowerCase().includes(q)) return true
    return (service.addresses ?? []).some(a =>
        String(a.port).includes(q) || bareAddress(a.ip_int).toLowerCase().includes(q))
}

export default function Services({ children }: { children: ReactNode }) {
    const navigate = useNavigate()
    const queryClient = useQueryClient()
    const { srv } = useParams()
    const [addOpen, setAddOpen] = useState(false)
    const [query, setQuery] = useState("")
    const list = servicesQuery()
    const rules = firewallRulesQuery()
    const { socketConnected, socketEverConnected } = useSystemStore()

    useEffect(() => {
        if (list.isError) errorNotify("Could not load the services", getErrorMessage(list.error))
    }, [list.isError])

    // A service's own page is a child route of this one; it brings its own header.
    if (srv) return <>{children}</>

    const all = Array.isArray(list.data) ? list.data : []
    const shown = all.filter(s => matches(s, query))
    const running = all.filter(s => s.status === "active").length
    const backend = backendLink(socketConnected, socketEverConnected)
    const firewallOn = rules.data?.enabled ?? false
    const policy = rules.data?.policy ?? "accept"

    return <>
        <div className="fg-page-head">
            <h1 className="fg-page-title">Services</h1>
            <Chip tone={firewallOn ? (policy === "accept" ? "ok" : "danger") : "muted"} label="Firewall">
                {firewallOn ? `enabled · ${policy}` : "off"}
            </Chip>
            <Chip tone={backend.tone} label="Backend" tooltip={BACKEND_LINK_HELP}>{backend.text}</Chip>
            <Chip tone={all.length && running === all.length ? "ok" : running ? "warn" : "muted"} label="Running">
                {running} / {all.length}
            </Chip>
            <span className="flex-spacer" />
            <Group gap="xs" wrap="nowrap">
                <Tooltip label="Refresh">
                    <ActionIcon variant="default" size="lg" loading={list.isFetching} aria-label="Refresh"
                        onClick={() => queryClient.invalidateQueries({ queryKey: serviceQueryKey })}>
                        <TbReload size={16} />
                    </ActionIcon>
                </Tooltip>
                <DocsButton doc="services" />
                <Button leftSection={<BsPlusLg size={14} />} onClick={() => setAddOpen(true)}>Add service</Button>
            </Group>
        </div>

        {all.length > 0 ? <>
            <TextInput mb="md" maw={420} leftSection={<TbSearch size={15} />}
                placeholder="Filter services by name, port or address"
                value={query} onChange={e => setQuery(e.currentTarget.value)} />
            <div className="fg-table-wrap">
                <table className="fg-table">
                    <thead>
                        <tr>
                            <th>Service</th>
                            <th>State</th>
                            <th className="fg-hide-sm">Layer</th>
                            <th className="fg-hide-sm">Filters</th>
                            <th className="num fg-hide-sm">Blocked 15m</th>
                            <th className="num fg-hide-md">Blocked total</th>
                            <th className="fg-hide-lg">Last 15 min</th>
                            <th />
                        </tr>
                    </thead>
                    <tbody>
                        {shown.map(service => <ServiceTableRow key={service.service_id} service={service}
                            onClick={() => navigate(`/services/${service.service_id}`)} />)}
                    </tbody>
                </table>
                {shown.length === 0
                    ? <Text c="dimmed" ta="center" py="lg" size="sm">Nothing matches “{query}”.</Text>
                    : null}
            </div>
        </> : list.isLoading
            ? <LoadingOverlay visible />
            : <div className="fg-table-wrap" style={{ padding: "56px 24px", textAlign: "center" }}>
                <Title order={3}>A service is a network layer with filters on top of it</Title>
                <Text c="dimmed" mt="xs" maw={560} mx="auto">
                    Choose how to intercept the traffic once, then attach as many regex or
                    Python filters as you like, in any order.
                </Text>
                <Group justify="center" mt="lg">
                    <Button leftSection={<BsPlusLg size={14} />} onClick={() => setAddOpen(true)}>Add service</Button>
                    <DocsButton doc="services" />
                </Group>
            </div>}
        <AddEditService opened={addOpen} onClose={() => setAddOpen(false)} />
    </>
}
