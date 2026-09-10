import { ActionIcon, Box, LoadingOverlay, Space, ThemeIcon, Title, Tooltip } from '@mantine/core';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { BsPlusLg } from 'react-icons/bs';
import { TbHexagon, TbReload } from 'react-icons/tb';
import { useNavigate, useParams } from 'react-router';
import { DocsButton } from '../../components/DocsButton';
import AddEditService from '../../components/Services/AddEditService';
import ServiceRow from '../../components/Services/ServiceRow';
import { serviceQueryKey, servicesQuery } from '../../components/Services/utils';
import { errorNotify, getErrorMessage, isMediumScreen } from '../../js/utils';

export default function Services({ children }: { children: any }) {
    const navigate = useNavigate()
    const queryClient = useQueryClient()
    const { srv } = useParams()
    const [addOpen, setAddOpen] = useState(false)
    const isMedium = isMediumScreen()
    const list = servicesQuery()

    useEffect(() => {
        if (list.isError) errorNotify("Could not load the services", getErrorMessage(list.error))
    }, [list.isError])

    // No header totals: a count of services and filters across the whole instance is a
    // number nobody acts on, and each row already carries its own. What is worth knowing
    // about a service is on the service.
    const all = Array.isArray(list.data) ? list.data : []

    return <>
        <Space h="sm" />
        <Box className={isMedium ? 'center-flex' : 'center-flex-row'}>
            <Title order={5} className="center-flex">
                <ThemeIcon radius="md" size="md" variant="filled" color="grape"><TbHexagon size={20} /></ThemeIcon>
                <Space w="xs" />Services
            </Title>
            {isMedium ? <Box className="flex-spacer" /> : <Space h="sm" />}
            <Box className="center-flex">
                {srv ? null : <>
                    <Tooltip label="Add a new service" position="bottom" color="blue">
                        <ActionIcon color="blue" onClick={() => setAddOpen(true)} size="lg" radius="md" variant="filled">
                            <BsPlusLg size={18} />
                        </ActionIcon>
                    </Tooltip>
                    <Space w="xs" />
                </>}
                <Tooltip label="Refresh" position="bottom" color="indigo">
                    <ActionIcon color="indigo" size="lg" radius="md" variant="filled" loading={list.isFetching}
                        onClick={() => queryClient.invalidateQueries({ queryKey: serviceQueryKey })}>
                        <TbReload size={18} />
                    </ActionIcon>
                </Tooltip>
                <Space w="xs" />
                <DocsButton doc="services" />
            </Box>
        </Box>
        <Space h="xl" />

        <Box className="center-flex-row" style={{ gap: 12, width: "100%" }}>
            {srv ? null : <>
                <LoadingOverlay visible={list.isLoading} />
                {all.length > 0
                    ? all.map(service => <ServiceRow key={service.service_id} service={service}
                        onClick={() => navigate("/services/" + service.service_id)} />)
                    : <Box className="center-flex-row">
                        <Space h="xl" />
                        <Title className="center-flex" style={{ textAlign: "center" }} order={3}>
                            A service is a network layer with filters on top of it
                        </Title>
                        <Space h="xs" />
                        <Title className="center-flex" style={{ textAlign: "center" }} order={5}>
                            Choose how to intercept the traffic once, then attach as many
                            regex or Python filters as you like, in any order.
                        </Title>
                        <Space h="lg" />
                        <Box className="center-flex" style={{ gap: 20 }}>
                            <Tooltip label="Add a new service" color="blue">
                                <ActionIcon color="blue" onClick={() => setAddOpen(true)} size="xl" radius="md" variant="filled">
                                    <BsPlusLg size="20px" />
                                </ActionIcon>
                            </Tooltip>
                            <DocsButton doc="services" size="xl" />
                        </Box>
                    </Box>}
            </>}
        </Box>
        {srv ? children : null}
        <AddEditService opened={addOpen} onClose={() => setAddOpen(false)} />
    </>
}
