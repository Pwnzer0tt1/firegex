import { ActionIcon, Badge, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import ServiceRow from '../../components/PortHijack/ServiceRow';
import { porthijackServiceQuery } from '../../components/PortHijack/utils';
import { errorNotify, getErrorMessage } from '../../js/utils';
import AddNewService from '../../components/PortHijack/AddNewService';
import { useQueryClient } from '@tanstack/react-query';
import { TbReload } from 'react-icons/tb';


function PortHijack() {

    const [open, setOpen] = useState(false);
    const [tooltipAddServOpened, setTooltipAddServOpened] = useState(false);
    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
    const queryClient = useQueryClient()
    const [tooltipRefreshOpened, setTooltipRefreshOpened] = useState(false);


    const services = porthijackServiceQuery()

    useEffect(()=>{
        if(services.isError)
            errorNotify("Porthijack Update failed!", getErrorMessage(services.error))
    },[services.isError])

    const closeModal = () => {setOpen(false);}

    return <>
        <Space h="sm" />
        <div className='center-flex'>
            <Title order={4}>Hijack port to proxy</Title>
            <div className='flex-spacer' />
            <Badge size="sm" color="yellow" variant="filled">Services: {services.isLoading?0:services.data?.length}</Badge>
            <Space w="xs" />
            <Tooltip label="Add a new service" position='bottom' color="blue" opened={tooltipAddOpened}>
                <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
                    onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
                    onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
            </Tooltip>
            <Space w="xs" />
            <Tooltip label="Refresh" position='bottom' color="indigo" opened={tooltipRefreshOpened}>
                <ActionIcon color="indigo" onClick={()=>queryClient.invalidateQueries(["porthijack"])} size="lg" radius="md" variant="filled"
                loading={services.isFetching}
                onFocus={() => setTooltipRefreshOpened(false)} onBlur={() => setTooltipRefreshOpened(false)}
                onMouseEnter={() => setTooltipRefreshOpened(true)} onMouseLeave={() => setTooltipRefreshOpened(false)}><TbReload size={18} /></ActionIcon>
            </Tooltip>
        </div>
        <div id="service-list" className="center-flex-row">
            <LoadingOverlay visible={services.isLoading} />
            {(services.data && services.data.length > 0) ?services.data.map( srv => <ServiceRow service={srv} key={srv.service_id} />):<>
            <Space h="xl"/> <Title className='center-flex' align='center' order={3}>No services found! Add one clicking the "+" buttons</Title>
                <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> 
                <div className='center-flex'>
                    <Tooltip label="Add a new service" color="blue" opened={tooltipAddServOpened}>
                        <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                            onFocus={() => setTooltipAddServOpened(false)} onBlur={() => setTooltipAddServOpened(false)}
                            onMouseEnter={() => setTooltipAddServOpened(true)} onMouseLeave={() => setTooltipAddServOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
                    </Tooltip>
                </div>
            </>}
            <AddNewService opened={open} onClose={closeModal} />
        </div>
    </>
}

export default PortHijack;
