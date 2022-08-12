import { ActionIcon, Badge, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import ServiceRow from '../../components/PortHijack/ServiceRow';
import { GeneralStats, porthijack, Service } from '../../components/PortHijack/utils';
import { errorNotify, eventUpdateName, fireUpdateRequest } from '../../js/utils';
import AddNewService from '../../components/PortHijack/AddNewService';
import { useWindowEvent } from '@mantine/hooks';


function PortHijack() {

    const [services, setServices] = useState<Service[]>([]);
    const [loader, setLoader] = useState(true);
    const [open, setOpen] = useState(false);
    const [tooltipAddServOpened, setTooltipAddServOpened] = useState(false);
    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
    
    const [generalStats, setGeneralStats] = useState<GeneralStats>({services:0});
    const updateInfo = async () => {
        
        await Promise.all([
            porthijack.stats().then(res => {
                setGeneralStats(res)
            }).catch(
                err => errorNotify("General Info Auto-Update failed!", err.toString())
            ),
            porthijack.services().then(res => {
                setServices(res)    
            }).catch(err => {
                errorNotify("Home Page Auto-Update failed!", err.toString())
            })
        ])
        setLoader(false)
    }

    useWindowEvent(eventUpdateName, updateInfo)
    useEffect(fireUpdateRequest,[])

    const closeModal = () => {setOpen(false);}

    return <>
        <Space h="sm" />
        <div className='center-flex'>
            <Title order={4}>Hijack port to proxy</Title>
            <div className='flex-spacer' />
            <Badge size="sm" color="yellow" variant="filled">Services: {generalStats.services}</Badge>
            <Space w="xs" />
            <Tooltip label="Add a new service" position='bottom' transition="pop" transitionDuration={200} transitionTimingFunction="ease" color="blue" opened={tooltipAddOpened}>
                <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
                    onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
                    onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
            </Tooltip>
        </div>
        <div id="service-list" className="center-flex-row">
            <LoadingOverlay visible={loader} />
            {services.length > 0?services.map( srv => <ServiceRow service={srv} key={srv.service_id} />):<><Space h="xl"/> <Title className='center-flex' align='center' order={3}>No services found! Add one clicking the "+" buttons</Title>
                <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> 
                <div className='center-flex'>
                    <Tooltip label="Add a new service" transition="pop" transitionDuration={200} transitionTimingFunction="ease" color="blue" opened={tooltipAddServOpened}>
                        <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                            onFocus={() => setTooltipAddServOpened(false)} onBlur={() => setTooltipAddServOpened(false)}
                            onMouseEnter={() => setTooltipAddServOpened(true)} onMouseLeave={() => setTooltipAddServOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
                    </Tooltip>
                </div>
            </>}
            <AddNewService opened={open} onClose={closeModal} />
        </div>
        <AddNewService opened={open} onClose={closeModal} />
    </>
}

export default PortHijack;
