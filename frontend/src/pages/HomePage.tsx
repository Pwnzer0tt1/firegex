import { ActionIcon, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import { useNavigate } from 'react-router-dom';
import ServiceRow from '../components/ServiceRow';
import { Service } from '../js/models';
import { errorNotify, eventUpdateName, fireUpdateRequest, servicelist } from '../js/utils';
import AddNewService from '../components/AddNewService';
import { useWindowEvent } from '@mantine/hooks';


function HomePage() {

    const [services, setServices] = useState<Service[]>([]);
    const [loader, setLoader] = useState(true);
    const navigator = useNavigate()
    const [open, setOpen] = useState(false);
    const [tooltipAddServOpened, setTooltipAddServOpened] = useState(false);
    
    const updateInfo = async () => {
        await servicelist().then(res => {
            setServices(res)    
        }).catch(err => {
            errorNotify("Home Page Auto-Update failed!", err.toString())
        })
        setLoader(false)
    }

    useWindowEvent(eventUpdateName, updateInfo)
    useEffect(fireUpdateRequest,[])

    const closeModal = () => {setOpen(false);}

    return <div id="service-list" className="center-flex-row">
        <LoadingOverlay visible={loader} />
        {services.length > 0?services.map( srv => <ServiceRow service={srv} key={srv.service_id} onClick={()=>{
            navigator("/"+srv.service_id)
        }} />):<><Space h="xl"/> <Title className='center-flex' align='center' order={3}>No services found! Add one clicking the "+" buttons</Title>
            <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> 
            <div className='center-flex'>
                <Tooltip label="Add a new service" transition="pop" transitionDuration={200} /*openDelay={500}*/ zIndex={0} transitionTimingFunction="ease" color="blue" opened={tooltipAddServOpened} tooltipId="tooltip-addServ-id">
                    <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                        onFocus={() => setTooltipAddServOpened(false)} onBlur={() => setTooltipAddServOpened(false)}
                        onMouseEnter={() => setTooltipAddServOpened(true)} onMouseLeave={() => setTooltipAddServOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
                </Tooltip>
            </div>
        </>}
        <AddNewService opened={open} onClose={closeModal} />
    </div>
}

export default HomePage;
