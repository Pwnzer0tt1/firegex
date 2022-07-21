import { ActionIcon, Badge, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import { useNavigate, useParams } from 'react-router-dom';
import ServiceRow from '../../components/NFRegex/ServiceRow';
import { GeneralStats, Service } from '../../js/models';
import { errorNotify, eventUpdateName, fireUpdateRequest, nfregex } from '../../js/utils';
import AddNewService from '../../components/NFRegex/AddNewService';
import { useWindowEvent } from '@mantine/hooks';


function NFRegex({ children }: { children: any }) {

    const [services, setServices] = useState<Service[]>([]);
    const [loader, setLoader] = useState(true);
    const navigator = useNavigate()
    const [open, setOpen] = useState(false);
    const {srv} = useParams()
    const [tooltipAddServOpened, setTooltipAddServOpened] = useState(false);
    
    const [generalStats, setGeneralStats] = useState<GeneralStats>({closed:0, regexes:0, services:0});

    const updateInfo = async () => {
        
        await Promise.all([
            nfregex.stats().then(res => {
                setGeneralStats(res)
            }).catch(
                err => errorNotify("General Info Auto-Update failed!", err.toString())
            ),
            nfregex.services().then(res => {
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
    
    <div id="service-list" className="center-flex-row">
        <Space h="sm" />
        <div className='center-flex'>
            <Badge color="green" size="lg" variant="filled">Services: {generalStats.services}</Badge>
              <Space w="xs" />
            <Badge size="lg" color="yellow" variant="filled">Filtered Connections: {generalStats.closed}</Badge>
              <Space w="xs" />
            <Badge size="lg" color="violet" variant="filled">Regexes: {generalStats.regexes}</Badge>
        </div>
        {srv?null:<>
            <LoadingOverlay visible={loader} />
            {services.length > 0?services.map( srv => <ServiceRow service={srv} key={srv.service_id} onClick={()=>{
                navigator("/nfregex/"+srv.service_id)
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
        </>}
    </div>
    {srv?children:null}
    </>
}

export default NFRegex;
