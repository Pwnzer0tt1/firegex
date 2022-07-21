import { ActionIcon, Badge, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import { useNavigate, useParams } from 'react-router-dom';
import ServiceRow from '../../components/NFRegex/ServiceRow';
import { GeneralStats, nfregex, Service } from '../../components/NFRegex/utils';
import { errorNotify, eventUpdateName, fireUpdateRequest } from '../../js/utils';
import AddNewService from '../../components/NFRegex/AddNewService';
import { useWindowEvent } from '@mantine/hooks';
import AddNewRegex from '../../components/NFRegex/AddNewRegex';


function NFRegex({ children }: { children: any }) {

    const [services, setServices] = useState<Service[]>([]);
    const [loader, setLoader] = useState(true);
    const navigator = useNavigate()
    const [open, setOpen] = useState(false);
    const {srv} = useParams()
    const [tooltipAddServOpened, setTooltipAddServOpened] = useState(false);
    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
    
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
    <Space h="sm" />
    <div className='center-flex'>
        <Title order={4}>Netfilter Regex</Title>
        <div className='flex-spacer' />
        <Badge size="sm" color="green" variant="filled">Services: {generalStats.services}</Badge>
        <Space w="xs" />
        <Badge size="sm" color="yellow" variant="filled">Filtered Connections: {generalStats.closed}</Badge>
        <Space w="xs" />
        <Badge size="sm" color="violet" variant="filled">Regexes: {generalStats.regexes}</Badge>
        <Space w="xs" />
        { srv?
          <Tooltip label="Add a new regex" position='bottom' transition="pop" transitionDuration={200} transitionTimingFunction="ease" color="blue" opened={tooltipAddOpened}>
            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
             onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
             onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
          </Tooltip>
        : <Tooltip label="Add a new service" position='bottom' transition="pop" transitionDuration={200} transitionTimingFunction="ease" color="blue" opened={tooltipAddOpened}>
            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
             onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
             onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
          </Tooltip>
      }
    </div>
    <div id="service-list" className="center-flex-row">
        {srv?null:<>
            <LoadingOverlay visible={loader} />
            {services.length > 0?services.map( srv => <ServiceRow service={srv} key={srv.service_id} onClick={()=>{
                navigator("/nfregex/"+srv.service_id)
            }} />):<><Space h="xl"/> <Title className='center-flex' align='center' order={3}>No services found! Add one clicking the "+" buttons</Title>
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
        </>}
    </div>
    {srv?children:null}
    {srv?
        <AddNewRegex opened={open} onClose={closeModal} service={srv} />:
        <AddNewService opened={open} onClose={closeModal} />
    }
    </>
}

export default NFRegex;
