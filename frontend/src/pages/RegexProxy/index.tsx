import { ActionIcon, Badge, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import { useNavigate, useParams } from 'react-router-dom';
import ServiceRow from '../../components/RegexProxy/ServiceRow';
import { regexproxyServiceQuery } from '../../components/RegexProxy/utils';
import { errorNotify, getErrorMessage } from '../../js/utils';
import AddNewService from '../../components/RegexProxy/AddNewService';
import AddNewRegex from '../../components/AddNewRegex';


function RegexProxy({ children }: { children: any }) {

    const navigator = useNavigate()
    const [open, setOpen] = useState(false);
    const {srv} = useParams()
    const [tooltipAddServOpened, setTooltipAddServOpened] = useState(false);
    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);

    const services = regexproxyServiceQuery()

    useEffect(()=> {
        if(services.isError){
            errorNotify("RegexProxy Update failed!", getErrorMessage(services.error))
        }
    },[services.isError])

    const closeModal = () => {setOpen(false);}

    return <>
    <Space h="sm" />
    <div className='center-flex'>
        <Title order={4}>TCP Proxy Regex Filter (IPv4 Only)</Title>
        <div className='flex-spacer' />
        <Badge size="sm" color="green" variant="filled">Services: {services.isLoading?0:services.data?.length}</Badge>
        <Space w="xs" />
        <Badge size="sm" color="yellow" variant="filled">Filtered Connections: {services.isLoading?0:services.data?.reduce((acc, s)=> acc+=s.n_packets, 0)}</Badge>
        <Space w="xs" />
        <Badge size="sm" color="violet" variant="filled">Regexes: {services.isLoading?0:services.data?.reduce((acc, s)=> acc+=s.n_regex, 0)}</Badge>
        <Space w="xs" />
        { srv?
          <Tooltip label="Add a new regex" position='bottom' color="blue" opened={tooltipAddOpened}>
            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
             onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
             onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
          </Tooltip>
        : <Tooltip label="Add a new service" position='bottom' color="blue" opened={tooltipAddOpened}>
            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
             onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
             onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
          </Tooltip>
      }
    </div>
    <div id="service-list" className="center-flex-row">
        {srv?null:<>
            <LoadingOverlay visible={services.isLoading} />
            {(services.data && services.data?.length > 0)?services.data.map( srv => <ServiceRow service={srv} key={srv.id} onClick={()=>{
                navigator("/regexproxy/"+srv.id)
            }} />):<><Space h="xl"/> <Title className='center-flex' align='center' order={3}>No services found! Add one clicking the "+" buttons</Title>
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
        </>}
    </div>
    {srv?children:null}
    {srv?
        <AddNewRegex opened={open} onClose={closeModal} service={srv} />:
        <AddNewService opened={open} onClose={closeModal} />
    }
    </>
}

export default RegexProxy;
