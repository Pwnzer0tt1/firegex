import { ActionIcon, Badge, Box, LoadingOverlay, Space, ThemeIcon, Title, Tooltip } from '@mantine/core';
import { useEffect, useState } from 'react';
import { BsPlusLg, BsRegex } from "react-icons/bs";
import { useNavigate, useParams } from 'react-router-dom';
import ServiceRow from '../../components/NFRegex/ServiceRow';
import { nfregexServiceQuery } from '../../components/NFRegex/utils';
import { errorNotify, getErrorMessage, isMediumScreen } from '../../js/utils';
import AddEditService from '../../components/NFRegex/AddEditService';
import AddNewRegex from '../../components/AddNewRegex';
import { useQueryClient } from '@tanstack/react-query';
import { TbReload } from 'react-icons/tb';
import { FaFilter } from 'react-icons/fa';
import { FaServer } from "react-icons/fa6";
import { VscRegex } from "react-icons/vsc";

function NFRegex({ children }: { children: any }) {

    const navigator = useNavigate()
    const [open, setOpen] = useState(false);
    const {srv} = useParams()
    const queryClient = useQueryClient()
    const [tooltipRefreshOpened, setTooltipRefreshOpened] = useState(false);
    const [tooltipAddServOpened, setTooltipAddServOpened] = useState(false);
    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
    const isMedium = isMediumScreen()
    const services = nfregexServiceQuery()

    useEffect(()=> {
        if(services.isError)
            errorNotify("NFRegex Update failed!", getErrorMessage(services.error))
    },[services.isError])

    const closeModal = () => {setOpen(false);}

    return <>
    <Space h="sm" />
    <Box className={isMedium?'center-flex':'center-flex-row'}>
        <Title order={5} className="center-flex"><ThemeIcon radius="md" size="md" variant='filled' color='grape' ><BsRegex size={20} /></ThemeIcon><Space w="xs" />Netfilter Regex</Title>
        {isMedium?<Box className='flex-spacer' />:<Space h="sm" />}
        <Box className='center-flex' >
            {isMedium?"General stats:":null}
            <Space w="xs" />
            <Badge size="md" radius="sm" color="green" variant="filled"><FaServer style={{ marginBottom: -1, marginRight: 4}} />Services: {services.isLoading?0:services.data?.length}</Badge>
            <Space w="xs" />
            <Badge color="yellow" radius="sm" size="md" variant="filled"><FaFilter style={{ marginBottom: -2, marginRight: 4}} />{services.isLoading?0:services.data?.reduce((acc, s)=> acc+=s.n_packets, 0)}</Badge>
            <Space w="xs" />
            <Badge size="md" radius="sm" color="violet" variant="filled"><VscRegex style={{ marginBottom: -2, marginRight: 4}} />{services.isLoading?0:services.data?.reduce((acc, s)=> acc+=s.n_regex, 0)}</Badge>
            <Space w="xs" />
        </Box>
        {isMedium?null:<Space h="md" />}
        <Box className='center-flex' >
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
        <Space w="xs" />
            <Tooltip label="Refresh" position='bottom' color="indigo" opened={tooltipRefreshOpened}>
                <ActionIcon color="indigo" onClick={()=>queryClient.invalidateQueries(["nfregex"])} size="lg" radius="md" variant="filled"
                loading={services.isFetching}
                onFocus={() => setTooltipRefreshOpened(false)} onBlur={() => setTooltipRefreshOpened(false)}
                onMouseEnter={() => setTooltipRefreshOpened(true)} onMouseLeave={() => setTooltipRefreshOpened(false)}><TbReload size={18} /></ActionIcon>
            </Tooltip>
        </Box>
    </Box>
    <Space h="md" />
    <Box className="center-flex-row" style={{gap: 20}}>
        {srv?null:<>
            <LoadingOverlay visible={services.isLoading} />
            {(services.data && services.data?.length > 0)?services.data.map( srv => <ServiceRow service={srv} key={srv.service_id} onClick={()=>{
                navigator("/nfregex/"+srv.service_id)
            }} />):<><Space h="xl"/> <Title className='center-flex' style={{textAlign:"center"}} order={3}>No services found! Add one clicking the "+" buttons</Title>
                <Box className='center-flex'>
                    <Tooltip label="Add a new service" color="blue" opened={tooltipAddServOpened}>
                        <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                            onFocus={() => setTooltipAddServOpened(false)} onBlur={() => setTooltipAddServOpened(false)}
                            onMouseEnter={() => setTooltipAddServOpened(true)} onMouseLeave={() => setTooltipAddServOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
                    </Tooltip>
                </Box>
            </>}
        </>}
    </Box>
    {srv?children:null}
    {srv?
        <AddNewRegex opened={open} onClose={closeModal} service={srv} />:
        <AddEditService opened={open} onClose={closeModal} />
    }
    </>
}

export default NFRegex;
