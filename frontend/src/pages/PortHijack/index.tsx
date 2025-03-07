import { ActionIcon, Badge, Box, Divider, LoadingOverlay, Space, ThemeIcon, Title, Tooltip } from '@mantine/core';
import { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import ServiceRow from '../../components/PortHijack/ServiceRow';
import { porthijackServiceQuery } from '../../components/PortHijack/utils';
import { errorNotify, getErrorMessage, isMediumScreen } from '../../js/utils';
import AddNewService from '../../components/PortHijack/AddNewService';
import { useQueryClient } from '@tanstack/react-query';
import { TbReload } from 'react-icons/tb';
import { FaServer } from 'react-icons/fa';
import { GrDirections } from 'react-icons/gr';
import { DocsButton } from '../../components/DocsButton';


function PortHijack() {

    const [open, setOpen] = useState(false);
    const queryClient = useQueryClient()
    const isMedium = isMediumScreen()

    const services = porthijackServiceQuery()

    useEffect(()=>{
        if(services.isError)
            errorNotify("Porthijack Update failed!", getErrorMessage(services.error))
    },[services.isError])

    const closeModal = () => {setOpen(false);}

    return <>
        <Space h="sm" />
        <Box className={isMedium?'center-flex':'center-flex-row'}>
            <Title order={5} className="center-flex"><ThemeIcon radius="md" size="md" variant='filled' color='blue' ><GrDirections size={20} /></ThemeIcon><Space w="xs" />Hijack port to proxy</Title>
            {isMedium?<Box className='flex-spacer' />:<Space h="sm" />}
            <Box className='center-flex'>
                <Badge size="md" radius="sm" color="yellow" variant="filled"><FaServer style={{ marginBottom: -1, marginRight: 4}} />Services: {services.isLoading?0:services.data?.length}</Badge>
                <Space w="xs" />
                <Tooltip label="Add a new service" position='bottom' color="blue">
                    <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"><BsPlusLg size={18} /></ActionIcon>
                </Tooltip>
                <Space w="xs" />
                <Tooltip label="Refresh" position='bottom' color="indigo">
                    <ActionIcon color="indigo" onClick={()=>queryClient.invalidateQueries(["porthijack"])} size="lg" radius="md" variant="filled"
                    loading={services.isFetching}><TbReload size={18} /></ActionIcon>
                </Tooltip>
                <Space w="xs" />
                <DocsButton doc="porthijack" />
            </Box>
        </Box>
        <Space h="md" />
        <Box className="center-flex-row" style={{gap: 20}}>
            <LoadingOverlay visible={services.isLoading} />
            {(services.data && services.data.length > 0) ?services.data.map( srv => <ServiceRow service={srv} key={srv.service_id} />):<>
                <Box className='center-flex-row'>
                    <Space h="xl" />
                    <Title className='center-flex' style={{textAlign:"center"}} order={3}>Hjiack Port to Proxy is a feature that allows you to run your custom proxy without touch the service config</Title>
                    <Space h="xs" />
                    <Title className='center-flex' style={{textAlign:"center"}} order={5}>It hijack the traffic to a secondary port, where you can run your proxy, that will still be able to contact the original service using loopback</Title>
                    <Space h="xs" />
                    <Title className='center-flex' style={{textAlign:"center"}} order={5}>Start using port hijacking creating a new service and routing the traffic to your proxy not changing the original service configs</Title>
                    <Space h="lg" />
                    <Box className='center-flex' style={{gap: 20}}>
                        <Tooltip label="Add a new service" color="blue">
                            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled">
                                <BsPlusLg size="20px" />
                            </ActionIcon>
                        </Tooltip>
                        <DocsButton doc="porthijack" size="xl" />
                    </Box>
                </Box>
            </>}
            <AddNewService opened={open} onClose={closeModal} />
        </Box>
    </>
}

export default PortHijack;
