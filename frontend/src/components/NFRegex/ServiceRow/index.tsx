import { ActionIcon, Badge, Box, Divider, Grid, Menu, Space, Title, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { FaPlay, FaStop } from 'react-icons/fa';
import { nfregex, Service, serviceQueryKey } from '../utils';
import { MdOutlineArrowForwardIos } from "react-icons/md"
import YesNoModal from '../../YesNoModal';
import { errorNotify, isMediumScreen, okNotify, regex_ipv4 } from '../../../js/utils';
import { BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi'
import RenameForm from './RenameForm';
import { MenuDropDownWithButton } from '../../MainLayout';
import { useQueryClient } from '@tanstack/react-query';

function ServiceRow({ service, onClick }:{ service:Service, onClick?:()=>void }) {

    let status_color = "gray";
    switch(service.status){
        case "stop": status_color = "red"; break;
        case "active": status_color = "teal"; break;
    }

    const queryClient = useQueryClient()
    const [buttonLoading, setButtonLoading] = useState(false)
    const [tooltipStopOpened, setTooltipStopOpened] = useState(false);
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const isMedium = isMediumScreen()

    const stopService = async () => {
        setButtonLoading(true)
        
        await nfregex.servicestop(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} stopped successfully!`,`The service on ${service.port} has been stopped!`)
                queryClient.invalidateQueries(serviceQueryKey)
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${service.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${service.port}`,`Error: ${err}`)
        })
        setButtonLoading(false);
    }

    const startService = async () => {
        setButtonLoading(true)
        await nfregex.servicestart(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} started successfully!`,`The service on ${service.port} has been started!`)
                queryClient.invalidateQueries(serviceQueryKey)
            }else{
                errorNotify(`An error as occurred during the starting of the service ${service.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${service.port}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const deleteService = () => {
        nfregex.servicedelete(service.service_id).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${service.name} has been deleted!`)
                queryClient.invalidateQueries(serviceQueryKey)
            }else
                errorNotify("An error occurred while deleting a service",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while deleting a service",`Error: ${err}`)
        })
        
    }

    return <>
        <Box className='firegex__nfregex__rowbox'>
            <Grid className="firegex__nfregex__row" justify="flex-end" style={{width:"100%"}}>
                <Grid.Col span={{ md:4, xs: 12 }}>

                    <Box className={"center-flex-row"}>
                        <Title className="firegex__nfregex__name">
                            {service.name}
                        </Title>
                        <Box className="center-flex" style={{ gap: 6 }}>
                            <Badge color={status_color} radius="md" size="lg" variant="filled">Status: <u>{service.status}</u></Badge>
                            <Badge size="lg" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient" radius="md">
                                :{service.port}
                            </Badge>
                        </Box>
                        {isMedium?null:<Space w="xl" />}
                    </Box>
                </Grid.Col>
                
                <Grid.Col className={isMedium?"center-flex":"center-flex-row"} span={{ md:8, xs: 12 }}>
                    <Box visibleFrom='md' className='flex-spacer' />
                    <Space hiddenFrom='md' h="md" />
                    <Space hiddenFrom='md' w="xl" />
                    <Space hiddenFrom='md' w="md" />
                    <Box className="center-flex-row">
                        <Badge color="yellow" radius="sm" size="md" variant="filled">Connections Blocked: {service.n_packets}</Badge>
                        <Space h="xs" />
                        <Badge color="violet" radius="sm" size="md" variant="filled">Regex: {service.n_regex}</Badge>
                        <Space h="xs" />
                        <Badge color={service.ip_int.match(regex_ipv4)?"cyan":"pink"} radius="sm" size="md" variant="filled">{service.ip_int} on {service.proto}</Badge>
                    </Box>
                    {isMedium?<Box className='flex-spacer' />:<Space h="xl" />}
                    <Box className="center-flex">
                        <MenuDropDownWithButton>
                            <Menu.Label><b>Rename service</b></Menu.Label>
                            <Menu.Item leftSection={<BiRename size={18} />} onClick={()=>setRenameModal(true)}>Change service name</Menu.Item>
                            <Divider />
                            <Menu.Label><b>Danger zone</b></Menu.Label>
                            <Menu.Item color="red" leftSection={<BsTrashFill size={18} />} onClick={()=>setDeleteModal(true)}>Delete Service</Menu.Item>
                        </MenuDropDownWithButton>
                        <Space w="md"/>                        
                        <Tooltip label="Stop service" zIndex={0} color="red" opened={tooltipStopOpened}>
                            <ActionIcon color="red" loading={buttonLoading}
                            onClick={stopService} size="xl" radius="md" variant="filled"
                            disabled={service.status === "stop"}
                            aria-describedby="tooltip-stop-id"
                            onFocus={() => setTooltipStopOpened(false)} onBlur={() => setTooltipStopOpened(false)}
                            onMouseEnter={() => setTooltipStopOpened(true)} onMouseLeave={() => setTooltipStopOpened(false)}>
                                <FaStop size="20px" />
                            </ActionIcon>
                        </Tooltip>
                        <Space w="md"/>
                        <Tooltip label="Start service" zIndex={0} color="teal">
                            <ActionIcon color="teal" size="xl" radius="md" onClick={startService} loading={buttonLoading}
                                        variant="filled" disabled={!["stop","pause"].includes(service.status)?true:false}>
                                <FaPlay size="20px" />
                            </ActionIcon>
                        </Tooltip>
                        {isMedium?<Space w="xl" />:<Space w="md" />} 
                        {onClick?<Box style={{ backgroundColor: "var(--secondary_color)", borderRadius: "38%", width:"35px", height:"35px", display:"flex", justifyContent: "center", alignItems: "center", border:"#AAA 2px solid"}}>
                            <MdOutlineArrowForwardIos onClick={onClick} style={{cursor:"pointer"}} size={25} />
                        </Box>:null}
                        {isMedium?<Space w="xl" />:null}
                    </Box>
            
                </Grid.Col>
            </Grid>
        </Box>
        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${service.port}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
        <RenameForm
            onClose={()=>setRenameModal(false)}
            opened={renameModal}
            service={service}
        />
    </>
}

export default ServiceRow;
