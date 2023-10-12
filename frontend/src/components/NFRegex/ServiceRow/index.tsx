import { ActionIcon, Badge, Divider, Grid, Menu, Space, Title, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { FaPlay, FaStop } from 'react-icons/fa';
import { nfregex, Service, serviceQueryKey } from '../utils';
import { MdOutlineArrowForwardIos } from "react-icons/md"
import style from "./index.module.scss";
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
        <Grid className={style.row} justify="flex-end" style={{width:"100%"}}>
            <Grid.Col md={4} xs={12}>

                <div className={isMedium?"center-flex-row":"center-flex"}>
                    <div className="center-flex"><Title className={style.name}>{service.name}</Title> <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient">:{service.port}</Badge></div>
                    <Badge style={isMedium?{}:{marginLeft:"20px"}} color={status_color} radius="sm" size="lg" variant="filled">Status: <u>{service.status}</u></Badge>
                    {isMedium?null:<Space w="xl" />}
                </div>
                {!isMedium?<Space h="xl" />:null}
            </Grid.Col>
            
            <Grid.Col className="center-flex" md={8} xs={12}>
                {!isMedium?<div className='flex-spacer' />:<><Space w="xl" /><Space w="xl" /></>}
                
                <div className="center-flex-row">
                    <Badge color="yellow" radius="sm" size="md" variant="filled">Connections Blocked: {service.n_packets}</Badge>
                    <Space h="xs" />
                    <Badge color="violet" radius="sm" size="md" variant="filled">Regex: {service.n_regex}</Badge>
                    <Space h="xs" />
                    <Badge color={service.ip_int.match(regex_ipv4)?"cyan":"pink"} radius="sm" size="md" variant="filled">{service.ip_int} on {service.proto}</Badge>
                </div>
                {isMedium?<div className='flex-spacer' />:<><Space w="xl" /><Space w="xl" /></>}
                <div className="center-flex">
                    <MenuDropDownWithButton>
                        <Menu.Label><b>Rename service</b></Menu.Label>
                        <Menu.Item icon={<BiRename size={18} />} onClick={()=>setRenameModal(true)}>Change service name</Menu.Item>
                        <Divider />
                        <Menu.Label><b>Danger zone</b></Menu.Label>
                        <Menu.Item color="red" icon={<BsTrashFill size={18} />} onClick={()=>setDeleteModal(true)}>Delete Service</Menu.Item>
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
                </div>
                <Space w="xl" /><Space w="xl" />
                {onClick?<div>
                    <MdOutlineArrowForwardIos onClick={onClick} style={{cursor:"pointer"}} size={45} />
                    <Space w="xl" />
                </div>:null}
                {isMedium?<><Space w="xl" /><Space w="xl" /></>:null}                
            </Grid.Col>
        </Grid>
        <Divider size="md" style={{width:"100%"}}/>
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
