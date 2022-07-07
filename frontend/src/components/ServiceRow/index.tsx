import { ActionIcon, Badge, Divider, Grid, MediaQuery, Menu, Space, Title, Tooltip } from '@mantine/core';
import React, { useState } from 'react';
import { FaPlay, FaStop } from 'react-icons/fa';
import { Service } from '../../js/models';
import { MdOutlineArrowForwardIos } from "react-icons/md"
import style from "./ServiceRow.module.scss";
import YesNoModal from '../YesNoModal';
import { deleteservice, errorNotify, fireUpdateRequest, okNotify, startservice, stopservice } from '../../js/utils';
import { BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi'

//"status":"stop"/"wait"/"active"/"pause",
function ServiceRow({ service, onClick }:{ service:Service, onClick?:()=>void }) {

    let status_color = "gray";
    switch(service.status){
        case "stop": status_color = "red"; break;
        case "active": status_color = "teal"; break;
    }

    const [stopModal, setStopModal] = useState(false);
    const [buttonLoading, setButtonLoading] = useState(false)
    const [tooltipStopOpened, setTooltipStopOpened] = useState(false);
    const [deleteModal, setDeleteModal] = useState(false)

    const stopService = async () => {
        setButtonLoading(true)
        await stopservice(service.port).then(res => {
            if(!res){
                okNotify(`Service ${service.port} stopped successfully!`,`The service ${service.name} has been stopped!`)
                fireUpdateRequest();
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
        await startservice(service.port).then(res => {
            if(!res){
                okNotify(`Service ${service.port} started successfully!`,`The service ${service.name} has been started!`)
                fireUpdateRequest();
            }else{
                errorNotify(`An error as occurred during the starting of the service ${service.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${service.port}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const deleteService = () => {
        deleteservice(service.port).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${service.port} has been deleted!`)
                fireUpdateRequest();
            }else
                errorNotify("An error occurred while deleting a service",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while deleting a service",`Error: ${err}`)
        })
        
    }

    return <>
        <Grid className={style.row} justify="flex-end" style={{width:"100%"}}>
            <Grid.Col md={4} xs={12}>
                <MediaQuery smallerThan="md" styles={{ display: 'none' }}><div>
                    <div className="center-flex-row">
                        <div className="center-flex"><Title className={style.name}>{service.name}</Title> <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient">:{service.port}</Badge></div>
                    </div>
                </div></MediaQuery>
                <MediaQuery largerThan="md" styles={{ display: 'none' }}><div>
                    <div className="center-flex">
                        <div className="center-flex"><Title className={style.name}>{service.name}</Title> <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient">:{service.port}</Badge></div>
                        <Space w="xl" />
                    </div>
                </div></MediaQuery>
                
                <MediaQuery largerThan="md" styles={{ display: 'none' }}>
                    <Space h="xl" />
                </MediaQuery>
            </Grid.Col>
            
            <Grid.Col className="center-flex" md={8} xs={12}>
                <MediaQuery smallerThan="md" styles={{ display: 'none' }}>
                    <div className='flex-spacer' />
                </MediaQuery>
                <MediaQuery largerThan="md" styles={{ display: 'none' }}>
                    <><Space w="xl" /><Space w="xl" /></>
                </MediaQuery>
                
                <div className="center-flex-row">
                    <Badge style={{marginBottom:"20px"}} color={status_color} radius="sm" size="xl" variant="filled">Status: <u>{service.status}</u></Badge>
                    <Badge style={{marginBottom:"8px"}}color="violet" radius="sm" size="lg" variant="filled">Regex: {service.n_regex}</Badge>
                    <Badge color="yellow" radius="sm" size="lg" variant="filled">Connections Blocked: {service.n_packets}</Badge>
                </div>
                <MediaQuery largerThan="md" styles={{ display: 'none' }}>
                    <div className='flex-spacer' />
                </MediaQuery>
                <MediaQuery smallerThan="md" styles={{ display: 'none' }}>
                    <><Space w="xl" /><Space w="xl" /></>
                </MediaQuery>
                <div className="center-flex">
                    <Menu>
                        <Menu.Label><b>Rename service</b></Menu.Label>
                        <Menu.Item icon={<BiRename size={18} />} onClick={()=>{}}>Change service name</Menu.Item>
                        <Divider />
                        <Menu.Label><b>Danger zone</b></Menu.Label>
                        <Menu.Item color="red" icon={<BsTrashFill size={18} />} onClick={()=>setDeleteModal(true)}>Delete Service</Menu.Item>
                    </Menu>
                    <Space w="md"/>                        
                    <Tooltip label="Stop service" zIndex={0} transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="red" opened={tooltipStopOpened} tooltipId="tooltip-stop-id">
                        <ActionIcon color="red" loading={buttonLoading}
                        onClick={()=>setStopModal(true)} size="xl" radius="md" variant="filled"
                        disabled={service.status === "stop"}
                        aria-describedby="tooltip-stop-id"
                        onFocus={() => setTooltipStopOpened(false)} onBlur={() => setTooltipStopOpened(false)}
                        onMouseEnter={() => setTooltipStopOpened(true)} onMouseLeave={() => setTooltipStopOpened(false)}>
                            <FaStop size="20px" />
                        </ActionIcon>
                    </Tooltip>
                    <Space w="md"/>
                    <Tooltip label="Start service" transition="pop" zIndex={0} transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="teal">
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
                <MediaQuery largerThan="md" styles={{ display: 'none' }}>
                    <><Space w="xl" /><Space w="xl" /></>
                </MediaQuery>
                
            </Grid.Col>
        </Grid>
        <YesNoModal
            title='Are you sure to stop this service?'
            description={`You are going to delete the service '${service.port}', causing the firewall to stop. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>{setStopModal(false);}}
            action={stopService}
            opened={stopModal}
        />
        <hr style={{width:"100%"}}/>
        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${service.port}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
    </>
}

export default ServiceRow;
