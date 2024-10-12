import { ActionIcon, Badge, Box, Divider, Grid, Menu, Space, Title, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { FaPause, FaPlay, FaStop } from 'react-icons/fa';
import { MdOutlineArrowForwardIos } from "react-icons/md"
import YesNoModal from '../../YesNoModal';
import { errorNotify, isMediumScreen, okNotify } from '../../../js/utils';
import { BsArrowRepeat, BsTrashFill } from 'react-icons/bs';
import { TbNumbers } from 'react-icons/tb';
import { BiRename } from 'react-icons/bi'
import ChangePortModal from './ChangePortModal';
import RenameForm from './RenameForm';
import { regexproxy, Service } from '../utils';
import { MenuDropDownWithButton } from '../../MainLayout';

//"status":"stop"/"wait"/"active"/"pause",
function ServiceRow({ service, onClick }:{ service:Service, onClick?:()=>void }) {

    let status_color = "gray";
    switch(service.status){
        case "stop": status_color = "red"; break;
        case "wait": status_color = "yellow"; break;
        case "active": status_color = "teal"; break;
        case "pause": status_color = "cyan"; break;
    }

    const [stopModal, setStopModal] = useState(false);
    const [buttonLoading, setButtonLoading] = useState(false)
    const [tooltipStopOpened, setTooltipStopOpened] = useState(false);
    const [deleteModal, setDeleteModal] = useState(false)
    const [changePortModal, setChangePortModal] = useState(false)
    const [choosePortModal, setChoosePortModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)

    const isMedium = isMediumScreen()

    const stopService = async () => {
        setButtonLoading(true)
        await regexproxy.servicestop(service.id).then(res => {
            if(!res){
                okNotify(`Service ${service.id} stopped successfully!`,`The service ${service.name} has been stopped!`)
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${service.id}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${service.id}`,`Error: ${err}`)
        })
        setButtonLoading(false);
    }

    const startService = async () => {
        setButtonLoading(true)
        await regexproxy.servicestart(service.id).then(res => {
            if(!res){
                okNotify(`Service ${service.id} started successfully!`,`The service ${service.name} has been started!`)
            }else{
                errorNotify(`An error as occurred during the starting of the service ${service.id}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${service.id}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const pauseService = async () => {
        setButtonLoading(true)
        await regexproxy.servicepause(service.id).then(res => {
            if(!res){
                okNotify(`Service ${service.id} paused successfully!`,`The service ${service.name} has been paused (Transparent mode)!`)
            }else{
                errorNotify(`An error as occurred during the pausing of the service ${service.id}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the pausing of the service ${service.id}`,`Error: ${err}`)
        })
        setButtonLoading(false)
        
    }

    const deleteService = () => {
        regexproxy.servicedelete(service.id).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${service.id} has been deleted!`)
            }else
                errorNotify("An error occurred while deleting a service",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while deleting a service",`Error: ${err}`)
        })
        
    }

    const changePort = () => {
        regexproxy.serviceregenport(service.id).then(res => {
            if (!res){
                okNotify("Service port regeneration completed!",`The service ${service.id} has changed the internal port!`)
            }else
                errorNotify("An error occurred while changing the internal service port",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while changing the internal service port",`Error: ${err}`)
        })
    }

    return <>
        <Grid className="firegex__servicerow__row" justify="flex-end" style={{width:"100%"}}>
            <Grid.Col span={{ md:4, xs: 12 }}>
                <Box className={isMedium?"center-flex-row":"center-flex"}>
                    <Box className="center-flex"><Title className="firegex__servicerow__name">{service.name}</Title> <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient">:{service.public_port}</Badge></Box>
                    <Badge color={status_color} size="lg" radius="md">{service.internal_port} {"->"} {service.public_port}</Badge>
                </Box>
                {!isMedium?<Space h="xl" />:null}
            </Grid.Col>
            
            <Grid.Col className="center-flex" span={{ md:8, xs: 12 }}>
                {!isMedium?<Box className='flex-spacer' />:<><Space w="xl" /><Space w="xl" /></>}
                <Box className="center-flex-row">
                    <Badge style={{marginBottom:"20px"}} color={status_color} radius="sm" size="lg" variant="filled">Status: <u>{service.status}</u></Badge>
                    <Badge style={{marginBottom:"8px"}}color="violet" radius="sm" size="md" variant="filled">Regex: {service.n_regex}</Badge>
                    <Badge color="yellow" radius="sm" size="md" variant="filled">Connections Blocked: {service.n_packets}</Badge>
                </Box>
                {isMedium?<Box className='flex-spacer' />:<><Space w="xl" /><Space w="xl" /></>}
                <Box className="center-flex">
                    <MenuDropDownWithButton>
                        <Menu.Label><b>Rename service</b></Menu.Label>
                        <Menu.Item leftSection={<BiRename size={18} />} onClick={()=>setRenameModal(true)}>Change service name</Menu.Item>
                        <Divider />
                        <Menu.Label><b>Change ports</b></Menu.Label>
                        <Menu.Item leftSection={<TbNumbers size={18} />} onClick={()=>setChoosePortModal(true)}>Change port</Menu.Item>
                        <Menu.Item leftSection={<BsArrowRepeat size={18} />} onClick={()=>setChangePortModal(true)}>Regen proxy port</Menu.Item>
                        <Divider />
                        <Menu.Label><b>Danger zone</b></Menu.Label>
                        <Menu.Item color="red" leftSection={<BsTrashFill size={18} />} onClick={()=>setDeleteModal(true)}>Delete Service</Menu.Item>
                    </MenuDropDownWithButton>
                    <Space w="md"/>
                    {["pause","wait"].includes(service.status)?
                        
                        <Tooltip label="Stop service" zIndex={0} color="orange" opened={tooltipStopOpened}>
                            <ActionIcon color="yellow" loading={buttonLoading}
                            onClick={()=>setStopModal(true)} size="xl" radius="md" variant="filled"
                            disabled={service.status === "stop"}
                            aria-describedby="tooltip-stop-id"
                            onFocus={() => setTooltipStopOpened(false)} onBlur={() => setTooltipStopOpened(false)}
                            onMouseEnter={() => setTooltipStopOpened(true)} onMouseLeave={() => setTooltipStopOpened(false)}>
                                <FaStop size="20px" />
                            </ActionIcon>
                        </Tooltip>:
                        <Tooltip label={service.status === "stop"?"Start in pause mode":"Pause service"} zIndex={0} color={service.status === "stop"?"cyan":"red"}>
                            <ActionIcon color={service.status === "stop"?"cyan":"red"} loading={buttonLoading}
                                    onClick={pauseService} size="xl" radius="md" variant="filled">
                                <FaPause size="20px" />
                            </ActionIcon>
                        </Tooltip>
                    }
                    
                    <Space w="md"/>
                    <Tooltip label="Start service" zIndex={0} color="teal">
                        <ActionIcon color="teal" size="xl" radius="md" onClick={startService} loading={buttonLoading}
                                    variant="filled" disabled={!["stop","pause"].includes(service.status)?true:false}>
                            <FaPlay size="20px" />
                        </ActionIcon>
                    </Tooltip>
                </Box>
                <Space w="xl" /><Space w="xl" />
                {onClick?<Box>
                    <MdOutlineArrowForwardIos onClick={onClick} style={{cursor:"pointer"}} size={45} />
                    <Space w="xl" />
                </Box>:null}
                {!isMedium?<><Space w="xl" /><Space w="xl" /></>:null}
                
            </Grid.Col>
        </Grid>
        <YesNoModal
            title='Are you sure to stop this service?'
            description={`You are going to delete the service '${service.id}', causing the firewall to stop. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>{setStopModal(false);}}
            action={stopService}
            opened={stopModal}
        />
        <Divider size="md" style={{width:"100%"}}/>
        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${service.id}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
        <YesNoModal
            title='Are you sure to change the proxy internal port?'
            description={`You are going to change the proxy port '${service.internal_port}'. This will cause the shutdown of your service temporarily! ⚠️`}
            onClose={()=>setChangePortModal(false)}
            action={changePort}
            opened={changePortModal}
        />
        <ChangePortModal
            service={service}
            onClose={()=> setChoosePortModal(false)}
            opened={choosePortModal}
        />
        <RenameForm
            onClose={()=>setRenameModal(false)}
            opened={renameModal}
            service={service}
        />
    </>
}

export default ServiceRow;
