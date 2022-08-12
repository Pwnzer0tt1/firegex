import { ActionIcon, Badge, Divider, Grid, MediaQuery, Menu, Space, Title, Tooltip } from '@mantine/core';
import React, { useState } from 'react';
import { FaPlay, FaStop } from 'react-icons/fa';
import { porthijack, Service } from '../utils';
import style from "./index.module.scss";
import YesNoModal from '../../YesNoModal';
import { errorNotify, okNotify, regex_ipv4 } from '../../../js/utils';
import { BsArrowRepeat, BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi'
import RenameForm from './RenameForm';
import ChangeDestination from './ChangeDestination';

function ServiceRow({ service }:{ service:Service }) {

    let status_color = service.active ? "teal": "red"

    const [buttonLoading, setButtonLoading] = useState(false)
    const [tooltipStopOpened, setTooltipStopOpened] = useState(false);
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [changeDestModal, setChangeDestModal] = useState(false)

    const stopService = async () => {
        setButtonLoading(true)
        
        await porthijack.servicestop(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} stopped successfully!`,`The service on ${service.public_port} has been stopped!`)
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${service.public_port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${service.public_port}`,`Error: ${err}`)
        })
        setButtonLoading(false);
    }

    const startService = async () => {
        setButtonLoading(true)
        await porthijack.servicestart(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} started successfully!`,`The service on ${service.public_port} has been started!`)
            }else{
                errorNotify(`An error as occurred during the starting of the service ${service.public_port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${service.public_port}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const deleteService = () => {
        porthijack.servicedelete(service.service_id).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${service.name} has been deleted!`)
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
                        <div className="center-flex"><Title className={style.name}>{service.name}</Title> <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient">:{service.public_port}</Badge></div>
                        <Badge color={status_color} radius="sm" size="lg" variant="filled">Status: <u>{service.active?"ENABLED":"DISABLED"}</u></Badge>
                    </div>
                </div></MediaQuery>
                <MediaQuery largerThan="md" styles={{ display: 'none' }}><div>
                    <div className="center-flex">
                        <div className="center-flex"><Title className={style.name}>{service.name}</Title> <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient">:{service.public_port}</Badge></div>
                        <Badge style={{marginLeft:"20px"}} color={status_color} radius="sm" size="lg" variant="filled">Status: <u>{service.active?"ENABLED":"DISABLED"}</u></Badge>
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
                    <Badge color={service.ip_src.match(regex_ipv4)?"cyan":"pink"} radius="sm" size="md" variant="filled">{service.ip_src} on {service.proto}</Badge>
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
                        <Menu.Item icon={<BiRename size={18} />} onClick={()=>setRenameModal(true)}>Change service name</Menu.Item>
                        <Menu.Label><b>Change destination</b></Menu.Label>
                        <Menu.Item icon={<BsArrowRepeat size={18} />} onClick={()=>setChangeDestModal(true)}>Change hijacking destination</Menu.Item>
                        <Divider />
                        <Menu.Label><b>Danger zone</b></Menu.Label>
                        <Menu.Item color="red" icon={<BsTrashFill size={18} />} onClick={()=>setDeleteModal(true)}>Delete Service</Menu.Item>
                    </Menu>
                    <Space w="md"/>                        
                    <Tooltip label="Stop service" zIndex={0} transition="pop" transitionDuration={200} transitionTimingFunction="ease" color="red" opened={tooltipStopOpened} tooltipId="tooltip-stop-id">
                        <ActionIcon color="red" loading={buttonLoading}
                        onClick={stopService} size="xl" radius="md" variant="filled"
                        disabled={!service.active}
                        aria-describedby="tooltip-stop-id"
                        onFocus={() => setTooltipStopOpened(false)} onBlur={() => setTooltipStopOpened(false)}
                        onMouseEnter={() => setTooltipStopOpened(true)} onMouseLeave={() => setTooltipStopOpened(false)}>
                            <FaStop size="20px" />
                        </ActionIcon>
                    </Tooltip>
                    <Space w="md"/>
                    <Tooltip label="Start service" transition="pop" zIndex={0} transitionDuration={200} transitionTimingFunction="ease" color="teal">
                        <ActionIcon color="teal" size="xl" radius="md" onClick={startService} loading={buttonLoading}
                                    variant="filled" disabled={service.active}>
                            <FaPlay size="20px" />
                        </ActionIcon>
                    </Tooltip>
                </div>
                <Space w="xl" /><Space w="xl" />
                <MediaQuery largerThan="md" styles={{ display: 'none' }}>
                    <><Space w="xl" /><Space w="xl" /></>
                </MediaQuery>
                
            </Grid.Col>
        </Grid>
        <hr style={{width:"100%"}}/>
        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${service.public_port}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
        <RenameForm
            onClose={()=>setRenameModal(false)}
            opened={renameModal}
            service={service}
        />
        <ChangeDestination
            onClose={()=>setChangeDestModal(false)}
            opened={changeDestModal}
            service={service}
        />
    </>
}

export default ServiceRow;
