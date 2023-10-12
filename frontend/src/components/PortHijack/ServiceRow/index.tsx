import { ActionIcon, Badge, Divider, Menu, Space, Title, Tooltip } from '@mantine/core';
import React, { useState } from 'react';
import { FaPlay, FaStop } from 'react-icons/fa';
import { porthijack, Service } from '../utils';
import style from "./index.module.scss";
import YesNoModal from '../../YesNoModal';
import { errorNotify, isMediumScreen, okNotify } from '../../../js/utils';
import { BsArrowRepeat, BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi'
import RenameForm from './RenameForm';
import ChangeDestination from './ChangeDestination';
import PortInput from '../../PortInput';
import { useForm } from '@mantine/form';
import { MenuDropDownWithButton } from '../../MainLayout';

function ServiceRow({ service }:{ service:Service }) {

    let status_color = service.active ? "teal": "red"

    const [buttonLoading, setButtonLoading] = useState(false)
    const [tooltipStopOpened, setTooltipStopOpened] = useState(false);
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [changeDestModal, setChangeDestModal] = useState(false)
    const portInputRef = React.createRef<HTMLInputElement>()
    const isMedium = isMediumScreen()

    const form = useForm({
        initialValues: { proxy_port:service.proxy_port },
        validate:{ proxy_port: (value) => (value > 0 && value < 65536)? null : "Invalid proxy port" }
    })

    const onChangeProxyPort = ({proxy_port}:{proxy_port:number}) => {
        if (proxy_port === service.proxy_port) return
        if (proxy_port > 0 && proxy_port < 65536 && proxy_port !== service.public_port){
            porthijack.changedestination(service.service_id, service.ip_dst, proxy_port).then( res => {
                if (res.status === "ok"){
                    okNotify(`Service ${service.name} destination port has changed in ${ proxy_port }`, `Successfully changed destination port`)
                }else{
                    errorNotify(`Error while changing the destination port of ${service.name}`,`Error: ${res.status}`)
                }
            }).catch( err => {
                errorNotify("Request for changing port failed!",`Error: [ ${err} ]`)
            })
        }else{
            form.setFieldValue("proxy_port", service.proxy_port)
            errorNotify(`Error while changing the destination port of ${service.name}`,`Insert a valid port number`)
        }
    }

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
        <div className={isMedium?style.row:style.row_mobile} style={{width:"100%"}}>
            <Space w="xl" /><Space w="xl" />
            <div>
                <div className="center-flex-row">
                    <Title order={4} className={style.name}>{service.name}</Title>
                    <div className="center-flex">
                        <Badge color={status_color} radius="sm" size="md" variant="filled">Status: <u>{service.active?"ENABLED":"DISABLED"}</u></Badge>
                        <Space w="sm" />
                        <Badge color={service.proto === "tcp"?"cyan":"orange"} radius="sm" size="md" variant="filled">
                            {service.proto}
                        </Badge>
                    </div>
                </div>
            </div>
        
            <div className='flex-spacer' />
            {isMedium?null:<Space h="xl" />}
            <div className='center-flex'>
            <div className="center-flex-row">
                <Badge color="lime" radius="sm" size="md" variant="filled">
                    FROM {service.ip_src} : {service.public_port}
                </Badge>
                <Space h="sm" />
                <Badge color="blue" radius="sm" size="md" variant="filled">
                    <div className="center-flex">
                        TO {service.ip_dst} : 
                        <form onSubmit={form.onSubmit((v)=>portInputRef.current?.blur())}>
                            <PortInput
                                defaultValue={service.proxy_port}
                                size="xs"
                                variant="unstyled"
                                style={{
                                    width: (10+form.values.proxy_port.toString().length*6.2) +"px"
                                }}
                                className={style.portInput}
                                onBlur={(e)=>{onChangeProxyPort({proxy_port:parseInt(e.target.value)})}}
                                ref={portInputRef}
                                {...form.getInputProps("proxy_port")}
                            />
                        </form>
                    </div>
                </Badge>
            </div>

            <Space w="xl" /><Space w="xl" />
            <div className="center-flex">
                <MenuDropDownWithButton>
                    <Menu.Label><b>Rename service</b></Menu.Label>
                    <Menu.Item icon={<BiRename size={18} />} onClick={()=>setRenameModal(true)}>Change service name</Menu.Item>
                    <Menu.Label><b>Change destination</b></Menu.Label>
                    <Menu.Item icon={<BsArrowRepeat size={18} />} onClick={()=>setChangeDestModal(true)}>Change hijacking destination</Menu.Item>
                    <Divider />
                    <Menu.Label><b>Danger zone</b></Menu.Label>
                    <Menu.Item color="red" icon={<BsTrashFill size={18} />} onClick={()=>setDeleteModal(true)}>Delete Service</Menu.Item>
                </MenuDropDownWithButton>
                <Space w="md"/>                        
                <Tooltip label="Stop service" zIndex={0} color="red" opened={tooltipStopOpened}>
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
                <Tooltip label="Start service" zIndex={0} color="teal">
                    <ActionIcon color="teal" size="xl" radius="md" onClick={startService} loading={buttonLoading}
                                variant="filled" disabled={service.active}>
                        <FaPlay size="20px" />
                    </ActionIcon>
                </Tooltip>
            </div>
            </div>
            {isMedium?null:<Space h="xl" />}
            <Space w="xl" /><Space w="xl" />
                
        </div>
        <Divider size="sm" style={{width:"100%"}}/>

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
