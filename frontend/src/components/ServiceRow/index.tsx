import { ActionIcon, Badge, Grid, Space, Title } from '@mantine/core';
import React, { useState } from 'react';
import { FaPause, FaPlay, FaStop } from 'react-icons/fa';
import { Service } from '../../js/models';
import { MdOutlineArrowForwardIos } from "react-icons/md"
import style from "./ServiceRow.module.scss";
import YesNoModal from '../YesNoModal';
import { errorNotify, okNotify, pauseservice, startservice, stopservice } from '../../js/utils';

//"status":"stop"/"wait"/"active"/"pause",
function ServiceRow({ service, onClick, additional_buttons }:{ service:Service, onClick?:()=>void, additional_buttons?:any }) {

    let status_color = "gray";
    switch(service.status){
        case "stop": status_color = "red"; break;
        case "wait": status_color = "yellow"; break;
        case "active": status_color = "teal"; break;
        case "pause": status_color = "cyan"; break;
    }

    const [stopModal, setStopModal] = useState(false);
    const [buttonLoading, setButtonLoading] = useState(false)

    const stopService = async () => {
        setButtonLoading(true)
        await stopservice(service.id).then(res => {
            if(!res){
                okNotify(`Service ${service.id} stopped successfully!`,`The service ${service.name} has been stopped!`)
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${service.id}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${service.id}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const startService = async () => {
        setButtonLoading(true)
        await startservice(service.id).then(res => {
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
        await pauseservice(service.id).then(res => {
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


    return <>
        <Grid className={style.row} style={{width:"100%"}}>
            <Grid.Col span={4}>
                <div className="center-flex-row">
                    <div className="center-flex"><Title className={style.name}>{service.name}</Title> <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient">:{service.public_port}</Badge></div>
                    <Badge color={status_color} size="xl" radius="md">{service.internal_port} {"->"} {service.public_port}</Badge>
                </div>
            </Grid.Col>
            <Grid.Col className="center-flex" span={8}>
                <div className='flex-spacer'></div>
                <div className="center-flex-row">
                    <Badge style={{marginBottom:"20px"}} color={status_color} radius="sm" size="xl" variant="filled">Status: <u>{service.status}</u></Badge>
                    <Badge style={{marginBottom:"8px"}}color="violet" radius="sm" size="lg" variant="filled">Regex: {service.n_regex}</Badge>
                    <Badge color="yellow" radius="sm" size="lg" variant="filled">Connections Blocked: {service.n_packets}</Badge>
                </div>
                <Space w="xl" /><Space w="xl" />
                <div className="center-flex">
                    {additional_buttons}
                    {["pause","wait"].includes(service.status)?
                        <ActionIcon color="yellow" loading={buttonLoading}
                        onClick={()=>setStopModal(true)} size="xl" radius="md" variant="filled"
                        disabled={service.status === "stop"}>
                            <FaStop size="20px" />
                        </ActionIcon>:
                        <ActionIcon color="red" loading={buttonLoading}
                                onClick={pauseService} size="xl" radius="md" variant="filled"
                                disabled={service.status === "stop"}>
                            <FaPause size="20px" />
                        </ActionIcon>
                    }
                    
                    <Space w="md"/>
                    <ActionIcon color="teal" size="xl" radius="md" onClick={startService} loading={buttonLoading}
                                variant="filled" disabled={!["stop","pause"].includes(service.status)?true:false}>
                        <FaPlay size="20px" />
                    </ActionIcon>
                </div>
                <Space w="xl" /><Space w="xl" />
                {onClick?<MdOutlineArrowForwardIos onClick={onClick} style={{cursor:"pointer"}} size="45px" />:null}
                <Space w="xl" />
            </Grid.Col>
        </Grid>
        <YesNoModal
            title='Are you sure to stop this service!'
            description={`You are going to delete the service '${service.id}', causing the stopping of the firewall. This will cause the shutdown of your service ⚠️!`}
            onClose={()=>setStopModal(false)}
            action={stopService}
            opened={stopModal}
        />
        <hr style={{width:"100%"}}/>
    </>
}

export default ServiceRow;
