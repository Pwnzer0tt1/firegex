import { Button, Group, Space, Notification, Modal, Center, Title } from '@mantine/core';
import { useForm } from '@mantine/form';
import React, { useEffect, useState } from 'react';
import { ImCross } from "react-icons/im"
import { FaLongArrowAltDown } from 'react-icons/fa';
import { regexproxy, Service } from '../utils';
import { okNotify } from '../../../js/utils';
import PortInput from '../../PortInput';

type InputForm = {
    internalPort:number,
    port:number
}

function ChangePortModal({ service, opened, onClose }:{ service:Service, opened:boolean, onClose:()=>void }) {

    const form = useForm({
        initialValues: {
            internalPort: service.internal_port,
            port: service.public_port
        },
        validate:{
            internalPort: (value) => (value>0 && value<65536) ? null : "Invalid internal port",
            port: (value) => (value>0 && value<65536) ? null : "Invalid public port",
        }
    })

    useEffect(()=>{
        form.setValues({internalPort: service.internal_port, port:service.public_port})
    },[opened])

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)
 
    const submitRequest = (data:InputForm) =>{
        setSubmitLoading(true)
        regexproxy.servicechangeport(service.id, data).then( res => {
            if (!res){
                setSubmitLoading(false)
                close();
                okNotify(`Internal port on ${service.name} service has changed in ${data.internalPort}`, `Successfully changed internal port of service with id ${service.id}`)
            }else{
                setSubmitLoading(false)
                setError("Invalid request! [ "+res+" ]")
            }
        }).catch( err => {
            setSubmitLoading(false)
            setError("Request Failed! [ "+err+" ]")
        })
    }    


  return <Modal size="xl" title="Change Ports" opened={opened} onClose={close} closeOnClickOutside={false} centered>
    <form onSubmit={form.onSubmit(submitRequest)}>

            <PortInput
                fullWidth
                label="Internal Proxy Port"
                {...form.getInputProps('internalPort')}
            />  

            <Space h="xl" />
            <Center><FaLongArrowAltDown size={50}/></Center>
            
            <PortInput
                fullWidth
                label="Public Service Port"
                {...form.getInputProps('port')}
            />
            
            <Space h="xl" />

            <Center><Title order={5}>The change of the ports will cause a temporarily shutdown of the service! ⚠️</Title></Center>

            <Space h="md" />

            <Group align="right" mt="md">
                <Button loading={submitLoading} disabled={
                    service.internal_port === form.values.internalPort && service.public_port === form.values.port
                    } type="submit">Change Port</Button>
            </Group>

            <Space h="md" />
            
            {error?<>
            <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                Error: {error}
            </Notification><Space h="md" /></>:null}
            
        </form>
    </Modal>

}

export default ChangePortModal;
