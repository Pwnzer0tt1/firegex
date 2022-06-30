import { Button, Group, NumberInput, Space, Notification, Modal, Center, Title } from '@mantine/core';
import { useForm } from '@mantine/hooks';
import React, { useEffect, useState } from 'react';
import { changeports, fireUpdateRequest, okNotify } from '../../js/utils';
import { ImCross } from "react-icons/im"
import { Service } from '../../js/models';
import { BsArrowDownSquareFill } from 'react-icons/bs';

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
        validationRules:{
            internalPort: (value) => value>0 && value<65536,
            port: (value) => value>0 && value<65536 
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
        changeports(service.id, data).then( res => {
            if (!res){
                setSubmitLoading(false)
                close();
                fireUpdateRequest();
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



            <NumberInput
                placeholder="30001"
                min={1}
                max={65535}
                label="Internal Proxy Port"
                {...form.getInputProps('internalPort')}
            />    

            <Space h="xl" />
            <Center><BsArrowDownSquareFill size={50}/></Center>
            
            <NumberInput
                placeholder="8080"
                min={1}
                max={65535}
                label="Public Service Port"
                {...form.getInputProps('port')}
            />

            <Space h="xl" />

            <Center><Title order={5}>The change of the ports will cause a temporarily shutdown of the service! ⚠️</Title></Center>

            <Space h="md" />

            <Group position="right" mt="md">
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
