import { Button, Group, NumberInput, Space, TextInput, Notification, Modal, Switch, SegmentedControl } from '@mantine/core';
import { useForm } from '@mantine/hooks';
import React, { useState } from 'react';
import { addservice, okNotify, startservice, regex_ipv4, regex_ipv6 } from '../js/utils';
import { ImCross } from "react-icons/im"

type ServiceAddForm = {
    name:string,
    port:number,
    proto:string,
    ip_int:string,
    autostart: boolean,
}

function AddNewService({ opened, onClose }:{ opened:boolean, onClose:()=>void }) {

    const form = useForm({
        initialValues: {
            name:"",
            port:8080,
            ip_int:"127.0.0.1",
            proto:"tcp",
            autostart: true
        },
        validationRules:{
            name: (value) => value !== ""?true:false,
            port: (value) => value>0 && value<65536,
            proto: (value) => ["tcp","udp"].includes(value),
            ip_int: (value) => value.match(regex_ipv6)?true:false || value.match(regex_ipv4)?true:false
        }
    })

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)
 
    const submitRequest = ({ name, port, autostart, proto, ip_int }:ServiceAddForm) =>{
        setSubmitLoading(true)
        addservice({name, port, proto, ip_int }).then( res => {
            if (res.status === "ok" && res.service_id){
                setSubmitLoading(false)
                close();
                if (autostart) startservice(res.service_id)
                okNotify(`Service ${name} has been added`, `Successfully added service with port ${port}`)
            }else{
                setSubmitLoading(false)
                setError("Invalid request! [ "+res.status+" ]")
            }
        }).catch( err => {
            setSubmitLoading(false)
            setError("Request Failed! [ "+err+" ]")
        })
    }    

  return <Modal size="xl" title="Add a new service" opened={opened} onClose={close} closeOnClickOutside={false} centered>
    <form onSubmit={form.onSubmit(submitRequest)}>
            <TextInput
                label="Service name"
                placeholder="Challenge 01"
                {...form.getInputProps('name')}
            />
            <Space h="md" />

            <TextInput
                label="Public IP Interface (ipv4/ipv6 + CIDR allowed)"
                placeholder="10.1.1.0/24"
                {...form.getInputProps('ip_int')}
            />

            <Space h="md" />

            <NumberInput
                placeholder="8080"
                min={1}
                max={65535}
                label="Public Service port"
                {...form.getInputProps('port')}
            />
            
            <Space h="md" />


            <div className='center-flex'>
                <Switch
                    label="Auto-Start Service"
                    {...form.getInputProps('autostart', { type: 'checkbox' })}
                />  
                <div className="flex-spacer"></div>
                <SegmentedControl
                    data={[
                        { label: 'TCP', value: 'tcp' },
                        { label: 'UDP', value: 'udp' },
                    ]}
                    {...form.getInputProps('proto')}
                />
            </div>      

            <Group position="right" mt="md">
                <Button loading={submitLoading} type="submit">Add Service</Button>
            </Group>

            <Space h="md" />
            
            {error?<>
            <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                Error: {error}
            </Notification><Space h="md" /></>:null}
            
        </form>
    </Modal>

}

export default AddNewService;
