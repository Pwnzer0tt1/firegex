import { Button, Group, Space, TextInput, Notification, Modal, Switch } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useState } from 'react';
import { okNotify } from '../../js/utils';
import { ImCross } from "react-icons/im"
import { regexproxy } from './utils';
import PortInput from '../PortInput';

type ServiceAddForm = {
    name:string,
    port:number,
    autostart: boolean,
    chosenInternalPort: boolean,
    internalPort: number
}

function AddNewService({ opened, onClose }:{ opened:boolean, onClose:()=>void }) {

    const form = useForm({
        initialValues: {
            name:"",
            port:8080,
            internalPort:30001,
            chosenInternalPort:false,
            autostart: true
        },
        validate:{
            name: (value) => value !== ""? null : "Service name is required",
            port: (value) => (value>0 && value<65536) ? null : "Invalid port",
            internalPort: (value) => (value>0 && value<65536) ? null : "Invalid internal port",
        }
    })

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)
 
    const submitRequest = ({ name, port, autostart, chosenInternalPort, internalPort }:ServiceAddForm) =>{
        setSubmitLoading(true)
        regexproxy.servicesadd(chosenInternalPort?{ internalPort, name, port }:{ name, port }).then( res => {
            if (res.status === "ok"){
                setSubmitLoading(false)
                close();
                if (autostart) regexproxy.servicestart(res.id)
                okNotify(`Service ${name} has been added`, `Successfully added ${res.id} with port ${port}`)
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

            <PortInput
                fullWidth
                label="Public Service port"
                {...form.getInputProps('port')}
            />

            {form.values.chosenInternalPort?<>
                <Space h="md" />
                <PortInput
                    fullWidth
                    label="Internal Proxy Port"
                    {...form.getInputProps('internalPort')}
                />
                <Space h="sm" />
            </>:null}

            <Space h="xl" />

            <Switch
                label="Auto-Start Service"
                {...form.getInputProps('autostart', { type: 'checkbox' })}
            />

            <Space h="md" />

            <Switch
                label="Choose internal port"
                {...form.getInputProps('chosenInternalPort', { type: 'checkbox' })}
            />

            <Group align="right" mt="md">
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
