import { Button, Group, NumberInput, Space, TextInput, Notification, Modal } from '@mantine/core';
import { useForm } from '@mantine/hooks';
import React, { useState } from 'react';
import { ServiceAddForm } from '../js/models';
import { addservice, okNotify } from '../js/utils';
import { ImCross } from "react-icons/im"

function AddNewService({ opened, onClose }:{ opened:boolean, onClose:()=>void }) {

    const form = useForm({
        initialValues: {
            name:"",
            port:1,
        },
        validationRules:{
            name: (value) => value !== ""?true:false,
            port: (value) => value>0 && value<65536
        }
    })

    const close = () =>{
        onClose()
        form.reset()
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)

    const submitRequest = (values:ServiceAddForm) =>{
        setSubmitLoading(true)
        addservice(values).then( res => {
            if (!res){
                setSubmitLoading(false)
                close();
                okNotify(`Service ${values.name} has been added`, `Successfully added ${values.name} with port ${values.port}`)
            }else{
                setSubmitLoading(false)
                setError("Invalid request! [ "+res+" ]")
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

            <NumberInput
                placeholder="8080"
                min={1}
                max={65535}
                label="Service port"
                {...form.getInputProps('port')}
            />


            <Space h="md" />

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
