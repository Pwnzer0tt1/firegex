import { Button, Group, Space, TextInput, Notification, Modal } from '@mantine/core';
import { useForm } from '@mantine/hooks';
import React, { useEffect, useState } from 'react';
import { fireUpdateRequest, okNotify, renameservice } from '../../js/utils';
import { ImCross } from "react-icons/im"
import { Service } from '../../js/models';

function RenameForm({ opened, onClose, service }:{ opened:boolean, onClose:()=>void, service:Service }) { 

    const form = useForm({
        initialValues: { name:service.name },
        validationRules:{ name: (value) => value !== "" }
    })

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    useEffect(()=> form.setFieldValue("name", service.name),[opened])

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)

    const submitRequest = ({ name }:{ name:string }) => {
        setSubmitLoading(true)
        renameservice(service.id, name).then( res => {
            if (!res){
                setSubmitLoading(false)
                close();
                fireUpdateRequest();
                okNotify(`Service ${service.name} has been renamed in ${ name }`, `Successfully renamed service on port ${service.public_port}`)
            }else{
                setSubmitLoading(false)
                setError("Error: [ "+res+" ]")
            }
        }).catch( err => {
            setSubmitLoading(false)
            setError("Request Failed! [ "+err+" ]")
        })

    }    


  return <Modal size="xl" title={`Rename '${service.name}' service on port ${service.public_port}`} opened={opened} onClose={close} closeOnClickOutside={false} centered>
    <form onSubmit={form.onSubmit(submitRequest)}>
            <TextInput
                label="Service Name"
                placeholder="Awesome Service Name!"
                {...form.getInputProps('name')}
            />
            <Group position="right" mt="md">
                <Button loading={submitLoading} type="submit">Rename</Button>
            </Group>

            <Space h="md" />

            {error?<>
            <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                Error: {error}
            </Notification><Space h="md" /></>:null}

        </form>
    </Modal>

}

export default RenameForm;