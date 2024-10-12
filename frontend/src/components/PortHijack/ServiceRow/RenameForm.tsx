import { Button, Group, Space, TextInput, Notification, Modal } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { okNotify } from '../../../js/utils';
import { ImCross } from "react-icons/im"
import { porthijack, Service } from '../utils';

function RenameForm({ opened, onClose, service }:{ opened:boolean, onClose:()=>void, service:Service }) { 

    const form = useForm({
        initialValues: { name:service.name },
        validate:{ name: (value) => value !== ""? null : "Service name is required" }
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
        porthijack.servicerename(service.service_id, name).then( res => {
            if (!res){
                setSubmitLoading(false)
                close();
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
            <Group align="right" mt="md">
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
