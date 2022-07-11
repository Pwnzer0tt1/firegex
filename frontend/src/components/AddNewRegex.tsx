import { Button, Group, Space, TextInput, Notification, Switch, NativeSelect, Modal } from '@mantine/core';
import { useForm } from '@mantine/hooks';
import React, { useState } from 'react';
import { RegexAddForm } from '../js/models';
import { addregex, b64decode, b64encode, fireUpdateRequest, okNotify } from '../js/utils';
import { ImCross } from "react-icons/im"
import FilterTypeSelector from './FilterTypeSelector';


type RegexAddInfo = {
    regex:string,
    type:string,
    mode:string,
    is_case_insensitive:boolean,
    deactive:boolean
}

function AddNewRegex({ opened, onClose, service }:{ opened:boolean, onClose:()=>void, service:string }) { 

    const form = useForm({
        initialValues: {
            regex:"",
            type:"blacklist",
            mode:"C -> S",
            is_case_insensitive:false,
            deactive:false
        },
        validationRules:{
            regex: (value) => value !== "",
            type: (value) => ["blacklist","whitelist"].includes(value),
            mode: (value) => ['C -> S', 'S -> C', 'C <-> S'].includes(value)
        }
    })

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)

    const submitRequest = (values:RegexAddInfo) => {
        setSubmitLoading(true)
        const filter_mode = ({'C -> S':'C', 'S -> C':'S', 'C <-> S':'B'}[values.mode])

        const request:RegexAddForm = {
            is_blacklist:values.type !== "whitelist",
            is_case_sensitive: !values.is_case_insensitive,
            service_id: service,
            mode: filter_mode?filter_mode:"B",
            regex: b64encode(values.regex),
            active: !values.deactive
        }
        setSubmitLoading(false)
        addregex(request).then( res => {
            if (!res){
                setSubmitLoading(false)
                close();
                fireUpdateRequest();
                okNotify(`Regex ${b64decode(request.regex)} has been added`, `Successfully added  ${request.is_case_sensitive?"case sensitive":"case insensitive"} ${request.is_blacklist?"blacklist":"whitelist"} regex to ${request.service_id} service`)
            }else if (res.toLowerCase() === "invalid regex"){
                setSubmitLoading(false)
                form.setFieldError("regex", "Invalid Regex")
            }else{
                setSubmitLoading(false)
                setError("Error: [ "+res+" ]")
            }
        }).catch( err => {
            setSubmitLoading(false)
            setError("Request Failed! [ "+err+" ]")
        })
        
    }    


  return <Modal size="xl" title="Add a new regex filter" opened={opened} onClose={close} closeOnClickOutside={false} centered>
    <form onSubmit={form.onSubmit(submitRequest)}>
            <TextInput
                label="Regex"
                placeholder="[A-Z0-9]{31}="
                {...form.getInputProps('regex')}
            />
            <Space h="md" />
            <Switch
                label="Case insensitive"
                {...form.getInputProps('is_case_insensitive', { type: 'checkbox' })}
            />
            <Space h="md" />
            <Switch
                label="Deactivate"
                {...form.getInputProps('deactive', { type: 'checkbox' })}
            />
            <Space h="md" />
            <NativeSelect
                data={['C -> S', 'S -> C', 'C <-> S']}
                label="Choose the source of the packets to filter"
                variant="filled"
                {...form.getInputProps('mode')}
            />
            <Space h="md" />
            <FilterTypeSelector
                size="md"
                color="gray"
                {...form.getInputProps('type')}
            />
            <Group position="right" mt="md">
                <Button loading={submitLoading} type="submit">Add Filter</Button>
            </Group>

            <Space h="md" />
            
            {error?<>
            <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                Error: {error}
            </Notification><Space h="md" /></>:null}
            
        </form>
    </Modal>

}

export default AddNewRegex;
