import { Button, Group, Space, TextInput, Notification, Switch, NativeSelect } from '@mantine/core';
import { useForm } from '@mantine/hooks';
import React, { useState } from 'react';
import { RegexAddForm } from '../js/models';
import { addregex, b64encode, getHumanReadableRegex, okNotify, validateRegex } from '../js/utils';
import { ImCross } from "react-icons/im"
import FilterTypeSelector from './FilterTypeSelector';


type RegexAddInfo = {
    regex:string,
    type:string,
    mode:string,
    regex_exact:boolean,
    percentage_encoding:boolean
}

function AddNewRegex({ closePopup, service }:{ closePopup:()=>void, service:string }) { 

    const form = useForm({
        initialValues: {
            regex:"",
            type:"blacklist",
            mode:"C <-> S",
            regex_exact:false,
            percentage_encoding:false
        },
        validationRules:{
            regex: (value) => value !== "" && validateRegex(value),
            type: (value) => ["blacklist","whitelist"].includes(value),
            mode: (value) => ['C -> S', 'S -> C', 'C <-> S'].includes(value)
        }
    })

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)

    const submitRequest = (values:RegexAddInfo) => {
        setSubmitLoading(true)
        const filter_mode = ({'C -> S':'C', 'S -> C':'S', 'C <-> S':'B'}[values.mode])

        let final_regex = values.regex
        if (values.percentage_encoding){
            final_regex = decodeURIComponent(final_regex)
        }
        if(!values.regex_exact){
            final_regex = ".*"+final_regex+".*"
        }

        const request:RegexAddForm = {
            is_blacklist:values.type !== "whitelist",
            service_id: service,
            mode: filter_mode?filter_mode:"B",
            regex: b64encode(final_regex)
        }
        setSubmitLoading(false)
        addregex(request).then( res => {
            if (!res){
                setSubmitLoading(false)
                closePopup();
                okNotify(`Regex ${getHumanReadableRegex(request.regex)} has been added`, `Successfully added ${request.is_blacklist?"blacklist":"whitelist"} regex to ${request.service_id} service`)
            }else{
                setSubmitLoading(false)
                setError("Invalid request! [ "+res+" ]")
            }
        }).catch( err => {
            setSubmitLoading(false)
            setError("Request Failed! [ "+err+" ]")
        })
        
    }    


  return <form onSubmit={form.onSubmit(submitRequest)}>
        <TextInput
            required
            label="Regex"
            placeholder="[A-Z0-9]{31}="
            {...form.getInputProps('regex')}
        />
        <Space h="md" />
        <Switch
            label="Use percentage encoding for binary values"
            {...form.getInputProps('percentage_encoding', { type: 'checkbox' })}
        />
        <Space h="md" />
        <Switch
            label="Match the exactly the regex"
            {...form.getInputProps('regex_exact', { type: 'checkbox' })}
        />
        <Space h="md" />
        <NativeSelect
            data={['C -> S', 'S -> C', 'C <-> S']}
            label="Choose the source of the packets to filter"
            variant="filled"
            required
            {...form.getInputProps('mode')}
        />
        <Space h="md" />
        <FilterTypeSelector
            size="md"
            color="gray"
            required
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

}

export default AddNewRegex;
