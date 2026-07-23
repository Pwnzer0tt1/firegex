import { Button, Group, Space, TextInput, Notification, Switch, Modal, Card, Text, Title, SegmentedControl, Box } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useState } from 'react';
import { RegexAddForm } from '../js/models';
import { b64decode, b64encode, okNotify } from '../js/utils';
import { ImCross } from "react-icons/im"
import { nfregex } from './NFRegex/utils';

type RegexAddInfo = {
    regex:string,
    mode:string,
    is_case_insensitive:boolean,
    deactive:boolean
}

function AddNewRegex({ opened, onClose, service }:{ opened:boolean, onClose:()=>void, service:string }) { 

    const form = useForm({
        initialValues: {
            regex:"",
            mode:"C",
            is_case_insensitive:false,
            deactive:false
        },
        validate:{
            regex: (value) => value !== "" ? null : "Regex is required",
            mode: (value) => ['C', 'S', 'B'].includes(value) ? null : "Invalid mode",
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

        const request:RegexAddForm = {
            is_case_sensitive: !values.is_case_insensitive,
            service_id: service,
            mode: values.mode?values.mode:"B",
            regex: b64encode(values.regex),
            active: !values.deactive
        }
        setSubmitLoading(false)
        nfregex.regexesadd(request).then( res => {
            if (!res){
                setSubmitLoading(false)
                close();
                okNotify(`Regex ${b64decode(request.regex)} has been added`, `Successfully added  ${request.is_case_sensitive?"case sensitive":"case insensitive"} regex to ${request.service_id} service`)
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


    return <Modal size="lg" title="Add a new regex filter" opened={opened} onClose={close} closeOnClickOutside={false} centered>
        <form onSubmit={form.onSubmit(submitRequest)}>
            <TextInput
                label="Regex"
                placeholder="[A-Z0-9]{31}="
                size="md"
                data-autofocus
                {...form.getInputProps('regex')}
            />
            
            <Space h="xl" />
            <Group justify="space-between" align="center">
                <Box>
                    <Text fw={500} size="sm">Packet Direction</Text>
                    <Text size="xs" c="dimmed">Choose which traffic this regex should filter</Text>
                </Box>
                <SegmentedControl
                    value={form.values.mode}
                    onChange={(val) => form.setFieldValue('mode', val)}
                    data={[
                        { label: 'Client → Server', value: 'C' },
                        { label: 'Bidirectional', value: 'B' },
                        { label: 'Server → Client', value: 'S' },
                    ]}
                    color="cyan"
                    size="sm"
                />
            </Group>

            <Space h="xl" />
            <Card withBorder radius="md" p="md" bg="transparent">
                <Group justify="space-between" mb="xs">
                    <Text fw={500} size="sm">Case Insensitive</Text>
                    <Switch
                        color="cyan"
                        {...form.getInputProps('is_case_insensitive', { type: 'checkbox' })}
                    />
                </Group>
                <Text size="xs" c="dimmed" mb="md">
                    Ignore letter casing when matching this regex against packets.
                </Text>

                <Group justify="space-between" mb="xs">
                    <Text fw={500} size="sm">Start Deactivated</Text>
                    <Switch
                        color="orange"
                        {...form.getInputProps('deactive', { type: 'checkbox' })}
                    />
                </Group>
                <Text size="xs" c="dimmed">
                    Create the filter but keep it disabled initially.
                </Text>
            </Card>

            <Group justify="flex-end" mt="xl">
                <Button variant="default" onClick={close}>Cancel</Button>
                <Button loading={submitLoading} type="submit" color="cyan">Add Filter</Button>
            </Group>

            {error?<>
            <Space h="md" />
            <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                Error: {error}
            </Notification></>:null}
            
        </form>
    </Modal>
}

export default AddNewRegex;
