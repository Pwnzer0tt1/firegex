import { Button, Group, Space, TextInput, Notification, Modal, Switch, SegmentedControl, Box, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { okNotify, regex_ipv4, regex_ipv6 } from '../../js/utils';
import { ImCross } from "react-icons/im"
import { nfregex, Service } from './utils';
import PortAndInterface from '../PortAndInterface';
import { IoMdInformationCircleOutline } from "react-icons/io";
import { ServiceAddForm as ServiceAddFormOriginal } from './utils';

type ServiceAddForm = ServiceAddFormOriginal & {autostart: boolean}

function AddEditService({ opened, onClose, edit }:{ opened:boolean, onClose:()=>void, edit?:Service }) {

    const initialValues = {
        name: "",
        port:edit?.port??8080,
        ip_int:edit?.ip_int??"",
        proto:edit?.proto??"tcp",
        fail_open: edit?.fail_open??false,
        autostart: true
    }
    
    const form = useForm({
        initialValues: initialValues,
        validate:{
            name: (value) => edit? null : value !== "" ? null : "Service name is required",
            port: (value) => (value>0 && value<65536) ? null : "Invalid port",
            proto: (value) => ["tcp","udp"].includes(value) ? null : "Invalid protocol",
            ip_int: (value) => (value.match(regex_ipv6) || value.match(regex_ipv4)) ? null : "Invalid IP address",
        }
    })

    useEffect(() => {
        if (opened){
            form.setInitialValues(initialValues)
            form.reset()
        }
    }, [opened])

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)
 
    const submitRequest = ({ name, port, autostart, proto, ip_int, fail_open }:ServiceAddForm) =>{
        setSubmitLoading(true)
        if (edit){
            nfregex.settings(edit.service_id, { port, proto, ip_int, fail_open }).then( res => {
                if (!res){
                    setSubmitLoading(false)
                    close();
                    okNotify(`Service ${name} settings updated`, `Successfully updated settings for service ${name}`)
                }
            }).catch( err => {
                setSubmitLoading(false)
                setError("Request Failed! [ "+err+" ]")
            })
        }else{
            nfregex.servicesadd({ name, port, proto, ip_int, fail_open }).then( res => {
                if (res.status === "ok" && res.service_id){
                    setSubmitLoading(false)
                    close();
                    if (autostart) nfregex.servicestart(res.service_id)
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
    }


  return <Modal size="xl" title={edit?`Editing ${edit.name} service`:"Add a new service"} opened={opened} onClose={close} closeOnClickOutside={false} centered>
    <form onSubmit={form.onSubmit(submitRequest)}>
            {!edit?<TextInput
                label="Service name"
                placeholder="Challenge 01"
                {...form.getInputProps('name')}
            />:null}
            <Space h="md" />
            <PortAndInterface form={form} int_name="ip_int" port_name="port" label={"Public IP Interface and port (ipv4/ipv6 + CIDR allowed)"} />            
            <Space h="md" />

            <Box className='center-flex'>
                <Box>
                    {!edit?<Switch
                        label="Auto-Start Service"
                        {...form.getInputProps('autostart', { type: 'checkbox' })}
                    />:null}
                    <Space h="sm" />
                    <Switch
                        label={<Box className='center-flex'>
                            Enable fail-open nfqueue
                            <Space w="xs" />
                            <Tooltip label={<>
                                Firegex use internally nfqueue to handle packets<br />enabling this option will allow packets to pass through the firewall <br /> in case the filtering is too slow or too many traffic is coming<br />
                            </>}>
                                <IoMdInformationCircleOutline size={15} />
                            </Tooltip>
                        </Box>}
                        {...form.getInputProps('fail_open', { type: 'checkbox' })}
                    />
                </Box>
                <Box className="flex-spacer"></Box>
                <SegmentedControl
                    data={[
                        { label: 'TCP', value: 'tcp' },
                        { label: 'UDP', value: 'udp' },
                    ]}
                    {...form.getInputProps('proto')}
                />
            </Box>      

            <Group justify='flex-end' mt="md" mb="sm">
                <Button loading={submitLoading} type="submit" disabled={edit?!form.isDirty():false}>{edit?"Edit Service":"Add Service"}</Button>
            </Group>

            {error?<>
                <Space h="md" />
                <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                    Error: {error}
                </Notification><Space h="md" />
            </>:null}
            
        </form>
    </Modal>

}

export default AddEditService;
