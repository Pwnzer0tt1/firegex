import { Button, Group, Space, TextInput, Notification, Modal, Switch, SegmentedControl, Box, Tooltip, ActionIcon } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { okNotify, regex_ipv4, regex_ipv6 } from '../../js/utils';
import TLSServiceFields from '../TLSServiceFields';
import { ImCross } from "react-icons/im"
import { nfproxy, Service } from './utils';
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
        autostart: true,
        tls_enabled: false,
        tls_cert: "",
        tls_key: ""
    }
    
    const form = useForm({
        initialValues: initialValues,
        validate:{
            name: (value) => edit? null : value !== "" ? null : "Service name is required",
            port: (value) => (value>0 && value<65536) ? null : "Invalid port",
            proto: (value) => ["tcp","http"].includes(value) ? null : "Invalid protocol",
            ip_int: (value) => (value.match(regex_ipv6) || value.match(regex_ipv4)) ? null : "Invalid IP address",
            tls_cert: (value, values) => !edit && values.tls_enabled && !value ? "Certificate is required when TLS is enabled" : null,
            tls_key: (value, values) => !edit && values.tls_enabled && !value ? "Private key is required when TLS is enabled" : null,
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
 
    const submitRequest = (values: ServiceAddForm) => {
        setSubmitLoading(true)
        if (edit){
            nfproxy.settings(edit.service_id, { port: values.port, ip_int: values.ip_int, fail_open: values.fail_open }).then( res => {
                if (!res){
                    setSubmitLoading(false)
                    close();
                    okNotify(`Service ${values.name} settings updated`, `Successfully updated settings for service ${values.name}`)
                }
            }).catch( err => {
                setSubmitLoading(false)
                setError("Request Failed! [ "+err+" ]")
            })
        }else{
            const payload = {
                name: values.name,
                port: values.port,
                proto: values.proto,
                ip_int: values.ip_int,
                fail_open: values.fail_open,
                tls_enabled: values.tls_enabled,
                tls_cert: values.tls_enabled ? values.tls_cert : null,
                tls_key: values.tls_enabled ? values.tls_key : null,
            }
            nfproxy.servicesadd(payload).then( res => {
                if (res.status === "ok" && res.service_id){
                    setSubmitLoading(false)
                    close();
                    if (values.autostart) nfproxy.servicestart(res.service_id)
                    okNotify(`Service ${values.name} has been added`, `Successfully added service with port ${values.port}`)
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
                    <Group gap="xs" wrap="nowrap" align="center">
                        <Switch
                            label="Enable fail-open nfqueue"
                            {...form.getInputProps('fail_open', { type: 'checkbox' })}
                        />
                        <Tooltip 
                            label={<>
                                Firegex use internally nfqueue to handle packets<br />enabling this option will allow packets to pass through the firewall <br /> in case the filtering is too slow or too many traffic is coming<br />
                            </>}
                            zIndex={1000000}
                        >
                            <ActionIcon 
                                variant="subtle" 
                                color="gray" 
                                size="sm" 
                                onClick={(e: any) => { e.preventDefault(); e.stopPropagation(); }}
                            >
                                <IoMdInformationCircleOutline size={18} />
                            </ActionIcon>
                        </Tooltip>
                    </Group>
                </Box>
                <Box className="flex-spacer"></Box>
                {edit?null:<SegmentedControl
                    data={[
                        { label: 'TCP', value: 'tcp' },
                        { label: 'HTTP', value: 'http' },
                    ]}
                    {...form.getInputProps('proto')}
                />}
            </Box>      

            {!edit && <TLSServiceFields form={form} />}

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
