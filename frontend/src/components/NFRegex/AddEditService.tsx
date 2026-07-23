import { Button, Group, Space, TextInput, Notification, Modal, Switch, SegmentedControl, Box, Tooltip, ActionIcon, Title, Tabs, Text, UnstyledButton, Badge, Card, Divider } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { okNotify, regex_ipv4, regex_ipv6, postapi } from '../../js/utils';
import TLSServiceFields from '../TLSServiceFields';
import { ImCross } from "react-icons/im"
import { nfregex, Service } from './utils';
import PortAndInterface from '../PortAndInterface';
import { IoMdInformationCircleOutline } from "react-icons/io";
import { TbNetwork, TbShieldLock, TbSettings, TbTarget } from "react-icons/tb";
import { ServiceAddForm as ServiceAddFormOriginal } from './utils';

type ServiceAddForm = ServiceAddFormOriginal & {
    autostart: boolean,
    tls_enabled: boolean,
    tls_cert: string,
    tls_key: string
}

function AddEditService({ opened, onClose, edit }:{ opened:boolean, onClose:()=>void, edit?:Service }) {

    const initialValues = {
        name: "",
        port:edit?.port??8080,
        ip_int:edit?.ip_int??"",
        proto:edit?.proto??"tcp",
        fail_open: edit?.fail_open??false,
        autostart: true,
        tls_enabled: edit?.target_type === 'tls',
        tls_stream_id: edit?.tls_stream_id ?? undefined,
        tls_cert: "",
        tls_key: ""
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
 
    const submitRequest = async (values: ServiceAddForm) => {
        setSubmitLoading(true)
        let streamId = values.tls_stream_id;

        if (edit){
            if (values.tls_enabled && values.tls_cert && values.tls_key) {
                try {
                    const res = await postapi('tls/streams', {
                        name: values.name,
                        ip_int: values.ip_int,
                        port: values.port,
                        cert: values.tls_cert,
                        key: values.tls_key
                    });
                    if (res.status !== "ok") {
                        setSubmitLoading(false);
                        setError("Failed to create TLS Stream!");
                        return;
                    }
                    streamId = res.stream_id;
                } catch (err: any) {
                    setSubmitLoading(false);
                    setError("Failed to create TLS Stream: " + err);
                    return;
                }
            }

            nfregex.settings(edit.service_id, { port: values.port, proto: values.proto, ip_int: values.ip_int, fail_open: values.fail_open, target_type: values.tls_enabled ? "tls" : "flow", tls_stream_id: streamId }).then( res => {
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
            if (values.tls_enabled && values.tls_cert && values.tls_key) {
                try {
                    const res = await postapi('tls/streams', {
                        name: values.name,
                        ip_int: values.ip_int,
                        port: values.port,
                        cert: values.tls_cert,
                        key: values.tls_key
                    });
                    if (res.status !== "ok") {
                        setSubmitLoading(false);
                        setError("Failed to create TLS Stream!");
                        return;
                    }
                    streamId = res.stream_id;
                } catch (err: any) {
                    setSubmitLoading(false);
                    setError("Failed to create TLS Stream: " + err);
                    return;
                }
            }

            const payload = {
                name: values.name,
                port: values.port,
                proto: values.proto,
                ip_int: values.ip_int,
                fail_open: values.fail_open,
                target_type: values.tls_enabled ? "tls" : "flow",
                tls_stream_id: streamId,
            }
            nfregex.servicesadd(payload).then( res => {
                if (res.status === "ok" && res.service_id){
                    setSubmitLoading(false)
                    close();
                    if (values.autostart) nfregex.servicestart(res.service_id)
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


  return <Modal size="xl" title={edit?`Editing ${edit.name} service`:"Add a new service"} opened={opened} onClose={close} closeOnClickOutside={false} centered styles={{ body: { maxHeight: 'calc(100vh - 150px)', overflowY: 'auto' } }}>
        <form onSubmit={form.onSubmit(submitRequest)}>
            <Tabs defaultValue="general" color="cyan" variant="outline" radius="md">
                <Tabs.List>
                    <Tabs.Tab value="general" leftSection={<TbSettings size={16} />}>
                        General
                    </Tabs.Tab>
                    <Tabs.Tab value="advanced" leftSection={<TbShieldLock size={16} />}>
                        Advanced
                    </Tabs.Tab>
                </Tabs.List>

                <Tabs.Panel value="general" pt="xl" pb="md">
                    {!edit ? (
                        <TextInput
                            label="Service name"
                            placeholder="Challenge 01"
                            size="md"
                            {...form.getInputProps('name')}
                        />
                    ) : null}
                    <Space h="md" />
                    <Title order={6} mb="xs">Protocol</Title>
                    <SegmentedControl
                        fullWidth
                        size="md"
                        color="cyan"
                        data={[
                            { label: 'TCP', value: 'tcp' },
                            { label: 'UDP', value: 'udp' },
                        ]}
                        {...form.getInputProps('proto')}
                        disabled={edit !== undefined}
                    />
                    <Space h="xl" />
                    <Divider mb="xl" label="Target Setup" labelPosition="center" />
                    
                    <Title order={6} mb="xs">Target Type</Title>
                    <Group grow mb="xl">
                        <UnstyledButton
                            onClick={() => form.setFieldValue('tls_enabled', false)}
                            style={{
                                padding: '1rem',
                                borderRadius: '12px',
                                border: form.values.tls_enabled ? '1px solid var(--fourth_color)' : '2px solid var(--accent-color)',
                                backgroundColor: form.values.tls_enabled ? 'transparent' : 'rgba(0, 229, 255, 0.05)',
                                transition: 'all 0.2s ease'
                            }}
                        >
                            <Group wrap="nowrap">
                                <TbNetwork size={32} color={!form.values.tls_enabled ? "var(--accent-color)" : "gray"} />
                                <div>
                                    <Text fw={600}>Direct Flow</Text>
                                    <Text size="xs" c="dimmed">Forward traffic directly without decryption</Text>
                                </div>
                            </Group>
                        </UnstyledButton>
                        <UnstyledButton
                            onClick={() => { if (form.values.proto === 'tcp') form.setFieldValue('tls_enabled', true) }}
                            style={{
                                padding: '1rem',
                                borderRadius: '12px',
                                border: !form.values.tls_enabled ? '1px solid var(--fourth_color)' : '2px solid var(--accent-color)',
                                backgroundColor: !form.values.tls_enabled ? 'transparent' : 'rgba(0, 229, 255, 0.05)',
                                opacity: form.values.proto !== 'tcp' && !form.values.tls_enabled ? 0.5 : 1,
                                transition: 'all 0.2s ease',
                                cursor: form.values.proto !== 'tcp' ? 'not-allowed' : 'pointer'
                            }}
                        >
                            <Group wrap="nowrap">
                                <TbShieldLock size={32} color={form.values.tls_enabled ? "var(--accent-color)" : "gray"} />
                                <div>
                                    <Text fw={600}>TLS Decrypted</Text>
                                    <Text size="xs" c="dimmed">Decrypt TLS traffic for deep inspection</Text>
                                </div>
                            </Group>
                        </UnstyledButton>
                    </Group>

                    {!form.values.tls_enabled ? (
                        <PortAndInterface form={form} int_name="ip_int" port_name="port" label={"Public IP Interface and port (ipv4/ipv6 + CIDR allowed)"} />
                    ) : (
                        <TLSServiceFields form={form} disabled={form.values.proto !== 'tcp'} />
                    )}
                </Tabs.Panel>

                <Tabs.Panel value="advanced" pt="xl" pb="md">
                    <Card withBorder padding="lg" radius="md" bg="transparent">
                        {!edit ? (
                            <Box mb="xl">
                                <Text fw={500} mb="xs">Auto-Start Service</Text>
                                <Text size="sm" c="dimmed" mb="md">Automatically start this service as soon as it is created.</Text>
                                <Switch
                                    size="md"
                                    color="cyan"
                                    {...form.getInputProps('autostart', { type: 'checkbox' })}
                                />
                            </Box>
                        ) : null}
                        
                        <Box>
                            <Text fw={500} mb="xs">Enable fail-open nfqueue</Text>
                            <Text size="sm" c="dimmed" mb="md">
                                Firegex uses nfqueue internally to handle packets. Enabling this option will allow packets to pass through the firewall automatically in case the regex engine is overloaded or crashes.
                            </Text>
                            <Switch
                                size="md"
                                color="cyan"
                                {...form.getInputProps('fail_open', { type: 'checkbox' })}
                            />
                        </Box>
                    </Card>
                </Tabs.Panel>
            </Tabs>

            {error ? <>
                <Space h="md" />
                <Notification icon={<ImCross size={14} />} color="red" onClose={() => { setError(null) }}>
                    Error: {error}
                </Notification>
            </> : null}

            <Group justify='flex-end' mt="xl" pt="md" style={{ borderTop: '1px solid var(--fourth_color)' }}>
                <Button variant="default" onClick={close}>Cancel</Button>
                <Button loading={submitLoading} type="submit" color="cyan" disabled={edit ? !form.isDirty() : false}>
                    {edit ? "Save Changes" : "Create Service"}
                </Button>
            </Group>
            
        </form>
    </Modal>

}

export default AddEditService;
