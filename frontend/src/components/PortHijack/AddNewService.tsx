import { Button, Group, Space, TextInput, Notification, Modal, Switch, SegmentedControl } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useState } from 'react';
import { okNotify, regex_ipv6_no_cidr, regex_ipv4_no_cidr } from '../../js/utils';
import { ImCross } from "react-icons/im"
import { porthijack } from './utils';
import PortAndInterface from '../PortAndInterface';

type ServiceAddForm = {
    name:string,
    public_port:number,
    proxy_port:number,
    proto:string,
    ip_src:string,
    ip_dst:string,
    autostart: boolean,
}

function AddNewService({ opened, onClose }:{ opened:boolean, onClose:()=>void }) {

    const form = useForm({
        initialValues: {
            name:"",
            public_port:80,
            proxy_port:8080,
            proto:"tcp",
            ip_src:"",
            ip_dst:"127.0.0.1",
            autostart: false,
        },
        validate:{
            name: (value) => value !== ""? null : "Service name is required",
            public_port: (value) => (value>0 && value<65536) ? null : "Invalid public port",
            proxy_port: (value) => (value>0 && value<65536) ? null : "Invalid proxy port",
            proto: (value) => ["tcp","udp"].includes(value) ? null : "Invalid protocol",
            ip_src: (value) => (value.match(regex_ipv6_no_cidr) || value.match(regex_ipv4_no_cidr)) ? null : "Invalid source IP address",
            ip_dst: (value) => (value.match(regex_ipv6_no_cidr) || value.match(regex_ipv4_no_cidr)) ? null : "Invalid destination IP address",
        }
    })

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)
 
    const submitRequest = ({ name, proxy_port, public_port, autostart, proto, ip_src, ip_dst }:ServiceAddForm) =>{
        setSubmitLoading(true)
        porthijack.servicesadd({name, proxy_port, public_port, proto, ip_src, ip_dst }).then( res => {
            if (res.status === "ok" && res.service_id){
                setSubmitLoading(false)
                close();
                if (autostart) porthijack.servicestart(res.service_id)
                okNotify(`Service ${name} has been added`, `Successfully added service from port ${public_port} to ${proxy_port}`)
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
            <PortAndInterface form={form} int_name="ip_src" port_name="public_port" label="Public IP Address and port (ipv4/ipv6)" />
            <Space h="md" />
            <PortAndInterface form={form} int_name="ip_dst" port_name="proxy_port" label="Proxy/Internal IP Address and port (ipv4/ipv6)" />
            <Space h="md" />

            <div className='center-flex'>
                <Switch
                    label="Auto-Start Service"
                    {...form.getInputProps('autostart', { type: 'checkbox' })}
                />  
                <div className="flex-spacer"></div>
                <SegmentedControl
                    data={[
                        { label: 'TCP', value: 'tcp' },
                        { label: 'UDP', value: 'udp' },
                    ]}
                    {...form.getInputProps('proto')}
                />
            </div>      

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
