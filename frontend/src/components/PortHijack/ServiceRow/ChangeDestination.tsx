import { Button, Group, Space, Notification, Modal } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { okNotify, regex_ipv4_no_cidr, regex_ipv6_no_cidr } from '../../../js/utils';
import { ImCross } from "react-icons/im"
import { porthijack, Service } from '../utils';
import PortAndInterface from '../../PortAndInterface';

function ChangeDestination({ opened, onClose, service }:{ opened:boolean, onClose:()=>void, service:Service }) { 

    const form = useForm({
        initialValues: { 
            ip_dst:service.ip_dst,
            proxy_port:service.proxy_port
        },
        validate:{
            proxy_port: (value) => (value>0 && value<65536) ? null : "Invalid proxy port",
            ip_dst: (value) => (value.match(regex_ipv6_no_cidr) || value.match(regex_ipv4_no_cidr))? null : "Invalid destination IP address",
        }
    })

    const close = () =>{
        onClose()
        form.reset()
        setError(null)
    }

    useEffect(() => form.setValues({ip_dst:service.ip_dst, proxy_port: service.proxy_port}),[opened])

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)

    const submitRequest = ({ ip_dst, proxy_port }:{ ip_dst:string, proxy_port:number }) => {
        setSubmitLoading(true)
        porthijack.changedestination(service.service_id, ip_dst, proxy_port).then( res => {
            if (res.status === "ok"){
                setSubmitLoading(false)
                close();
                okNotify(`Service ${service.name} has changed destination in ${ ip_dst }:${ proxy_port }`, `Successfully changed destination of service on port ${service.public_port}`)
            }else{
                setSubmitLoading(false)
                setError(res.status)
            }
        }).catch( err => {
            setSubmitLoading(false)
            setError("Request Failed! [ "+err+" ]")
        })
        
    }    


  return <Modal size="xl" title={`Change destination of '${service.name}' [${service.ip_src}]:${service.public_port}`} opened={opened} onClose={close} closeOnClickOutside={false} centered>
    <form onSubmit={form.onSubmit(submitRequest)}>
            
            <PortAndInterface form={form} int_name="ip_dst" port_name="proxy_port" />
            <Group align="right" mt="md">
                <Button loading={submitLoading} type="submit">Change</Button>
            </Group>
            <Space h="md" />
            
            {error?<>
            <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                Error: {error}
            </Notification><Space h="md" /></>:null}
            
        </form>
    </Modal>

}

export default ChangeDestination;
