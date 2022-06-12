import { Space, Title } from '@mantine/core';
import { showNotification } from '@mantine/notifications';
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ServiceRow from '../components/ServiceRow';
import { notification_time, Service, update_freq } from '../js/models';
import { servicelist } from '../js/utils';
import { ImCross } from "react-icons/im"


function HomePage() {

    const [services, setServices] = useState<Service[]>([
        {
            id:"ctfe",
            internal_port:18080,
            n_packets: 30,
            n_regex: 40,
            name:"CTFe",
            public_port:80,
            status:"pause"
        },
        {
            id:"saas",
            internal_port:18080,
            n_packets: 30,
            n_regex: 40,
            name:"SaaS",
            public_port:5000,
            status:"active"
        }
    ]);
    const navigator = useNavigate()
    
    const updateInfo = () => {
        servicelist().then(res => {
            setServices(res)
        }).catch(
            err =>{
                showNotification({
                    autoClose: notification_time,
                    title: "Home Page Auto-Update failed!",
                    message: "[ "+err+" ]",
                    color: 'red',
                    icon: <ImCross />,
                });
        })
    }

    useEffect(()=>{
        updateInfo()
        const updater = setInterval(updateInfo, update_freq)
        return () => { clearInterval(updater) }
    }, []);
    
    return <div id="service-list" className="center-flex-row">
        {services.length > 0?services.map( srv => <ServiceRow service={srv} key={srv.id} onClick={()=>{
            navigator("/"+srv.id)
        }} />):<><Space h="xl" /> <Title className='center-flex' order={1}>No services found! Add one clicking the button above</Title></>}
    </div>
}

export default HomePage;
