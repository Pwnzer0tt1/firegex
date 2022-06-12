import { Space, Title } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import ServiceRow from '../components/ServiceRow';
import { Service, update_freq } from '../js/models';
import { errorNotify, servicelist } from '../js/utils';


function HomePage() {

    const [services, setServices] = useState<Service[]>([]);
    const navigator = useNavigate()
    
    const updateInfo = () => {
        servicelist().then(res => {
            setServices(res)
        }).catch(
            err => errorNotify("Home Page Auto-Update failed!", err.toString())
        )
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
