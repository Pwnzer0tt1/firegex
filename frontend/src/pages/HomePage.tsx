import React, { useEffect, useState } from 'react';
import { Navigate, useNavigate, useRoutes } from 'react-router-dom';
import ServiceRow from '../components/ServiceRow';
import { Service, update_freq } from '../js/models';
import { servicelist } from '../js/utils';


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
        setTimeout(updateInfo, update_freq)
    }).catch(
        err =>{
        setTimeout(updateInfo, update_freq)}
    )
    }

    useEffect(updateInfo,[]);

    return <div id="service-list" className="center-flex-row">
        {services.map( srv => <ServiceRow service={srv} key={srv.id} onClick={()=>{
            navigator("/"+srv.id)
        }} />)}
    </div>
}

export default HomePage;
