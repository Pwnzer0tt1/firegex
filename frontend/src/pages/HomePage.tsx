import { ActionIcon, LoadingOverlay, Modal, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import { useNavigate } from 'react-router-dom';
import ServiceRow from '../components/ServiceRow';
import { Service, update_freq } from '../js/models';
import { errorNotify, servicelist } from '../js/utils';
import AddNewService from '../components/AddNewService';


function HomePage() {

    const [services, setServices] = useState<Service[]>([]);
    const [loader, setLoader] = useState(true);
    const navigator = useNavigate()
    const [open, setOpen] = useState(false);
    const closeModal = () => {setOpen(false);}
    
    const updateInfo = async () => {
        await servicelist().then(res => {
            setServices(res)    
        }).catch(err => {
            errorNotify("Home Page Auto-Update failed!", err.toString())
        })
        setLoader(false)
    }

    useEffect(()=>{
        updateInfo()
        const updater = setInterval(updateInfo, update_freq)
        return () => { clearInterval(updater) }
    }, []);


    
    return <div id="service-list" className="center-flex-row">
        <LoadingOverlay visible={loader} />
        {services.length > 0?services.map( srv => <ServiceRow service={srv} key={srv.id} onClick={()=>{
            navigator("/"+srv.id)
        }} />):<><Space h="xl"/> <Title className='center-flex' align='center' order={3}>No services found! Add one clicking the "+" button above</Title>
            <Space h="xl" /> <Space h="xl" /> 
            <div className='center-flex'>
                <Tooltip label="Add a new service" transition="pop" transitionDuration={200} openDelay={500} zIndex={0} transitionTimingFunction="ease" color="blue">
                    <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"><BsPlusLg size="20px" /></ActionIcon>
                </Tooltip>
            </div>
        </>}
        <AddNewService opened={open} onClose={closeModal} />
    </div>
}

export default HomePage;
