import { Grid, Space, Title } from '@mantine/core';
import { showNotification } from '@mantine/notifications';
import React, { useEffect, useState } from 'react';
import { ImCross } from 'react-icons/im';
import { useParams } from 'react-router-dom';
import RegexView from '../components/RegexView';
import ServiceRow from '../components/ServiceRow';
import { notification_time, RegexFilter, Service, update_freq } from '../js/models';
import { serviceinfo, serviceregexlist } from '../js/utils';

function ServiceDetails() {
    const {srv_id} = useParams()

    const [serviceInfo, setServiceInfo] = useState<Service>({
        id:srv_id?srv_id:"",
        internal_port:0,
        n_packets:0,
        n_regex:0,
        name:srv_id?srv_id:"",
        public_port:0,
        status:"🤔"
    })

    const [regexesList, setRegexesList] = useState<RegexFilter[]>([
        {
            id:3546,
            is_blacklist:true,
            mode:"B",
            regex:"d2VkcmZoaXdlZGZoYnVp",
            service_id:"ctfe"
        },
        {
            id:3546,
            is_blacklist:true,
            mode:"B",
            regex:"d2VkcmZoaXdlZGZoYnVp",
            service_id:"ctfe"
        },
        {
            id:3546,
            is_blacklist:true,
            mode:"B",
            regex:"d2VkcmZoaXdlZGZoYnVp",
            service_id:"ctfe"
        }
    ])

    const updateInfo = async () => {
        if (!srv_id) return
        let error = false;
        await serviceinfo(srv_id).then(res => {
            setServiceInfo(res)
        }).catch(
          err =>{
              showNotification({
                  autoClose: notification_time,
                  title: `Updater for ${srv_id} service failed [General Info]!`,
                  message: "[ "+err+" ]",
                  color: 'red',
                  icon: <ImCross />,
              });
              error = true;
        })
        if (error) return
        await serviceregexlist(srv_id).then(res => {
            setRegexesList(res)
        }).catch(
          err =>{
              showNotification({
                  autoClose: notification_time,
                  title: `Updater for ${srv_id} service failed [Regex list]!`,
                  message: "[ "+err+" ]",
                  color: 'red',
                  icon: <ImCross />,
              });
              error = true;
        })
    }
  
    useEffect(()=>{
        updateInfo()
        const updater = setInterval(updateInfo, update_freq)
        return () => { clearInterval(updater) }
    }, []);
    
    return <>
        <ServiceRow service={serviceInfo}></ServiceRow>
        {regexesList.length === 0? 
            <><Space h="xl" /> <Title className='center-flex' order={1}>No regex found for this service! Add one clicking the add button above</Title></>:
            <Grid>
                {regexesList.map( (regexInfo) => <Grid.Col key={regexInfo.id} span={6}><RegexView regexInfo={regexInfo}/></Grid.Col>)}
            </Grid>
        }
    </>
}

export default ServiceDetails;
