import React, { useEffect, useState } from 'react';
import { ActionIcon, Badge, Modal } from '@mantine/core';
import style from "./Header.module.scss";
import { generalstats } from '../../js/utils';
import { GeneralStats, notification_time, update_freq } from '../../js/models';
import { BsPlusLg } from "react-icons/bs"
import { AiFillHome } from "react-icons/ai"
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import AddNewRegex from '../AddNewRegex';
import AddNewService from '../AddNewService';
import { showNotification } from '@mantine/notifications';
import { ImCross } from 'react-icons/im';

function Header() {
  
  const [generalStats, setGeneralStats] = useState<GeneralStats>({closed:0, regex:0, services:0});
  const location = useLocation()

  const navigator = useNavigate()

    const updateInfo = () => {
      generalstats().then(res => {
        setGeneralStats(res)
      }).catch(
        err =>{
            showNotification({
                autoClose: notification_time,
                title: "General Info Auto-Update failed!",
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


  const {srv_id} = useParams()
  const [open, setOpen] = useState(false);
  const closeModal = () => {setOpen(false);}

  return <div id="header-page" className={style.header}>
        <div className={style.logo} >LOGO</div>
        <div className="flex-spacer" />
        <Badge color="green" size="lg" variant="filled">Services: {generalStats.services}</Badge>
        <Badge style={{marginLeft:"10px"}} size="lg" color="yellow" variant="filled">Filtered Connections: {generalStats.closed}</Badge>
        <Badge style={{marginLeft:"10px"}} size="lg" color="violet" variant="filled">Regexes: {generalStats.regex}</Badge>
        <div style={{marginLeft:"20px"}}></div>
        { location.pathname !== "/"?
            <ActionIcon color="teal" style={{marginRight:"10px"}}
              size="xl" radius="md" variant="filled"
              onClick={()=>navigator("/")}>
              <AiFillHome size="25px" />
            </ActionIcon>
        :null}
        <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"><BsPlusLg size="20px" /></ActionIcon>
        {srv_id?
          <Modal size="xl" title="Add a new regex filter" opened={open} onClose={closeModal} closeOnClickOutside={false} centered>
            <AddNewRegex closePopup={closeModal} service={srv_id} />
          </Modal>:
          <Modal size="xl" title="Add a new service" opened={open} onClose={closeModal} closeOnClickOutside={false} centered>
            <AddNewService closePopup={closeModal} />
          </Modal>
        }
            
        
        <div style={{marginLeft:"40px"}}></div>
  </div>
}

export default Header;
