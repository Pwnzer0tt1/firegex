import React, { useState } from 'react';
import { ActionIcon, Badge, Divider, Image, Menu, Space, Tooltip, FloatingTooltip, MediaQuery } from '@mantine/core';
import style from "./index.module.scss";
import { errorNotify, eventUpdateName, logout, nfregex } from '../../js/utils';
import { GeneralStats } from '../../js/models';
import { BsPlusLg } from "react-icons/bs"
import { AiFillHome } from "react-icons/ai"
import { useNavigate, useParams } from 'react-router-dom';
import AddNewRegex from '../NFRegex/AddNewRegex';
import AddNewService from '../NFRegex/AddNewService';
import { FaLock } from 'react-icons/fa';
import { MdOutlineSettingsBackupRestore } from 'react-icons/md';
import { ImExit } from 'react-icons/im';
import { useWindowEvent } from '@mantine/hooks';
import ResetPasswordModal from './ResetPasswordModal';
import ResetModal from './ResetModal';


function Header() {
  
  const [generalStats, setGeneralStats] = useState<GeneralStats>({closed:0, regexes:0, services:0});

  const navigator = useNavigate()

  const updateInfo = () => {
    nfregex.stats().then(res => {
      setGeneralStats(res)
    }).catch(
      err => errorNotify("General Info Auto-Update failed!", err.toString())
    )
  }

  useWindowEvent(eventUpdateName, updateInfo)
  
  const logout_action = () => {
    logout().then(r => {
        window.location.reload()
    }).catch(r => {
      errorNotify("Logout failed!",`Error: ${r}`)
    })
  } 

  const [changePasswordModal, setChangePasswordModal] = useState(false);
  const [resetFiregexModal, setResetFiregexModal] = useState(false);
  const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
  const [tooltipHomeOpened, setTooltipHomeOpened] = useState(false);

  const {srv} = useParams()

  const [open, setOpen] = useState(false);
  const closeModal = () => {setOpen(false);}

  return <div id="header-page" className={style.header}>
        <FloatingTooltip zIndex={0} label="Home" transition="pop" transitionDuration={200} openDelay={1000} transitionTimingFunction="ease" color="dark" position="right" >
          <div style={{ width: 240, marginLeft: 'auto', marginRight: 'auto', padding:"40px", cursor: 'pointer' }}>
            <Image src="/header-logo.png" alt="Firegex logo" onClick={()=>navigator("/")}/>
          </div>
        </FloatingTooltip>
        <div className="flex-spacer" />
        
        <MediaQuery largerThan="md" styles={{ display: 'none' }}>
          <div>
            <Badge color="green" size="lg" variant="filled">Services: {generalStats.services}</Badge>
              <Space h="xs" />
            <Badge size="lg" color="yellow" variant="filled">Filtered Connections: {generalStats.closed}</Badge>
              <Space h="xs" />
            <Badge size="lg" color="violet" variant="filled">Regexes: {generalStats.regexes}</Badge>
          </div>
        </MediaQuery>  

        <MediaQuery smallerThan="md" styles={{ display: 'none' }}><div>
          <div className="center-flex">
          <Badge color="green" size="lg" variant="filled">Services: {generalStats.services}</Badge>
            <Space w="xs" />
          <Badge size="lg" color="yellow" variant="filled">Filtered Connections: {generalStats.closed}</Badge>
            <Space w="xs" />
          <Badge size="lg" color="violet" variant="filled">Regexes: {generalStats.regexes}</Badge>
          </div>
        </div></MediaQuery>  

        
      
        <div style={{marginLeft:"20px"}}></div>
        <Menu>
          <Menu.Label>Firewall Access</Menu.Label>
          <Menu.Item icon={<ImExit size={14} />} onClick={logout_action}>Logout</Menu.Item>
          <Menu.Item color="red" icon={<FaLock size={14} />} onClick={() => setChangePasswordModal(true)}>Change Password</Menu.Item>
          <Divider />
          <Menu.Label>Actions</Menu.Label>
          <Menu.Item color="red" icon={<MdOutlineSettingsBackupRestore size={18} />} onClick={() => setResetFiregexModal(true)}>Reset Firegex</Menu.Item>
          
        </Menu>
        <div style={{marginLeft:"20px"}}></div>
        <Tooltip zIndex={0} label="Home" position='bottom' transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="teal" opened={tooltipHomeOpened} tooltipId="tooltip-home-id">
          <ActionIcon color="teal" style={{marginRight:"10px"}}
            size="xl" radius="md" variant="filled"
            onClick={()=>navigator("/")}
            aria-describedby="tooltip-home-id"
            onFocus={() => setTooltipHomeOpened(false)} onBlur={() => setTooltipHomeOpened(false)}
            onMouseEnter={() => setTooltipHomeOpened(true)} onMouseLeave={() => setTooltipHomeOpened(false)}>
            <AiFillHome size="25px" />
          </ActionIcon>
        </Tooltip>
        { srv?
          <Tooltip label="Add a new regex" zIndex={0} position='bottom' transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="blue" opened={tooltipAddOpened} tooltipId="tooltip-add-id">
            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
             aria-describedby="tooltip-add-id"
             onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
             onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
          </Tooltip>
        : <Tooltip label="Add a new service" zIndex={0} position='bottom' transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="blue" opened={tooltipAddOpened} tooltipId="tooltip-add-id">
            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
             aria-describedby="tooltip-add-id"
             onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
             onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
          </Tooltip>
      }
        
        {srv?
            <AddNewRegex opened={open} onClose={closeModal} service={srv} />:
            <AddNewService opened={open} onClose={closeModal} />
        }
        <ResetPasswordModal opened={changePasswordModal} onClose={() => setChangePasswordModal(false)} />
        <ResetModal opened={resetFiregexModal} onClose={() => setResetFiregexModal(false)} />
        
        <div style={{marginLeft:"40px"}}></div>
  </div>
}

export default Header;
