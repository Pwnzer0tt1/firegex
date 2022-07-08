import React, { useState } from 'react';
import { ActionIcon, Badge, Button, Divider, Group, Image, Menu, Modal, Notification, Space, Switch, Tooltip, FloatingTooltip, MediaQuery, PasswordInput } from '@mantine/core';
import style from "./index.module.scss";
import { changepassword, errorNotify, eventUpdateName, generalstats, logout, okNotify } from '../../js/utils';
import { ChangePassword, GeneralStats } from '../../js/models';
import { BsPlusLg } from "react-icons/bs"
import { AiFillHome } from "react-icons/ai"
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import AddNewRegex from '../AddNewRegex';
import AddNewService from '../AddNewService';
import { FaLock } from 'react-icons/fa';
import { ImCross, ImExit } from 'react-icons/im';
import { useForm, useWindowEvent } from '@mantine/hooks';


function Header() {
  
  const [generalStats, setGeneralStats] = useState<GeneralStats>({closed:0, regexes:0, services:0});
  const location = useLocation()

  const navigator = useNavigate()

  const updateInfo = () => {
    generalstats().then(res => {
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


  const form = useForm({
    initialValues: {
        password:"",
        expire:true
    },
    validationRules:{
      password: (value) => value !== ""
    }
  })

  const [loadingBtn, setLoadingBtn] = useState(false)
  const [error, setError] = useState<null|string>(null)
  const [changePasswordModal, setChangePasswordModal] = useState(false);
  const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
  const [tooltipHomeOpened, setTooltipHomeOpened] = useState(false);

  const submitRequest = async (values:ChangePassword) => {
    setLoadingBtn(true)
    await changepassword(values).then(res => {
      if(!res){
        okNotify("Password change done!","The password of the firewall has been changed!")
        setChangePasswordModal(false)
        form.reset()
      }else{
        setError(res)
      }
    }).catch( err => setError(err.toString()))
    setLoadingBtn(false)
  }

  const {srv} = useParams()
  const service_port = srv?parseInt(srv):null

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
          <Divider />
          <Menu.Item color="red" icon={<FaLock size={14} />} onClick={() => setChangePasswordModal(true)}>Change Password</Menu.Item>
        </Menu>
        <div style={{marginLeft:"20px"}}></div>
        { location.pathname !== "/"?
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
        :null}
        { service_port?
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
        
        {service_port?
            <AddNewRegex opened={open} onClose={closeModal} service={service_port} />:
            <AddNewService opened={open} onClose={closeModal} />
        }
        <Modal size="xl" title="Change Firewall Password" opened={changePasswordModal} onClose={()=>setChangePasswordModal(false)} closeOnClickOutside={false} centered>

          <form onSubmit={form.onSubmit(submitRequest)}>
              <Space h="md" />
              <PasswordInput
                  label="New Password"
                  placeholder="$3cr3t"
                  {...form.getInputProps('password')}
              />
              <Space h="md" />
              <Switch
                  label="Expire the login status to all connections"
                  {...form.getInputProps('expire', { type: 'checkbox' })}
              />
              <Space h="md" />
              <Group position="right" mt="md">
                <Button loading={loadingBtn} type="submit">Change Password</Button>
              </Group>
            </form>
            <Space h="xl" />
            {error?<>
              <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                  Error: {error}
              </Notification><Space h="md" /></>:null}
        </Modal>
        <div style={{marginLeft:"40px"}}></div>
  </div>
}

export default Header;
