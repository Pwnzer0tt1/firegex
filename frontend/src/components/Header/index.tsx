import React, { useEffect, useState } from 'react';
import { ActionIcon, Badge, Button, Divider, Group, Image, Menu, Modal, Notification, Space, Switch, TextInput } from '@mantine/core';
import style from "./Header.module.scss";
import { changepassword, errorNotify, generalstats, logout, okNotify } from '../../js/utils';
import { ChangePassword, GeneralStats, update_freq } from '../../js/models';
import { BsPlusLg } from "react-icons/bs"
import { AiFillHome } from "react-icons/ai"
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import AddNewRegex from '../AddNewRegex';
import AddNewService from '../AddNewService';
import { MdSettings } from 'react-icons/md';
import { FaLock } from 'react-icons/fa';
import { ImCross, ImExit } from 'react-icons/im';
import { useForm } from '@mantine/hooks';


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

  useEffect(()=>{
      updateInfo()
      const updater = setInterval(updateInfo, update_freq)
      return () => { clearInterval(updater) }
  }, []);
  
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



  const {srv_id} = useParams()

  

  const [open, setOpen] = useState(false);
  const closeModal = () => {setOpen(false);}

  return <div id="header-page" className={style.header}>
        <div style={{ width: 240, marginLeft: 'auto', marginRight: 'auto', padding:"40px" }}>
          <Image src="/header-logo.png" alt="Firegex logo" />
        </div>
        <div className="flex-spacer" />
        <Badge color="green" size="lg" variant="filled">Services: {generalStats.services}</Badge>
        <Badge style={{marginLeft:"10px"}} size="lg" color="yellow" variant="filled">Filtered Connections: {generalStats.closed}</Badge>
        <Badge style={{marginLeft:"10px"}} size="lg" color="violet" variant="filled">Regexes: {generalStats.regexes}</Badge>
        <div style={{marginLeft:"20px"}}></div>
        <Menu>
          <Menu.Label>Firewall Access</Menu.Label>
          <Menu.Item icon={<ImExit size={14} />} onClick={logout_action}>Logout</Menu.Item>
          <Divider />
          <Menu.Item color="red" icon={<FaLock size={14} />} onClick={() => setChangePasswordModal(true)}>Change Password</Menu.Item>
        </Menu>
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
        <Modal size="xl" title="Change Firewall Password" opened={changePasswordModal} onClose={()=>setChangePasswordModal(false)} closeOnClickOutside={false} centered>

          <form onSubmit={form.onSubmit(submitRequest)}>
              <Space h="md" />
              <TextInput
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
