import React, { useState } from 'react';
import { ActionIcon, Divider, Image, Menu, Tooltip, Burger, Space, AppShell, Box, Title } from '@mantine/core';
import { errorNotify, getMainPath, isLargeScreen, logout } from '../../js/utils';
import { AiFillHome } from "react-icons/ai"
import { useNavigate } from 'react-router-dom';
import { FaLock } from 'react-icons/fa';
import { MdOutlineSettingsBackupRestore } from 'react-icons/md';
import { ImExit } from 'react-icons/im';
import ResetPasswordModal from './ResetPasswordModal';
import ResetModal from './ResetModal';
import { MenuDropDownWithButton } from '../MainLayout';
import { useNavbarStore } from '../../js/store';


function HeaderPage(props: any) {
  
  const navigator = useNavigate()
  const { navOpened, toggleNav } = useNavbarStore()
  
  const logout_action = () => {
    logout().then(r => {
        window.location.reload()
    }).catch(r => {
      errorNotify("Logout failed!",`Error: ${r}`)
    })
  } 

  const go_to_home = () => {
    navigator(`/${getMainPath()}`)
  }

  const [changePasswordModal, setChangePasswordModal] = useState(false);
  const [resetFiregexModal, setResetFiregexModal] = useState(false);
  return <AppShell.Header className="firegex__header__header" {...props}>
        <Burger
          hiddenFrom='md'
          ml="lg"
          opened={navOpened}
          className="firegex__header__navbtn"
          onClick={toggleNav}
          size="sm"
        />
        <Box style={{ display: "flex", justifyContent: "center", alignItems: "center"}} ml={5}>
          <Box className="firegex__header__divlogo">
            <Tooltip zIndex={0} label="Home" openDelay={1000} color="dark" position="right" >
              <Image src="/header-logo.png" alt="Firegex logo" w={50} onClick={()=>navigator("/")}/>
            </Tooltip>
          </Box>
          <Box display="flex" style={{ flexDirection: "column" }} visibleFrom='xs'>
            <Title order={2} >[Fi]*regex</Title>
            <p style={{margin: 0, fontSize: "70%"}}>By <a href="https://pwnzer0tt1.it">Pwnzer0tt1</a></p>
          </Box>
        </Box>
        
        <Box className="flex-spacer" />        
      
        <MenuDropDownWithButton>
          <Menu.Label>Firewall Access</Menu.Label>
          <Menu.Item leftSection={<FaLock size={14} />} onClick={() => setChangePasswordModal(true)}>Change Password</Menu.Item>
          <Divider />
          <Menu.Label>Actions</Menu.Label>
          <Menu.Item color="red" leftSection={<MdOutlineSettingsBackupRestore size={18} />} onClick={() => setResetFiregexModal(true)}>Reset Firegex</Menu.Item>
        </MenuDropDownWithButton>
        <Space w="md" />
        <Tooltip label="Home" position='bottom' color="teal">
          <ActionIcon color="teal" style={{marginRight:"10px"}}
            size="xl" radius="md" variant="filled"
            onClick={go_to_home}>
            <AiFillHome size="25px" />
          </ActionIcon>
        </Tooltip>
        <Tooltip label="Logout" position='bottom' color="blue">
          <ActionIcon color="blue" onClick={logout_action} size="xl" radius="md" variant="filled">
            <ImExit size={23} style={{marginTop:"3px", marginLeft:"2px"}}/></ActionIcon>
        </Tooltip>        
        <ResetPasswordModal opened={changePasswordModal} onClose={() => setChangePasswordModal(false)} />
        <ResetModal opened={resetFiregexModal} onClose={() => setResetFiregexModal(false)} />
        <Space w="xl" />
  </AppShell.Header>
}

export default HeaderPage;
