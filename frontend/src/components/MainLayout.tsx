import React, { useEffect, useState } from 'react';
import { Container, Space } from '@mantine/core';
import { AppShell } from '@mantine/core';
import NavBar from './NavBar';
import FooterPage from './Footer';
import HeaderPage from './Header';
import { getmainpath } from '../js/utils';
import { useLocation } from 'react-router-dom';




function MainLayout({ children }:{ children:any }) {
  const [opened, setOpened] = useState(false);
  const location = useLocation()
  useEffect(()=>{
    if (location.pathname !== "/"){
      sessionStorage.setItem('home_section', getmainpath())
    }
  },[location.pathname])


  return <>  
      
  <AppShell
    padding="md"
    fixed
    navbar={<NavBar closeNav={()=>setOpened(false)} opened={opened} />}
    header={<HeaderPage navOpen={opened} setNav={setOpened} />}
    footer={<FooterPage />}
  >
    <Container size="lg">
        {children}
    </Container>
  <Space h="lg" />

  </AppShell>

</>

}

export default MainLayout;
