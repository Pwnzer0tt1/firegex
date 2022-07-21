import React, { useState } from 'react';
import { Container, Space } from '@mantine/core';
import { AppShell } from '@mantine/core';
import NavBar from './NavBar';
import FooterPage from './Footer';
import HeaderPage from './Header';




function MainLayout({ children }:{ children:any }) {
  const [opened, setOpened] = useState(false);
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
