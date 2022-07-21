import React from 'react';
import { Container, Space, Tabs } from '@mantine/core';
import Footer from './Footer';
import Header from './Header';

function MainLayout({ children }:{ children:any }) {
  return <>  
      <Header/>
      <Tabs grow variant="pills">
        <Tabs.Tab label="Regex Prox"></Tabs.Tab>
        <Tabs.Tab label="Port Hijacking"></Tabs.Tab>
        <Tabs.Tab label="Netfilter regex"></Tabs.Tab>
      </Tabs>
      <Space h="xl" />
      <Container size="md" style={{minHeight:"57.5vh"}}>
          {children}
      </Container>
      <Space h="xl" />
      <Footer />
  </>
}

export default MainLayout;
