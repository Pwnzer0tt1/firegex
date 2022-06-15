import React from 'react';
import { Container, Space } from '@mantine/core';
import Footer from './Footer';
import Header from './Header';

function MainLayout({ children }:{ children:any }) {
  return <>
      
            <Header/>
            <Space h="xl" />
            <Container size="xl" style={{minHeight:"57.5vh"}}>
                {children}
            </Container>
            <Space h="xl" />
            <Footer />

  </>
}

export default MainLayout;
