import { Container, MantineProvider } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { Service, update_freq } from '../js/models';
import { servicelist } from '../js/utils';
import Footer from './Footer';
import Header from './Header';

function MainLayout({ children }:{ children:any }) {

    const [services, setServices] = useState<Service[]>([]);
  
    const updateInfo = () => {
      servicelist().then(res => {
        setServices(res)
        setTimeout(updateInfo, update_freq)
      }).catch(
        err =>{
          setTimeout(updateInfo, update_freq)}
      )
    }
  
    useEffect(updateInfo,[]);

  return <>
    <MantineProvider theme={{ colorScheme: 'dark' }} withGlobalStyles withNormalizeCSS>
        <Header />
        <div style={{marginTop:"50px"}}/>
        <Container size="xl" style={{minHeight:"58vh"}}>
            {children}
        </Container>
        <div style={{marginTop:"50px"}}/>
        <Footer />
    </MantineProvider>
        
  </>
}

export default MainLayout;
