import { Container, MantineProvider, Space } from '@mantine/core';
import { NotificationsProvider } from '@mantine/notifications';
import React from 'react';
import Footer from './Footer';
import Header from './Header';

function MainLayout({ children }:{ children:any }) {
  return <>
      <MantineProvider theme={{ colorScheme: 'dark' }} withGlobalStyles withNormalizeCSS>
        <NotificationsProvider>
            <Header />
            <Space h="xl" />
            <Container size="xl" style={{minHeight:"57.5vh"}}>
                {children}
            </Container>
            <Space h="xl" />
            <Footer />
        </NotificationsProvider>
      </MantineProvider>
  </>
}

export default MainLayout;
