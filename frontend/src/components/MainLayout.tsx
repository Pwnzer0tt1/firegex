import { useEffect } from 'react';
import { ActionIcon, Container, Menu, Space, Tooltip } from '@mantine/core';
import { AppShell } from '@mantine/core';
import NavBar from './NavBar';
import HeaderPage from './Header';
import { getMainPath } from '../js/utils';
import { useLocation } from 'react-router';
import { useNavbarStore } from '../js/store';
import { HiMenu } from "react-icons/hi";


function MainLayout({ children }:{ children:any }) {
  const { navOpened } = useNavbarStore()
  const location = useLocation()
  useEffect(()=>{
    if (location.pathname !== "/"){
      sessionStorage.setItem('home_section', getMainPath())
    }
  },[location.pathname])
  return <AppShell
    header={{ height: 70 }}
    navbar={{ width: 300 , breakpoint: "md", collapsed: { mobile: !navOpened } }}
    p="md"
  >
    <HeaderPage />
    <NavBar />
    <AppShell.Main>
      <Container size="lg">
          {children}
      </Container>
    </AppShell.Main>
  <Space h="lg" />

  </AppShell>

}

export default MainLayout;

export const MenuDropDownWithButton = ({children}:{children:any}) => <Menu withArrow>
        <Menu.Target>
            <Tooltip label="More options" color="gray">
              <ActionIcon variant='transparent'>
                  <HiMenu size={24} color='#FFF'/>
              </ActionIcon>
            </Tooltip>
        </Menu.Target>
        <Menu.Dropdown>
            {children}
        </Menu.Dropdown>
</Menu>
