import { useEffect } from 'react';
import { ActionIcon, Container, Menu, Space } from '@mantine/core';
import { AppShell } from '@mantine/core';
import NavBar from './NavBar';
import HeaderPage from './Header';
import { getMainPath } from '../js/utils';
import { useLocation } from 'react-router-dom';
import { RiMenu5Fill } from 'react-icons/ri';
import { useNavbarStore } from '../js/store';


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
            <ActionIcon variant='transparent'>
                <RiMenu5Fill size={24} color='#FFF'/>
            </ActionIcon>
        </Menu.Target>
        <Menu.Dropdown>
            {children}
        </Menu.Dropdown>
</Menu>
