import { Group, MantineColor, Navbar, ScrollArea, Text, ThemeIcon, Title, UnstyledButton } from "@mantine/core";
import React from "react";
import { IoMdGitNetwork } from "react-icons/io";
import { MdTransform } from "react-icons/md";
import { useNavigate } from "react-router-dom";
import { getmainpath } from "../../js/utils";
import { GrDirections } from "react-icons/gr";

function NavBarButton({ navigate, closeNav, name, icon, color, disabled }:
    { navigate: string, closeNav: () => void, name:string, icon:any, color:MantineColor, disabled?:boolean }) {
    const navigator = useNavigate()

    return <UnstyledButton sx={(theme) => ({
        display: 'block',
        width: '100%',
        padding: theme.spacing.xs,
        borderRadius: theme.radius.sm,
        opacity: disabled ? 0.4 : 1,
        color: theme.colorScheme === 'dark' ? theme.colors.dark[0] : theme.black,
        backgroundColor:(navigate===getmainpath()?(theme.colorScheme === 'dark' ? theme.colors.dark[6] : theme.colors.gray[0]):"transparent"),
        '&:hover': {
            backgroundColor:
                theme.colorScheme === 'dark' ? theme.colors.dark[6] : theme.colors.gray[0],
        },
    })} onClick={()=>{navigator(`/${navigate}`);closeNav()}} disabled={disabled}>
        <Group>
            <ThemeIcon color={color} variant="light">
                {icon}
            </ThemeIcon>
            <Text size="sm">{name}</Text>
        </Group>
    </UnstyledButton>
} 

export default function NavBar({ closeNav, opened }: {closeNav: () => void, opened: boolean}) {
    
    return <Navbar p="md" hiddenBreakpoint="md" hidden={!opened} width={{ md: 300 }}>
        <Navbar.Section px="xs" mt="xs">
            <Title order={3}>[Fi]*regex 🔥</Title>
        </Navbar.Section>
        <hr style={{width:"100%"}}/>
        <Navbar.Section grow component={ScrollArea} px="xs" mt="xs">
            <NavBarButton navigate="nfregex" closeNav={closeNav} name="Netfilter Regex" color="blue" icon={<IoMdGitNetwork />} />
            <NavBarButton navigate="regexproxy" closeNav={closeNav} name="TCP Proxy Regex Filter" color="lime" icon={<MdTransform />} />
            <NavBarButton navigate="porthijack" closeNav={closeNav} name="Hijack Port to Proxy" color="red" icon={<GrDirections />} />
        </Navbar.Section>
        
    </Navbar>
}
