import { Collapse, Divider, Group, MantineColor, Navbar, ScrollArea, Text, ThemeIcon, Title, UnstyledButton } from "@mantine/core";
import { useState } from "react";
import { IoMdGitNetwork } from "react-icons/io";
import { MdOutlineExpandLess, MdOutlineExpandMore, MdTransform } from "react-icons/md";
import { useNavigate } from "react-router-dom";
import { getmainpath } from "../../js/utils";
import { GrDirections } from "react-icons/gr";
import { PiWallLight } from "react-icons/pi";

function NavBarButton({ navigate, closeNav, name, icon, color, disabled, onClick }:
    { navigate?: string, closeNav: () => void, name:string, icon:any, color:MantineColor, disabled?:boolean, onClick?:CallableFunction }) {
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
    })} onClick={()=>{
        if(navigate){navigator(`/${navigate}`);closeNav()}
        if (onClick) onClick()
    }} disabled={disabled}>
        <Group>
            <ThemeIcon color={color} variant="light">
                {icon}
            </ThemeIcon>
            <Text size="sm">{name}</Text>
        </Group>
    </UnstyledButton>
} 

export default function NavBar({ closeNav, opened }: {closeNav: () => void, opened: boolean}) {
    const [toggle, setToggleState] = useState(false);

    
    return <Navbar p="md" hiddenBreakpoint="md" hidden={!opened} width={{ md: 300 }}>
        <Navbar.Section px="xs" mt="xs">
            <Title order={3}>[Fi]*regex 🔥</Title>
        </Navbar.Section>
        <Divider my="xs" />

        <Navbar.Section grow component={ScrollArea} px="xs" mt="xs">
            <NavBarButton navigate="firewall" closeNav={closeNav} name="Firewall Rules" color="red" icon={<PiWallLight />} />
            <NavBarButton navigate="nfregex" closeNav={closeNav} name="Netfilter Regex" color="lime" icon={<IoMdGitNetwork />} />
            <NavBarButton navigate="porthijack" closeNav={closeNav} name="Hijack Port to Proxy" color="blue" icon={<GrDirections />} />
            <Divider my="xs" label="Advanced" labelPosition="center" />
            <NavBarButton closeNav={closeNav} name="Deprecated options" color="gray" icon={toggle ? <MdOutlineExpandLess /> : <MdOutlineExpandMore />} onClick={()=>setToggleState(!toggle)}/>
            <Collapse in={toggle}>
                <NavBarButton navigate="regexproxy" closeNav={closeNav} name="TCP Proxy Regex Filter" color="grape" icon={<MdTransform />} />
            </Collapse>
        </Navbar.Section>
        
    </Navbar>
}
