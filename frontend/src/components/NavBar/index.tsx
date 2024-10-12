import { Collapse, Divider, Group, MantineColor, ScrollArea, Text, ThemeIcon, Title, UnstyledButton, Box, AppShell } from "@mantine/core";
import { useState } from "react";
import { IoMdGitNetwork } from "react-icons/io";
import { MdOutlineExpandLess, MdOutlineExpandMore, MdTransform } from "react-icons/md";
import { useNavigate } from "react-router-dom";
import { GrDirections } from "react-icons/gr";
import { PiWallLight } from "react-icons/pi";
import { useNavbarStore } from "../../js/store";
import { getMainPath } from "../../js/utils";

function NavBarButton({ navigate, closeNav, name, icon, color, disabled, onClick }:
    { navigate?: string, closeNav: () => void, name:string, icon:any, color:MantineColor, disabled?:boolean, onClick?:CallableFunction }) {
    const navigator = useNavigate()
    return <UnstyledButton
        className={`firegex__navbar__unstyled_button${navigate==getMainPath()?" selected":""}${disabled?" disabled":""}`}
        onClick={()=>{
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

export default function NavBar() {
    const [toggle, setToggleState] = useState(false);
    const { navOpened, closeNav } = useNavbarStore()

    return <AppShell.Navbar p="md" hidden={!navOpened}>
        <Box px="xs" mt="xs">
            <Title order={4}>Options ⚙️</Title>
        </Box>
        <Divider my="xs" />
        <Box style={{flexGrow: 1}} component={ScrollArea} px="xs" mt="xs">
            <NavBarButton navigate="nfregex" closeNav={closeNav} name="Netfilter Regex" color="lime" icon={<IoMdGitNetwork />} />
            <NavBarButton navigate="firewall" closeNav={closeNav} name="Firewall Rules" color="red" icon={<PiWallLight />} />
            <NavBarButton navigate="porthijack" closeNav={closeNav} name="Hijack Port to Proxy" color="blue" icon={<GrDirections />} />
            <Divider my="xs" label="Advanced" labelPosition="center" />
            <NavBarButton closeNav={closeNav} name="Deprecated options" color="gray" icon={toggle ? <MdOutlineExpandLess /> : <MdOutlineExpandMore />} onClick={()=>setToggleState(!toggle)}/>
            <Collapse in={toggle}>
                <NavBarButton navigate="regexproxy" closeNav={closeNav} name="TCP Proxy Regex Filter" color="grape" icon={<MdTransform />} />
            </Collapse>
        </Box>
        
    </AppShell.Navbar>
}
