import { Divider, Group, MantineColor, ScrollArea, Text, ThemeIcon, Title, UnstyledButton, Box, AppShell } from "@mantine/core";
import { useState } from "react";
import { TbPlugConnected } from "react-icons/tb";
import { useNavigate } from "react-router-dom";
import { GrDirections } from "react-icons/gr";
import { PiWallLight } from "react-icons/pi";
import { useNavbarStore } from "../../js/store";
import { getMainPath } from "../../js/utils";
import { BsRegex } from "react-icons/bs";

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
            <NavBarButton navigate="nfregex" closeNav={closeNav} name="Netfilter Regex" color="grape" icon={<BsRegex size={19} />} />
            <NavBarButton navigate="firewall" closeNav={closeNav} name="Firewall Rules" color="red" icon={<PiWallLight size={19} />} />
            <NavBarButton navigate="porthijack" closeNav={closeNav} name="Hijack Port to Proxy" color="blue" icon={<GrDirections size={19} />} />
            <Box px="xs" mt="lg">
                <Title order={5}>Experimental Features 🧪</Title>
            </Box>
            <Text></Text>
            <Divider my="xs" />
            <NavBarButton navigate="nfproxy" closeNav={closeNav} name="Netfilter Proxy" color="lime" icon={<TbPlugConnected size={19} />} />
        </Box>
        
    </AppShell.Navbar>
}
