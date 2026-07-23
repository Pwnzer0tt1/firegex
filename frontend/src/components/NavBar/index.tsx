import { Divider, Group, MantineColor, ScrollArea, Text, ThemeIcon, Title, UnstyledButton, Box, AppShell } from "@mantine/core";
import { useState } from "react";
import { TbPlugConnected, TbShieldLock } from "react-icons/tb";
import { useNavigate } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { GrDirections } from "react-icons/gr";
import { PiWallLight } from "react-icons/pi";
import { useNavbarStore } from "../../js/store";
import { getMainPath, getapi, postapi, okNotify, errorNotify } from "../../js/utils";
import { BsRegex } from "react-icons/bs";
import { MdDownload, MdUpload } from "react-icons/md";

function NavBarButton({ navigate, closeNav, name, icon, color, disabled, onClick }:
    { navigate?: string, closeNav: () => void, name: string, icon: any, color: MantineColor, disabled?: boolean, onClick?: CallableFunction }) {
    const navigator = useNavigate()
    return <UnstyledButton
        className={`firegex__navbar__unstyled_button${navigate == getMainPath() ? " selected" : ""}${disabled ? " disabled" : ""}`}
        onClick={() => {
            if (navigate) { navigator(`/${navigate}`); closeNav() }
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
    const queryClient = useQueryClient()

    return <AppShell.Navbar p="md" hidden={!navOpened}>
        <Box px="xs" mt="xs">
            <Title order={4}>Options ⚙️</Title>
        </Box>
        <Divider my="xs" />
        <Box style={{ flexGrow: 1 }} component={ScrollArea} px="xs" mt="xs">
            <NavBarButton navigate="nfregex" closeNav={closeNav} name="Netfilter Regex" color="grape" icon={<BsRegex size={19} />} />
            <NavBarButton navigate="firewall" closeNav={closeNav} name="Firewall Rules" color="red" icon={<PiWallLight size={19} />} />
            <NavBarButton navigate="porthijack" closeNav={closeNav} name="Hijack Port to Proxy" color="blue" icon={<GrDirections size={19} />} />
            <NavBarButton navigate="nfproxy" closeNav={closeNav} name="Netfilter Proxy" color="lime" icon={<TbPlugConnected size={19} />} />
            <NavBarButton navigate="tls-decrypt" closeNav={closeNav} name="TLS Decryption" color="cyan" icon={<TbShieldLock size={19} />} />
            <Box px="xs" mt="lg">
                <Title order={5}>Backup & Restore</Title>
            </Box>
            <Divider my="xs" />
            <NavBarButton closeNav={closeNav} name="Export Backup" color="yellow" icon={<MdDownload size={19} />} onClick={() => {
                getapi('export').then(data => {
                    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `firegex_backup_${new Date().toISOString().split('T')[0]}.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    okNotify("Backup Exported", "Your configuration backup has been downloaded.");
                }).catch(err => errorNotify("Export Failed", err.toString()));
            }} />
            <NavBarButton closeNav={closeNav} name="Import Backup" color="orange" icon={<MdUpload size={19} />} onClick={() => {
                const input = document.createElement('input');
                input.type = 'file';
                input.accept = '.json';
                input.onchange = (e) => {
                    const file = (e.target as HTMLInputElement).files?.[0];
                    if (!file) return;
                    const reader = new FileReader();
                    reader.onload = (e) => {
                        try {
                            const data = JSON.parse(e.target?.result as string);
                            postapi('import', data).then(() => {
                                okNotify("Backup Imported", "Configuration has been restored successfully.");
                                queryClient.invalidateQueries();
                            }).catch(err => errorNotify("Import Failed", err.toString()));
                        } catch (err: any) {
                            errorNotify("Invalid JSON", err.toString());
                        }
                    };
                    reader.readAsText(file);
                };
                input.click();
            }} />
        </Box>

    </AppShell.Navbar>
}
