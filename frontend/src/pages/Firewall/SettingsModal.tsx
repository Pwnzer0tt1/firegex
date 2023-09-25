import { Button, Group, Space, Modal, Switch } from '@mantine/core';
import { useEffect, useState } from 'react';
import { errorNotify, okNotify } from '../../js/utils';
import { FirewallSettings, firewall } from '../../components/Firewall/utils';

export function SettingsModal({ opened, onClose }:{ opened:boolean, onClose:()=>void }) {

    const [settings, setSettings] = useState<FirewallSettings>({keep_rules:false, allow_established:true, allow_loopback:true})

    useEffect(()=>{
        firewall.settings().then( res => {
            setSettings(res)
        }).catch( err => {
            errorNotify("Setting fetch failed!", err.toString())
            onClose()
        })
    },[])

    const [submitLoading, setSubmitLoading] = useState(false)
 
    const submitRequest = () =>{
        setSubmitLoading(true)
        firewall.setsettings(settings).then( () => {
            okNotify("Settings updated!", "Settings updated successfully")
            setSubmitLoading(false)
            onClose()
        }).catch( err => {
            errorNotify("Settings update failed!", err.toString())
            setSubmitLoading(false)
        })
    }


  return <Modal size="xl" title="Change firewall settings" opened={opened} onClose={onClose} closeOnClickOutside={false} centered>

            <Switch label="Keep rules on firegex shutdown" checked={settings.keep_rules} onChange={v => setSettings({...settings, keep_rules:v.target.checked})}/>
            <Space h="md" />
            <Switch label="Allow loopback to communicate with itself" checked={settings.allow_loopback} onChange={v => setSettings({...settings, allow_loopback:v.target.checked})}/>
            <Space h="md" />
            <Switch label="Allow established connection (essential to allow opening connection) (Dangerous to disable)" checked={settings.allow_established} onChange={v => setSettings({...settings, allow_established:v.target.checked})}/>
            <Space h="md" />

            <Group position="right" mt="md">
                <Button loading={submitLoading} onClick={submitRequest}>Save Setting</Button>
            </Group>
    </Modal>

}
