import { ActionIcon, Badge, LoadingOverlay, Space, Title, Tooltip } from "@mantine/core"
import { useEffect, useState } from "react";
import { BsPlusLg } from "react-icons/bs"
import { firewall, firewallRulesQuery } from "../../components/Firewall/utils";
import { errorNotify, getErrorMessage } from "../../js/utils";



export const Firewall = () => {

    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
    const [open, setOpen] = useState(false);

    const rules = firewallRulesQuery()


    useEffect(()=> {
        if(rules.isError)
            errorNotify("Firewall Update failed!", getErrorMessage(rules.error))
    },[rules.isError])

    return <>
        <Space h="sm" />
        <div className='center-flex'>
            <Title order={4}>Firewall Rules</Title>
            <div className='flex-spacer' />
            <div className='flex-spacer' />
            <Badge size="sm" color="green" variant="filled">Rules: {rules.isLoading?0:rules.data?.rules.length}</Badge>
            <Space w="xs" />
            <Badge size="sm" color="yellow" variant="filled">Policy: {rules.isLoading?"unknown":rules.data?.policy}</Badge>
            <Space w="xs" />
            <Badge size="sm" color="violet" variant="filled">Enabled: {rules.isLoading?"?":(rules.data?.enabled?"🟢":"🔴")}</Badge>
            <Space w="xs" />
            <Tooltip label="Add a new rule" position='bottom' color="blue" opened={tooltipAddOpened}>
                <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
                onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
                onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
            </Tooltip>
        </div>
        <LoadingOverlay visible={rules.isLoading} />
    </>
}