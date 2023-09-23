import { ActionIcon, Badge, LoadingOverlay, Space, Title, Tooltip } from "@mantine/core"
import { useEffect, useState } from "react";
import { BsPlusLg } from "react-icons/bs"
import { ActionType, GeneralStats, RuleInfo, firewall } from "../../components/Firewall/utils";
import { errorNotify, eventUpdateName, fireUpdateRequest } from "../../js/utils";
import { useWindowEvent } from "@mantine/hooks";



export const Firewall = () => {

    const [generalStats, setGeneralStats] = useState<GeneralStats>({ rules: 0 });
    const [rules, setRules] = useState<RuleInfo>({rules:[], policy:ActionType.ACCEPT});
    const [loader, setLoader] = useState(true);
    const [tooltipAddOpened, setTooltipAddOpened] = useState(false);
    const [open, setOpen] = useState(false);


    const updateInfo = async () => {
        
        await Promise.all([
            firewall.stats().then(res => {
                setGeneralStats(res)
            }).catch(
                err => errorNotify("General Info Auto-Update failed!", err.toString())
            ),
            firewall.rules().then(res => {
                setRules(res)    
            }).catch(err => {
                errorNotify("Home Page Auto-Update failed!", err.toString())
            })
        ])
        setLoader(false)
    }

    useWindowEvent(eventUpdateName, updateInfo)
    useEffect(fireUpdateRequest,[])


    return <>
        <Space h="sm" />
        <div className='center-flex'>
            <Title order={4}>Firewall Rules</Title>
            <div className='flex-spacer' />
            <Badge size="sm" color="green" variant="filled">Rules: {generalStats.rules}</Badge>
            <Space w="xs" />
            <Tooltip label="Add a new rule" position='bottom' color="blue" opened={tooltipAddOpened}>
                <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"
                onFocus={() => setTooltipAddOpened(false)} onBlur={() => setTooltipAddOpened(false)}
                onMouseEnter={() => setTooltipAddOpened(true)} onMouseLeave={() => setTooltipAddOpened(false)}><BsPlusLg size={18} /></ActionIcon>
            </Tooltip>
        </div>
        <LoadingOverlay visible={loader} />
    </>
}