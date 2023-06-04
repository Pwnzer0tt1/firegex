import { ActionIcon, Grid, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { BsPlusLg } from "react-icons/bs";
import { useWindowEvent } from '@mantine/hooks';
import { regexproxy, Service } from '../../components/RegexProxy/utils';
import { RegexFilter } from '../../js/models';
import { errorNotify, eventUpdateName, fireUpdateRequest } from '../../js/utils';
import ServiceRow from '../../components/RegexProxy/ServiceRow';
import AddNewRegex from '../../components/AddNewRegex';
import RegexView from '../../components/RegexView';

function ServiceDetailsProxyRegex() {
    const {srv} = useParams()

    const [serviceInfo, setServiceInfo] = useState<Service>({
        id:srv?srv:"",
        internal_port:0,
        n_packets:0,
        n_regex:0,
        name:srv?srv:"",
        public_port:0,
        status:"🤔"
    })

    const [regexesList, setRegexesList] = useState<RegexFilter[]>([])
    const [loader, setLoader] = useState(true);
    const [open, setOpen] = useState(false);
    const closeModal = () => {setOpen(false);updateInfo();}

    const updateInfo = async () => {
        if (!srv) return
        let error = false;
        await regexproxy.serviceinfo(srv).then(res => {
            setServiceInfo(res)
        }).catch(
          err =>{
            error = true;
            navigator("/")
        })
        if (error) return
        await regexproxy.serviceregexes(srv).then(res => {
            setRegexesList(res)
        }).catch(
          err => errorNotify(`Updater for ${srv} service failed [Regex list]!`, err.toString())
        )
        setLoader(false)
    }

    useWindowEvent(eventUpdateName, updateInfo)
    useEffect(fireUpdateRequest,[])

    const navigator = useNavigate()


    const [tooltipAddRegexOpened, setTooltipAddRegexOpened] = useState(false);

    return <div>
        <LoadingOverlay visible={loader} />
        <ServiceRow service={serviceInfo} />
        {regexesList.length === 0?<>
                <Space h="xl" />
                <Title className='center-flex' align='center' order={3}>No regex found for this service! Add one by clicking the "+" buttons</Title>
                <Space h="xl" /> <Space h="xl" /> <Space h="xl" /> <Space h="xl" />
                <div className='center-flex'>
                    <Tooltip label="Add a new regex" zIndex={0} color="blue" opened={tooltipAddRegexOpened}>
                        <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                         aria-describedby="tooltip-AddRegex-id"
                         onFocus={() => setTooltipAddRegexOpened(false)} onBlur={() => setTooltipAddRegexOpened(false)}
                         onMouseEnter={() => setTooltipAddRegexOpened(true)} onMouseLeave={() => setTooltipAddRegexOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
                    </Tooltip>
                </div>
            </>:
            <Grid>
                {regexesList.map( (regexInfo) => <Grid.Col key={regexInfo.id} lg={6} xs={12}><RegexView regexInfo={regexInfo} /></Grid.Col>)}
            </Grid>
        }

        {srv?<AddNewRegex opened={open} onClose={closeModal} service={srv} />:null}


    </div>
}

export default ServiceDetailsProxyRegex;
