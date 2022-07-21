import { ActionIcon, Grid, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import RegexView from '../components/RegexView';
import ServiceRow from '../components/ServiceRow';
import AddNewRegex from '../components/AddNewRegex';
import { BsPlusLg } from "react-icons/bs";
import { RegexFilter, Service } from '../js/models';
import { errorNotify, eventUpdateName, fireUpdateRequest, serviceinfo, serviceregexlist } from '../js/utils';
import { useWindowEvent } from '@mantine/hooks';

function ServiceDetails() {
    const {srv_id} = useParams()

    const [serviceInfo, setServiceInfo] = useState<Service>({
        id:srv_id?srv_id:"",
        internal_port:0,
        n_packets:0,
        n_regex:0,
        name:srv_id?srv_id:"",
        public_port:0,
        status:"🤔"
    })

    const [regexesList, setRegexesList] = useState<RegexFilter[]>([])
    const [loader, setLoader] = useState(true);
    const [open, setOpen] = useState(false);
    const closeModal = () => {setOpen(false);updateInfo();}

    const updateInfo = async () => {
        if (!srv_id) return
        let error = false;
        await serviceinfo(srv_id).then(res => {
            setServiceInfo(res)
        }).catch(
          err =>{
            error = true;
            navigator("/")
        })
        if (error) return
        await serviceregexlist(srv_id).then(res => {
            setRegexesList(res)
        }).catch(
          err => errorNotify(`Updater for ${srv_id} service failed [Regex list]!`, err.toString())
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
                    <Tooltip label="Add a new regex" zIndex={0} transition="pop" transitionDuration={200} /*openDelay={500}*/ transitionTimingFunction="ease" color="blue" opened={tooltipAddRegexOpened} tooltipId="tooltip-AddRegex-id">
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

        {srv_id?<AddNewRegex opened={open} onClose={closeModal} service={srv_id} />:null}


    </div>
}

export default ServiceDetails;
