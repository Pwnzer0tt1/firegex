import { ActionIcon, Grid, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import RegexView from '../../components/RegexView';
import ServiceRow from '../../components/NFRegex/ServiceRow';
import AddNewRegex from '../../components/AddNewRegex';
import { BsPlusLg } from "react-icons/bs";
import { nfregexServiceQuery, nfregexServiceRegexesQuery } from '../../components/NFRegex/utils';

function ServiceDetailsNFRegex() {

    const {srv} = useParams()
    const [open, setOpen] = useState(false)
    const services = nfregexServiceQuery()
    const serviceInfo = services.data?.find(s => s.service_id == srv)
    const [tooltipAddRegexOpened, setTooltipAddRegexOpened] = useState(false)
    const regexesList = nfregexServiceRegexesQuery(srv??"")

    if (!srv || !serviceInfo || regexesList.isError) return <Navigate to="/" replace />

    return <>
        <LoadingOverlay visible={regexesList.isLoading} />
        <ServiceRow service={serviceInfo} />
        {(!regexesList.data || regexesList.data.length == 0)?<>
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
                {regexesList.data?.map( (regexInfo) => <Grid.Col key={regexInfo.id} lg={6} xs={12}><RegexView regexInfo={regexInfo} /></Grid.Col>)}
            </Grid>
        }

        {srv?<AddNewRegex opened={open} onClose={() => {setOpen(false);}} service={srv} />:null}
    </>
}

export default ServiceDetailsNFRegex;
