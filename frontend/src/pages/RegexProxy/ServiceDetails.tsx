import { ActionIcon, Box, Grid, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { Navigate, useParams } from 'react-router-dom';
import { BsPlusLg } from "react-icons/bs";
import { regexproxyServiceQuery, regexproxyServiceRegexesQuery } from '../../components/RegexProxy/utils';
import ServiceRow from '../../components/RegexProxy/ServiceRow';
import AddNewRegex from '../../components/AddNewRegex';
import RegexView from '../../components/RegexView';

function ServiceDetailsProxyRegex() {

    const {srv} = useParams()
    const [open, setOpen] = useState(false)
    const services = regexproxyServiceQuery()
    const serviceInfo = services.data?.find(s => s.id == srv)
    const [tooltipAddRegexOpened, setTooltipAddRegexOpened] = useState(false)
    const regexesList = regexproxyServiceRegexesQuery(srv??"")

    if (!srv || !serviceInfo || regexesList.isError) return <Navigate to="/" replace />

    return <Box>
        <LoadingOverlay visible={regexesList.isLoading} />
        <ServiceRow service={serviceInfo} />
        {(!regexesList.data || regexesList.data.length == 0)?<>
                <Space h="xl" />
                <Title className='center-flex' style={{textAlign:"center"}} order={3}>No regex found for this service! Add one by clicking the "+" buttons</Title>
                <Space h="xl" /> <Space h="xl" /> 
                <Box className='center-flex'>
                    <Tooltip label="Add a new regex" zIndex={0} color="blue" opened={tooltipAddRegexOpened}>
                        <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                         aria-describedby="tooltip-AddRegex-id"
                         onFocus={() => setTooltipAddRegexOpened(false)} onBlur={() => setTooltipAddRegexOpened(false)}
                         onMouseEnter={() => setTooltipAddRegexOpened(true)} onMouseLeave={() => setTooltipAddRegexOpened(false)}><BsPlusLg size="20px" /></ActionIcon>
                    </Tooltip>
                </Box>
            </>:
            <Grid>
                {regexesList.data.map( (regexInfo) => <Grid.Col key={regexInfo.id} span={{ lg:6, xs: 12 }}><RegexView regexInfo={regexInfo} /></Grid.Col>)}
            </Grid>
        }

        {srv?<AddNewRegex opened={open} onClose={() => {setOpen(false)}} service={srv} />:null}


    </Box>
}

export default ServiceDetailsProxyRegex;
