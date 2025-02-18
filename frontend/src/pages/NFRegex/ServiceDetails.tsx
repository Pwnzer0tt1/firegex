import { ActionIcon, Box, Grid, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import { Navigate, useNavigate, useParams } from 'react-router-dom';
import RegexView from '../../components/RegexView';
import AddNewRegex from '../../components/AddNewRegex';
import { BsPlusLg } from "react-icons/bs";
import { nfregexServiceQuery, nfregexServiceRegexesQuery, Service } from '../../components/NFRegex/utils';
import { Badge, Divider, Menu } from '@mantine/core';
import { useState } from 'react';
import { FaFilter, FaPlay, FaStop } from 'react-icons/fa';
import { nfregex, serviceQueryKey } from '../../components/NFRegex/utils';
import { MdDoubleArrow } from "react-icons/md"
import YesNoModal from '../../components/YesNoModal';
import { errorNotify, isMediumScreen, okNotify, regex_ipv4 } from '../../js/utils';
import { BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi'
import RenameForm from '../../components/NFRegex/ServiceRow/RenameForm';
import { MenuDropDownWithButton } from '../../components/MainLayout';
import { useQueryClient } from '@tanstack/react-query';
import { FaArrowLeft } from "react-icons/fa";
import { VscRegex } from 'react-icons/vsc';
import { IoSettingsSharp } from 'react-icons/io5';
import AddEditService from '../../components/NFRegex/AddEditService';

export default function ServiceDetailsNFRegex() {

    const {srv} = useParams()
    const [open, setOpen] = useState(false)
    const services = nfregexServiceQuery()
    const serviceInfo = services.data?.find(s => s.service_id == srv)
    const [tooltipAddRegexOpened, setTooltipAddRegexOpened] = useState(false)
    const regexesList = nfregexServiceRegexesQuery(srv??"")
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [editModal, setEditModal] = useState(false)
    const [buttonLoading, setButtonLoading] = useState(false)
    const queryClient = useQueryClient()
    const [tooltipStopOpened, setTooltipStopOpened] = useState(false);
    const [tooltipBackOpened, setTooltipBackOpened] = useState(false);
    const navigate = useNavigate()
    const isMedium = isMediumScreen()

    if (services.isLoading) return <LoadingOverlay visible={true} />
    if (!srv || !serviceInfo || regexesList.isError) return <Navigate to="/" replace />

    let status_color = "gray";
    switch(serviceInfo.status){
        case "stop": status_color = "red"; break;
        case "active": status_color = "teal"; break;
    }

    const startService = async () => {
        setButtonLoading(true)
        await nfregex.servicestart(serviceInfo.service_id).then(res => {
            if(!res){
                okNotify(`Service ${serviceInfo.name} started successfully!`,`The service on ${serviceInfo.port} has been started!`)
                queryClient.invalidateQueries(serviceQueryKey)
            }else{
                errorNotify(`An error as occurred during the starting of the service ${serviceInfo.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${serviceInfo.port}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const deleteService = () => {
        nfregex.servicedelete(serviceInfo.service_id).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${serviceInfo.name} has been deleted!`)
                queryClient.invalidateQueries(serviceQueryKey)
            }else
                errorNotify("An error occurred while deleting a service",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while deleting a service",`Error: ${err}`)
        })
    }

    const stopService = async () => {
        setButtonLoading(true)
        
        await nfregex.servicestop(serviceInfo.service_id).then(res => {
            if(!res){
                okNotify(`Service ${serviceInfo.name} stopped successfully!`,`The service on ${serviceInfo.port} has been stopped!`)
                queryClient.invalidateQueries(serviceQueryKey)
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${serviceInfo.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${serviceInfo.port}`,`Error: ${err}`)
        })
        setButtonLoading(false);
    }

    return <>
        <LoadingOverlay visible={regexesList.isLoading} />
        <Box className={isMedium?'center-flex':'center-flex-row'} style={{ justifyContent: "space-between"}} px="md" mt="lg">
            <Box>
                <Title order={1}>
                    <Box className="center-flex">
                        <MdDoubleArrow /><Space w="sm" />{serviceInfo.name}
                    </Box>   
                </Title>
            </Box>
            {isMedium?null:<Space h="md" />}
            <Box className='center-flex'>
                <Badge color={status_color} radius="md" size="xl" variant="filled" mr="sm">
                    {serviceInfo.status}
                </Badge>
                <Badge size="xl" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient" radius="md" mr="sm">
                    :{serviceInfo.port}
                </Badge>

                <MenuDropDownWithButton>
                    <Menu.Item><b>Edit service</b></Menu.Item>
                    <Menu.Item leftSection={<IoSettingsSharp size={18} />} onClick={()=>setEditModal(true)}>Service Settings</Menu.Item>
                    <Menu.Item leftSection={<BiRename size={18} />} onClick={()=>setRenameModal(true)}>Change service name</Menu.Item>
                    <Divider />
                    <Menu.Label><b>Danger zone</b></Menu.Label>
                    <Menu.Item color="red" leftSection={<BsTrashFill size={18} />} onClick={()=>setDeleteModal(true)}>Delete Service</Menu.Item>
                </MenuDropDownWithButton>   
            </Box>
        </Box>
        {isMedium?null:<Space h="md" />}
        <Box className={isMedium?'center-flex':'center-flex-row'} style={{ justifyContent: "space-between"}} px="md" mt="lg">
            <Box className={isMedium?'center-flex':'center-flex-row'}>
                <Box className='center-flex'>
                    <Badge color="yellow" radius="sm" size="md" variant="filled"><FaFilter style={{ marginBottom: -2}} /> {serviceInfo.n_packets}</Badge>
                    <Space w="xs" />
                    <Badge color="violet" radius="sm" size="md" variant="filled"><VscRegex style={{ marginBottom: -2}} size={13} /> {serviceInfo.n_regex}</Badge>
                </Box>
                {isMedium?<Space w="xs" />:<Space h="xs" />}
                <Badge color={serviceInfo.ip_int.match(regex_ipv4)?"cyan":"pink"} radius="sm" size="md" variant="filled" mr="xs">{serviceInfo.ip_int} on {serviceInfo.proto}</Badge>
            </Box>
            {isMedium?null:<Space h="xl" />}
            <Box className='center-flex'>
                <Tooltip label="Go back" zIndex={0} color="cyan" opened={tooltipBackOpened}>
                    <ActionIcon color="cyan"
                    onClick={() => navigate("/")} size="xl" radius="md" variant="filled"
                    aria-describedby="tooltip-back-id"
                    onFocus={() => setTooltipBackOpened(false)} onBlur={() => setTooltipBackOpened(false)}
                    onMouseEnter={() => setTooltipBackOpened(true)} onMouseLeave={() => setTooltipBackOpened(false)}>
                        <FaArrowLeft size="25px" />
                    </ActionIcon>
                </Tooltip>
                <Space w="md"/>
                <Tooltip label="Stop service" zIndex={0} color="red" opened={tooltipStopOpened}>
                    <ActionIcon color="red" loading={buttonLoading}
                    onClick={stopService} size="xl" radius="md" variant="filled"
                    disabled={serviceInfo.status === "stop"}
                    aria-describedby="tooltip-stop-id"
                    onFocus={() => setTooltipStopOpened(false)} onBlur={() => setTooltipStopOpened(false)}
                    onMouseEnter={() => setTooltipStopOpened(true)} onMouseLeave={() => setTooltipStopOpened(false)}>
                        <FaStop size="20px" />
                    </ActionIcon>
                </Tooltip>
                <Space w="md"/>
                <Tooltip label="Start service" zIndex={0} color="teal">
                    <ActionIcon color="teal" size="xl" radius="md" onClick={startService} loading={buttonLoading}
                                variant="filled" disabled={!["stop","pause"].includes(serviceInfo.status)?true:false}>
                        <FaPlay size="20px" />
                    </ActionIcon>
                </Tooltip>
            </Box>
        </Box>
        <Divider my="xl" />
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
                {regexesList.data?.map( (regexInfo) => <Grid.Col key={regexInfo.id} span={{ lg:6, xs: 12 }}><RegexView regexInfo={regexInfo} /></Grid.Col>)}
            </Grid>
        }

        {srv?<AddNewRegex opened={open} onClose={() => {setOpen(false);}} service={srv} />:null}
        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${serviceInfo.port}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
        <RenameForm
            onClose={()=>setRenameModal(false)}
            opened={renameModal}
            service={serviceInfo}
        />
        <AddEditService
            opened={editModal}
            onClose={()=>setEditModal(false)}
            edit={serviceInfo}
        />
    </>
}
