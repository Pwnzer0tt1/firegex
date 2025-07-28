import { ActionIcon, Box, Code, Grid, LoadingOverlay, Space, Title, Tooltip } from '@mantine/core';
import { Navigate, useNavigate, useParams } from 'react-router';
import { Badge, Divider, Menu } from '@mantine/core';
import { useEffect, useState } from 'react';
import { FaFilter, FaPencilAlt, FaPlay, FaStop } from 'react-icons/fa';
import { EXAMPLE_PYFILTER, nfproxy, nfproxyServiceFilterCodeQuery, nfproxyServicePyfiltersQuery, nfproxyServiceQuery, serviceQueryKey } from '../../components/NFProxy/utils';
import { MdDoubleArrow } from "react-icons/md"
import YesNoModal from '../../components/YesNoModal';
import { errorNotify, isMediumScreen, okNotify, regex_ipv4, socketio } from '../../js/utils';
import { BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi'
import RenameForm from '../../components/NFProxy/ServiceRow/RenameForm';
import { MenuDropDownWithButton } from '../../components/MainLayout';
import { useQueryClient } from '@tanstack/react-query';
import { FaArrowLeft } from "react-icons/fa";
import { IoSettingsSharp } from 'react-icons/io5';
import AddEditService from '../../components/NFProxy/AddEditService';
import PyFilterView from '../../components/PyFilterView';
import { TbPlugConnected } from 'react-icons/tb';
import { CodeHighlight } from '@mantine/code-highlight';
import { FaPython } from "react-icons/fa";
import { FiFileText } from "react-icons/fi";
import { ModalLog } from '../../components/ModalLog';
import { useListState } from '@mantine/hooks';
import { ExceptionWarning } from '../../components/NFProxy/ExceptionWarning';
import { DocsButton } from '../../components/DocsButton';

export default function ServiceDetailsNFProxy() {

    const {srv} = useParams()
    const services = nfproxyServiceQuery()
    const serviceInfo = services.data?.find(s => s.service_id == srv)
    const filtersList = nfproxyServicePyfiltersQuery(srv??"")
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [editModal, setEditModal] = useState(false)
    const [buttonLoading, setButtonLoading] = useState(false)
    const queryClient = useQueryClient()
    const filterCode = nfproxyServiceFilterCodeQuery(srv??"")
    const navigate = useNavigate()
    const isMedium = isMediumScreen()
    const [openLogModal, setOpenLogModal] = useState(false)
    const [logData, logDataSetters] = useListState<string>([]);
    

    useEffect(()=>{
        if (srv){
            if (openLogModal){
                logDataSetters.setState([])
                socketio.emit("nfproxy-outstream-join", { service: srv });
                socketio.on(`nfproxy-outstream-${srv}`, (data) => {
                    logDataSetters.append(data)
                });
            }else{
                socketio.emit("nfproxy-outstream-leave", { service: srv });
                socketio.off(`nfproxy-outstream-${srv}`);
                logDataSetters.setState([])
            }
            return () => {
                socketio.emit("nfproxy-outstream-leave", { service: srv });
                socketio.off(`nfproxy-outstream-${srv}`);
                logDataSetters.setState([])
            }
        }
    }, [openLogModal, srv])

    if (services.isLoading) return <LoadingOverlay visible={true} />
    if (!srv || !serviceInfo || filtersList.isError) return <Navigate to="/" replace />

    let status_color = "gray";
    switch(serviceInfo.status){
        case "stop": status_color = "red"; break;
        case "active": status_color = "teal"; break;
    }

    const startService = async () => {
        setButtonLoading(true)
        await nfproxy.servicestart(serviceInfo.service_id).then(res => {
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
        nfproxy.servicedelete(serviceInfo.service_id).then(res => {
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
        
        await nfproxy.servicestop(serviceInfo.service_id).then(res => {
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
        <LoadingOverlay visible={filtersList.isLoading} />
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
                <ExceptionWarning service_id={srv} />
                <Space w="sm" />
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
                <Space w="md"/>
                <Tooltip label="Show logs" zIndex={0} color="cyan">
                    <ActionIcon color="cyan" size="lg" radius="md" onClick={()=>setOpenLogModal(true)} loading={buttonLoading} variant="filled">
                        <FiFileText size="20px" />
                    </ActionIcon>
                </Tooltip>
            </Box>
        </Box>
        {isMedium?null:<Space h="md" />}
        <Box className={isMedium?'center-flex':'center-flex-row'} style={{ justifyContent: "space-between"}} px="md" mt="lg">
            <Box className={isMedium?'center-flex':'center-flex-row'}>
                <Box className='center-flex'>
                    <Badge color="orange" radius="sm" size="md" variant="filled"><FaPencilAlt style={{ marginBottom: -2}} /> {serviceInfo.edited_packets}</Badge>
                    <Space w="xs" />
                    <Badge color="yellow" radius="sm" size="md" variant="filled"><FaFilter style={{ marginBottom: -2}} /> {serviceInfo.blocked_packets}</Badge>
                    <Space w="xs" />
                    <Badge color="violet" radius="sm" size="md" variant="filled"><TbPlugConnected style={{ marginBottom: -2}} size={13} /> {serviceInfo.n_filters}</Badge>
                </Box>
                {isMedium?<Space w="xs" />:<Space h="xs" />}
                <Badge color={serviceInfo.ip_int.match(regex_ipv4)?"cyan":"pink"} radius="sm" size="md" variant="filled" mr="xs">{serviceInfo.ip_int} on {serviceInfo.proto}</Badge>
            </Box>
            {isMedium?null:<Space h="xl" />}
            <Box className='center-flex'>
                <Tooltip label="Go back" zIndex={0} color="cyan">
                    <ActionIcon color="cyan"
                    onClick={() => navigate("/")} size="xl" radius="md" variant="filled"
                    aria-describedby="tooltip-back-id">
                        <FaArrowLeft size="25px" />
                    </ActionIcon>
                </Tooltip>
                <Space w="md"/>
                <Tooltip label="Stop service" zIndex={0} color="red">
                    <ActionIcon color="red" loading={buttonLoading}
                    onClick={stopService} size="xl" radius="md" variant="filled"
                    disabled={serviceInfo.status === "stop"}
                    aria-describedby="tooltip-stop-id">
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

        {filterCode.data?<>
            <Title order={3} style={{textAlign:"center"}} className="center-flex"><FaPython style={{ marginBottom: -3 }} size={30} /><Space w="xs" />Filter code</Title>
            <CodeHighlight code={filterCode.data} language="python" mt="lg" />
        </>: null}

        {(!filtersList.data || filtersList.data.length == 0)?<>
                <Space h="xl" />
                <Title className='center-flex' style={{textAlign:"center"}} order={3}>No filters found! Create some proxy filters, install the firegex client:<Space w="xs" /><Code mb={-4} >pip install -U fgex</Code></Title>
                <Space h="xs" />
                <Title className='center-flex' style={{textAlign:"center"}} order={3}>Read the documentation for more information<Space w="sm" /><DocsButton doc='nfproxy'/></Title>
                <Space h="xs" />
                <Title className='center-flex' style={{textAlign:"center"}} order={3}>Then create a new filter file with the following syntax and upload it here (using the button above)</Title>
            </>:<>{filtersList.data?.map( (filterInfo) => <PyFilterView filterInfo={filterInfo} key={filterInfo.name}/>)}</>
        }
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
        <ModalLog
            opened={openLogModal}
            close={()=>setOpenLogModal(false)}
            title={`Logs for service ${serviceInfo.name}`}
            data={logData.join("")}
        />
    </>
}
