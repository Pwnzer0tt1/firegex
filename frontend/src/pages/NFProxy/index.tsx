import { ActionIcon, Badge, Box, Code, LoadingOverlay, Space, ThemeIcon, Title, Tooltip } from '@mantine/core';
import { useEffect, useState } from 'react';
import { BsPlusLg } from "react-icons/bs";
import { useNavigate, useParams } from 'react-router-dom';
import ServiceRow from '../../components/NFProxy/ServiceRow';
import { errorNotify, getErrorMessage, isMediumScreen } from '../../js/utils';
import AddEditService from '../../components/NFProxy/AddEditService';
import { useQueryClient } from '@tanstack/react-query';
import { TbPlugConnected, TbReload } from 'react-icons/tb';
import { EXAMPLE_PYFILTER, nfproxy, nfproxyServiceQuery } from '../../components/NFProxy/utils';
import { FaFilter, FaPencilAlt, FaServer } from 'react-icons/fa';
import { MdUploadFile } from "react-icons/md";
import { notifications } from '@mantine/notifications';
import { useFileDialog } from '@mantine/hooks';
import { CodeHighlight } from '@mantine/code-highlight';
import { DocsButton } from '../../components/DocsButton';


export default function NFProxy({ children }: { children: any }) {

    const navigator = useNavigate()
    const [open, setOpen] = useState(false);
    const {srv} = useParams()
    const queryClient = useQueryClient()
    const isMedium = isMediumScreen()
    const services = nfproxyServiceQuery()
    const fileDialog = useFileDialog({
        accept: ".py",
        multiple: false,
        resetOnOpen: true,
        onChange: (files) => {
            if (files?.length??0 > 0)
                setFile(files![0])
        }
    });
    const [file, setFile] = useState<File | null>(null);
    useEffect(() => {
        if (!srv) return
        const service = services.data?.find(s => s.service_id === srv)
        if (!service) return
        if (file){
            console.log("Uploading code")
            const notify_id = notifications.show(
                {
                    title: "Uploading code",
                    message: `Uploading code for service ${service.name}`,
                    color: "blue",
                    icon: <MdUploadFile size={20} />,
                    autoClose: false,
                    loading: true,
                }
            )
            file.text()
            .then( code => nfproxy.setpyfilterscode(service?.service_id??"",code.toString()))
            .then( res => {
                if (!res){
                    notifications.update({
                        id: notify_id,
                        title: "Code uploaded",
                        message: `Successfully uploaded code for service ${service.name}`,
                        color: "green",
                        icon: <MdUploadFile size={20} />,
                        autoClose: 5000,
                        loading: false,
                    })
                }else{
                    notifications.update({
                        id: notify_id,
                        title: "Code upload failed",
                        message: `Error: ${res}`,
                        color: "red",
                        icon: <MdUploadFile size={20} />,
                        autoClose: 5000,
                        loading: false,
                    })
                }
            }).catch( err => {
                notifications.update({
                    id: notify_id,
                    title: "Code upload failed",
                    message: `Error: ${err}`,
                    color: "red",
                    icon: <MdUploadFile size={20} />,
                    autoClose: 5000,
                    loading: false,
                })
            }).finally(()=>{setFile(null)})  
        }
    }, [file])

    useEffect(()=> {
        if(services.isError)
            errorNotify("NFProxy Update failed!", getErrorMessage(services.error))
    },[services.isError])

    const closeModal = () => {setOpen(false);}

    return <>
    <Space h="sm" />
    <Box className={isMedium?'center-flex':'center-flex-row'}>
        <Title order={5} className="center-flex"><ThemeIcon radius="md" size="md" variant='filled' color='lime' ><TbPlugConnected size={20} /></ThemeIcon><Space w="xs" />Netfilter Proxy</Title>
        {isMedium?<Box className='flex-spacer' />:<Space h="sm" />}
        <Box className='center-flex' >
            {isMedium?"General stats:":null}
            <Space w="xs" />
            <Badge size="md" radius="sm" color="green" variant="filled"><FaServer style={{ marginBottom: -1, marginRight: 4}} />Services: {services.isLoading?0:services.data?.length}</Badge>
            <Space w="xs" />
            <Badge color="yellow" radius="sm" size="md" variant="filled"><FaFilter style={{ marginBottom: -2, marginRight: 4}} />{services.isLoading?0:services.data?.reduce((acc, s)=> acc+=s.blocked_packets, 0)}</Badge>
            <Space w="xs" />
            <Badge color="orange" radius="sm" size="md" variant="filled"><FaPencilAlt style={{ marginBottom: -2, marginRight: 4}} />{services.isLoading?0:services.data?.reduce((acc, s)=> acc+=s.edited_packets, 0)}</Badge>
            <Space w="xs" />
            <Badge size="md" radius="sm" color="violet" variant="filled"><TbPlugConnected style={{ marginBottom: -2, marginRight: 4}} size={13} />{services.isLoading?0:services.data?.reduce((acc, s)=> acc+=s.n_filters, 0)}</Badge>
            <Space w="xs" />
        </Box>
        {isMedium?null:<Space h="md" />}
        <Box className='center-flex' >
            { srv?
            <Tooltip label="Upload a new filter code" position='bottom' color="blue">
                <ActionIcon color="blue" size="lg" radius="md" variant="filled" onClick={fileDialog.open}>
                    <MdUploadFile size={18} />
                </ActionIcon>
            </Tooltip>      
            : <Tooltip label="Add a new service" position='bottom' color="blue">
                <ActionIcon color="blue" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled">
                    <BsPlusLg size={18} />
                </ActionIcon>
            </Tooltip>
        }
        <Space w="xs" />
            <Tooltip label="Refresh" position='bottom' color="indigo">
                <ActionIcon color="indigo" onClick={()=>queryClient.invalidateQueries(["nfproxy"])} size="lg" radius="md" variant="filled" loading={services.isFetching}>
                    <TbReload size={18} />
                </ActionIcon>
            </Tooltip>
            <Space w="xs" />
            <DocsButton doc="nfproxy" />
        </Box>
    </Box>
    <Space h="md" />
    <Box className="center-flex-row" style={{gap: 20}}>
        {srv?null:<>
            <LoadingOverlay visible={services.isLoading} />
            {(services.data && services.data?.length > 0)?services.data.map( srv => <ServiceRow service={srv} key={srv.service_id} onClick={()=>{
                navigator("/nfproxy/"+srv.service_id)
            }} />):<>
                <Box className='center-flex-row'>
                    <Space h="xl" />
                    <Title className='center-flex' style={{textAlign:"center"}} order={3}>Netfilter proxy is a simulated proxy written using python with a c++ core</Title>
                    <Space h="xs" />
                    <Title className='center-flex' style={{textAlign:"center"}} order={5}>Filters are created using a simple python syntax, infact the first you need to do is to install the firegex lib:<Space w="xs" /><Code mb={-4} >pip install -U fgex</Code></Title>
                    <Space h="xs" />
                    <Title className='center-flex' style={{textAlign:"center"}} order={5}>Then you can create a new service and write custom filters for the service</Title>
                    <Space h="lg" />
                    <Box className='center-flex' style={{gap: 20}}>
                        <Tooltip label="Add a new service" color="blue">
                            <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled">
                                <BsPlusLg size="20px" />
                            </ActionIcon>
                        </Tooltip>
                        <DocsButton doc="nfproxy" size="xl" />
                    </Box>
                </Box>
            </>}
        </>}
    </Box>
    {srv?children:null}
    {!srv?
        <AddEditService opened={open} onClose={closeModal} />:null
    }
    </>
}

