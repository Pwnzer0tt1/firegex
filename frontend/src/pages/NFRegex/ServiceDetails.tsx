import { ActionIcon, Box, Grid, LoadingOverlay, Space, Stack, Title, Tooltip, Card, Group } from '@mantine/core';
import { Navigate, useNavigate, useParams } from 'react-router';
import RegexView from '../../components/RegexView';
import AddNewRegex from '../../components/AddNewRegex';
import { BsPlusLg } from "react-icons/bs";
import { nfregexServiceQuery, nfregexServiceRegexesQuery, Service } from '../../components/NFRegex/utils';
import { Badge, Divider, Menu } from '@mantine/core';
import { useState } from 'react';
import { FaFilter, FaPlay, FaStop } from 'react-icons/fa';
import { nfregex, serviceQueryKey } from '../../components/NFRegex/utils';
import { MdDoubleArrow, MdDownload, MdUpload } from "react-icons/md"
import YesNoModal from '../../components/YesNoModal';
import { errorNotify, isMediumScreen, okNotify, regex_ipv4, getapi, postapi } from '../../js/utils';
import { BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi'
import RenameForm from '../../components/NFRegex/ServiceRow/RenameForm';
import { MenuDropDownWithButton } from '../../components/MainLayout';
import { useQueryClient } from '@tanstack/react-query';
import { FaArrowLeft } from "react-icons/fa";
import { VscRegex } from 'react-icons/vsc';
import { IoSettingsSharp } from 'react-icons/io5';
import AddEditService from '../../components/NFRegex/AddEditService';
import TLSAssociationBadge from '../../components/TLSAssociationBadge';

export default function ServiceDetailsNFRegex() {

    const {srv} = useParams()
    const [open, setOpen] = useState(false)
    const services = nfregexServiceQuery()
    const serviceInfo = services.data?.find(s => s.service_id == srv)
    const regexesList = nfregexServiceRegexesQuery(srv??"")
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [editModal, setEditModal] = useState(false)
    const [buttonLoading, setButtonLoading] = useState(false)
    const queryClient = useQueryClient()
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
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
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
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
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
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${serviceInfo.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${serviceInfo.port}`,`Error: ${err}`)
        })
        setButtonLoading(false);
    }

    return <>
        <Space h="sm" />
        <LoadingOverlay visible={regexesList.isLoading} />
        <Card
            withBorder
            shadow="md"
            radius="md"
            p="xl"
            mb="xl"
            bg="var(--third_color)"
            style={{ borderColor: 'var(--fourth_color)', overflow: "visible" }} // Allows dropdowns to overflow outside
        >
            <Group justify="space-between" align="center" wrap={isMedium ? "nowrap" : "wrap"} gap="xl">
                <Box>
                    <Group gap="xs" wrap="nowrap" align="center">
                        <Tooltip label="Go back" position="top">
                            <ActionIcon color="cyan" variant="subtle" radius="md" onClick={() => navigate("/nfregex")}>
                                <FaArrowLeft size={16} />
                            </ActionIcon>
                        </Tooltip>
                        <MdDoubleArrow size={24} style={{ color: "var(--text-secondary)" }} />
                        <Title order={2} style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {serviceInfo.name}
                        </Title>
                    </Group>
                    <Group gap="sm" mt="md">
                        <Badge color={status_color} radius="sm" size="lg" variant="light">{serviceInfo.status}</Badge>
                        <Badge size="lg" gradient={{ from: 'indigo', to: 'cyan' }} variant="gradient" radius="sm">
                            :{serviceInfo.port}
                        </Badge>
                        {serviceInfo.target_type === 'tls' && (
                            <TLSAssociationBadge tlsStreamId={serviceInfo.tls_stream_id} size="lg" />
                        )}
                        <Badge color={serviceInfo.ip_int.match(regex_ipv4) ? "cyan" : "pink"} radius="sm" size="lg" variant="light">
                            {serviceInfo.target_type === 'tls' ? 'decrypted traffic to ' : ''}{serviceInfo.ip_int} on {serviceInfo.proto}
                        </Badge>
                    </Group>
                </Box>
                
                <Box style={{ flexGrow: 1, minWidth: isMedium ? 'auto' : '100%' }}>
                    <Group gap="xl" justify={isMedium ? "flex-start" : "space-between"}>
                        <Group gap="xs">
                            <Badge color="yellow" radius="sm" size="lg" variant="light" leftSection={<FaFilter size={12} style={{ marginTop: 2 }} />}>
                                {serviceInfo.n_packets}
                            </Badge>
                            <Badge color="violet" radius="sm" size="lg" variant="light" leftSection={<VscRegex size={12} style={{ marginTop: 2 }} />}>
                                {serviceInfo.n_regex}
                            </Badge>
                        </Group>

                        <Group gap="sm" justify="flex-end" style={{ flexGrow: 1 }}>
                            <Tooltip label={serviceInfo.status === "stop" ? "Cannot stop" : "Stop service"} position="bottom" color="red">
                                <ActionIcon color="red" loading={buttonLoading} onClick={stopService} size="xl" radius="md" variant="light" disabled={serviceInfo.status === "stop"}>
                                    <FaStop size={18} />
                                </ActionIcon>
                            </Tooltip>
                            <Tooltip label={!["stop", "pause"].includes(serviceInfo.status) ? "Cannot start" : "Start service"} position="bottom" color="teal">
                                <ActionIcon color="teal" size="xl" radius="md" onClick={startService} loading={buttonLoading} variant="light" disabled={!["stop", "pause"].includes(serviceInfo.status)}>
                                    <FaPlay size={18} />
                                </ActionIcon>
                            </Tooltip>
                            <MenuDropDownWithButton>
                                <Menu.Label><b>Service Tools</b></Menu.Label>
                                <Menu.Item leftSection={<IoSettingsSharp size={16} />} onClick={() => setEditModal(true)}>Service Settings</Menu.Item>
                                <Menu.Item leftSection={<BiRename size={16} />} onClick={() => setRenameModal(true)}>Change Name</Menu.Item>
                                <Divider />
                                <Menu.Label><b>Rules Management</b></Menu.Label>
                                <Menu.Item leftSection={<MdDownload size={16} />} onClick={() => {
                                    getapi(`nfregex/services/${serviceInfo.service_id}/export`).then(data => {
                                        const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                                        const url = URL.createObjectURL(blob);
                                        const a = document.createElement("a");
                                        a.href = url;
                                        a.download = `firegex_nfregex_${serviceInfo.name}_backup.json`;
                                        document.body.appendChild(a);
                                        a.click();
                                        document.body.removeChild(a);
                                        URL.revokeObjectURL(url);
                                        okNotify("Exported", "Regex rules have been exported.");
                                    }).catch(err => errorNotify("Export Failed", err.toString()));
                                }}>Export Rules</Menu.Item>
                                <Menu.Item leftSection={<MdUpload size={16} />} onClick={() => {
                                    const input = document.createElement('input');
                                    input.type = 'file';
                                    input.accept = '.json';
                                    input.onchange = (e) => {
                                        const file = (e.target as HTMLInputElement).files?.[0];
                                        if (!file) return;
                                        const reader = new FileReader();
                                        reader.onload = (e) => {
                                            try {
                                                const data = JSON.parse(e.target?.result as string);
                                                postapi(`nfregex/services/${serviceInfo.service_id}/import`, data).then(() => {
                                                    okNotify("Imported", "Regex rules have been imported successfully.");
                                                    queryClient.invalidateQueries({ queryKey: serviceQueryKey });
                                                    queryClient.invalidateQueries({ queryKey: ["nfregex-service-regexes", serviceInfo.service_id] });
                                                }).catch(err => errorNotify("Import Failed", err.toString()));
                                            } catch (err: any) {
                                                errorNotify("Invalid JSON", err.toString());
                                            }
                                        };
                                        reader.readAsText(file);
                                    };
                                    input.click();
                                }}>Import Rules</Menu.Item>
                                <Divider />
                                <Menu.Label><b>Danger zone</b></Menu.Label>
                                <Menu.Item color="red" leftSection={<BsTrashFill size={16} />} onClick={() => setDeleteModal(true)}>Delete Service</Menu.Item>
                            </MenuDropDownWithButton>
                        </Group>
                    </Group>
                </Box>
            </Group>
        </Card>
        {(!regexesList.data || regexesList.data.length == 0) ? (
            <Stack align="center" gap="xl" py="xl">
                <Title order={3} ta="center">No regex found for this service! Add one by clicking the "+" buttons</Title>
                <Tooltip label="Add a new regex" zIndex={0} color="blue">
                    <ActionIcon color="blue" onClick={()=>setOpen(true)} size="xl" radius="md" variant="filled"
                     aria-describedby="tooltip-AddRegex-id"><BsPlusLg size="20px" /></ActionIcon>
                </Tooltip>
            </Stack>
        ) : (
            <Grid mt="xs">
                {regexesList.data?.map( (regexInfo) => <Grid.Col key={regexInfo.id} span={{ lg:6, xs: 12 }}><RegexView regexInfo={regexInfo} /></Grid.Col>)}
            </Grid>
        )}

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
