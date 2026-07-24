import { ActionIcon, Box, Code, LoadingOverlay, Space, Stack, Title, Tooltip, Card, Group, ThemeIcon } from '@mantine/core';
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
import TLSAssociationBadge from '../../components/TLSAssociationBadge';

export default function ServiceDetailsNFProxy() {

    const { srv } = useParams()
    const services = nfproxyServiceQuery()
    const serviceInfo = services.data?.find(s => s.service_id == srv)
    const filtersList = nfproxyServicePyfiltersQuery(srv ?? "")
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [editModal, setEditModal] = useState(false)
    const [buttonLoading, setButtonLoading] = useState(false)
    const queryClient = useQueryClient()
    const filterCode = nfproxyServiceFilterCodeQuery(srv ?? "")
    const navigate = useNavigate()
    const isMedium = isMediumScreen()
    const [openLogModal, setOpenLogModal] = useState(false)
    const [logData, logDataSetters] = useListState<string>([]);


    useEffect(() => {
        if (srv) {
            if (openLogModal) {
                logDataSetters.setState([])
                socketio.emit("nfproxy-outstream-join", { service: srv });
                socketio.on(`nfproxy-outstream-${srv}`, (data) => {
                    logDataSetters.append(data)
                });
            } else {
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
    switch (serviceInfo.status) {
        case "stop": status_color = "red"; break;
        case "active": status_color = "teal"; break;
    }

    const startService = async () => {
        setButtonLoading(true)
        await nfproxy.servicestart(serviceInfo.service_id).then(res => {
            if (!res) {
                okNotify(`Service ${serviceInfo.name} started successfully!`, `The service on ${serviceInfo.port} has been started!`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            } else {
                errorNotify(`An error as occurred during the starting of the service ${serviceInfo.port}`, `Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${serviceInfo.port}`, `Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const deleteService = () => {
        nfproxy.servicedelete(serviceInfo.service_id).then(res => {
            if (!res) {
                okNotify("Service delete complete!", `The service ${serviceInfo.name} has been deleted!`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            } else
                errorNotify("An error occurred while deleting a service", `Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while deleting a service", `Error: ${err}`)
        })
    }

    const stopService = async () => {
        setButtonLoading(true)

        await nfproxy.servicestop(serviceInfo.service_id).then(res => {
            if (!res) {
                okNotify(`Service ${serviceInfo.name} stopped successfully!`, `The service on ${serviceInfo.port} has been stopped!`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            } else {
                errorNotify(`An error as occurred during the stopping of the service ${serviceInfo.port}`, `Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${serviceInfo.port}`, `Error: ${err}`)
        })
        setButtonLoading(false);
    }

    return <>
        <Space h="sm" />
        <LoadingOverlay visible={filtersList.isLoading} />
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
                            <ActionIcon color="cyan" variant="subtle" radius="md" onClick={() => navigate("/nfproxy")}>
                                <FaArrowLeft size={16} />
                            </ActionIcon>
                        </Tooltip>
                        <MdDoubleArrow size={24} style={{ color: "var(--text-secondary)" }} />
                        <Title order={2} style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {serviceInfo.name}
                        </Title>
                    </Group>
                    <Group gap="sm" mt="md">
                        <ExceptionWarning service_id={srv} />
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
                            <Tooltip label="Packets blocked by this service's filters" position="bottom" color="yellow">
                                <Badge color="yellow" radius="sm" size="lg" variant="light" leftSection={<FaFilter size={12} style={{ marginTop: 2 }} />}>
                                    {serviceInfo.blocked_packets}
                                </Badge>
                            </Tooltip>
                            <Tooltip label="Packets mangled (modified) by this service's filters" position="bottom" color="orange">
                                <Badge color="orange" radius="sm" size="lg" variant="light" leftSection={<FaPencilAlt size={12} style={{ marginTop: 2 }} />}>
                                    {serviceInfo.edited_packets}
                                </Badge>
                            </Tooltip>
                            <Tooltip label="Number of Python filters attached to this service" position="bottom" color="violet">
                                <Badge color="violet" radius="sm" size="lg" variant="light" leftSection={<TbPlugConnected size={12} style={{ marginTop: 2 }} />}>
                                    {serviceInfo.n_filters}
                                </Badge>
                            </Tooltip>
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
                            <Tooltip label="Show logs" position="bottom" color="cyan">
                                <ActionIcon color="cyan" size="xl" radius="md" onClick={() => setOpenLogModal(true)} variant="light">
                                    <FiFileText size={18} />
                                </ActionIcon>
                            </Tooltip>
                            <MenuDropDownWithButton>
                                <Menu.Label><b>Service Tools</b></Menu.Label>
                                <Menu.Item leftSection={<IoSettingsSharp size={16} />} onClick={() => setEditModal(true)}>Service Settings</Menu.Item>
                                <Menu.Item leftSection={<BiRename size={16} />} onClick={() => setRenameModal(true)}>Change Name</Menu.Item>
                                <Divider />
                                <Menu.Label><b>Danger zone</b></Menu.Label>
                                <Menu.Item color="red" leftSection={<BsTrashFill size={16} />} onClick={() => setDeleteModal(true)}>Delete Service</Menu.Item>
                            </MenuDropDownWithButton>
                        </Group>
                    </Group>
                </Box>
            </Group>
        </Card>

        {filterCode.data ? <>
            <Group justify="center" gap="xs" mt="xl">
                <ThemeIcon radius="md" size="md" variant="light" color="yellow"><FaPython size={16} /></ThemeIcon>
                <Title order={3}>Filter code</Title>
            </Group>
            <Card withBorder radius="md" p={0} bg="transparent" style={{ borderColor: 'var(--fourth_color)', marginTop: '20px' }}>
                <CodeHighlight code={filterCode.data} language="python" style={{ backgroundColor: 'transparent' }} />
            </Card>
        </> : null}

        {(!filtersList.data || filtersList.data.length == 0) ? (
            <Stack align="center" gap="xs" py="xl">
                <Title order={3} ta="center">No filters found! Create some proxy filters, install the firegex client:<Space w="xs" /><Code mb={-4} >pip install -U fgex</Code></Title>
                <Title order={3} ta="center">Read the documentation for more information<Space w="sm" /><DocsButton doc='nfproxy' /></Title>
                <Title order={3} ta="center">Then create a new filter file with the following syntax and upload it here (using the button above)</Title>
            </Stack>
        ) : <Box mt="xs">{filtersList.data?.map((filterInfo) => <PyFilterView filterInfo={filterInfo} key={filterInfo.name} />)}</Box>
        }
        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${serviceInfo.port}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={() => setDeleteModal(false)}
            action={deleteService}
            opened={deleteModal}
        />
        <RenameForm
            onClose={() => setRenameModal(false)}
            opened={renameModal}
            service={serviceInfo}
        />
        <AddEditService
            opened={editModal}
            onClose={() => setEditModal(false)}
            edit={serviceInfo}
        />
        <ModalLog
            opened={openLogModal}
            close={() => setOpenLogModal(false)}
            title={`Logs for service ${serviceInfo.name}`}
            data={logData.join("")}
        />
    </>
}
