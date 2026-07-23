import { ActionIcon, Badge, Box, Divider, Menu, Space, Title, Tooltip, Card, Group, Button, Text } from '@mantine/core';
import { useState } from 'react';
import { FaPlay, FaStop, FaTrash } from 'react-icons/fa';
import { nfproxy, Service, serviceQueryKey } from '../utils';
import YesNoModal from '../../YesNoModal';
import { errorNotify, isMediumScreen, okNotify, regex_ipv4 } from '../../../js/utils';
import { BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi';
import RenameForm from './RenameForm';
import { MenuDropDownWithButton } from '../../MainLayout';
import { useQueryClient } from '@tanstack/react-query';
import { TbPlugConnected, TbShieldLock, TbHexagon } from "react-icons/tb";
import { FaFilter } from "react-icons/fa";
import { IoSettingsSharp } from 'react-icons/io5';
import AddEditService from '../AddEditService';
import { FaPencilAlt } from "react-icons/fa";
import { ExceptionWarning } from '../ExceptionWarning';
import { MdChevronRight } from "react-icons/md";
import TLSAssociationBadge from '../../TLSAssociationBadge';


export default function ServiceRow({ service, onClick }:{ service:Service, onClick?:()=>void }) {

    let status_color = "gray";
    switch(service.status){
        case "stop": status_color = "red"; break;
        case "active": status_color = "teal"; break;
    }

    const queryClient = useQueryClient()
    const [buttonLoading, setButtonLoading] = useState(false)
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [editModal, setEditModal] = useState(false)
    const isMedium = isMediumScreen()

    const stopService = async () => {
        setButtonLoading(true)
        
        await nfproxy.servicestop(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} stopped successfully!`,`The service on ${service.port} has been stopped!`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${service.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${service.port}`,`Error: ${err}`)
        })
        setButtonLoading(false);
    }

    const startService = async () => {
        setButtonLoading(true)
        await nfproxy.servicestart(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} started successfully!`,`The service on ${service.port} has been started!`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }else{
                errorNotify(`An error as occurred during the starting of the service ${service.port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${service.port}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const deleteService = () => {
        nfproxy.servicedelete(service.service_id).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${service.name} has been deleted!`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }else
                errorNotify("An error occurred while deleting a service",`Error: ${res}`)
        }).catch(err => {
            errorNotify("An error occurred while deleting a service",`Error: ${err}`)
        })
        
    }

    return <>
        <Card
            withBorder
            radius="md"
            p="md"
            w="100%"
            bg="transparent"
            className="firegex__clickable_row"
            style={{ borderColor: 'var(--fourth_color)' }}
            onClick={onClick}
        >
            <Group justify="space-between" align="center" wrap={isMedium ? "nowrap" : "wrap"}>
                <Group wrap="nowrap" align="flex-start">
                    <Box style={{ 
                        width: 42, 
                        height: 42, 
                        borderRadius: 8, 
                        backgroundColor: status_color === 'teal' ? 'rgba(32, 201, 151, 0.1)' : 'rgba(250, 82, 82, 0.1)', 
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'center',
                        color: status_color === 'teal' ? 'var(--mantine-color-teal-filled)' : 'var(--mantine-color-red-filled)'
                    }}>
                        <TbHexagon size={24} />
                    </Box>
                    <Box>
                        <Group gap="xs" align="center">
                            <Text fw={600} size="md">{service.name}</Text>
                            <Badge color={status_color} variant="light" size="xs" radius="sm">
                                {service.status.toUpperCase()}
                            </Badge>
                            {service.target_type === 'tls' && <TLSAssociationBadge tlsStreamId={service.tls_stream_id} />}
                        </Group>
                        <Group gap="xs" mt={4}>
                            <Text size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
                                PORT: :{service.port}
                            </Text>
                            <Text size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
                                • {service.target_type === 'tls' ? 'decrypted traffic to ' : ''}{service.ip_int} ON {service.proto.toUpperCase()}
                            </Text>
                        </Group>
                    </Box>
                </Group>
                
                <Group gap="xs" wrap="nowrap">
                    <Group gap="xs" onClick={(e) => e.stopPropagation()}>
                        <ExceptionWarning service_id={service.service_id} />
                        {service.status === "stop" ? (
                            <Button variant="default" size="xs" leftSection={<FaPlay size={10} />} onClick={startService} loading={buttonLoading}>
                                Start
                            </Button>
                        ) : (
                            <Button variant="default" size="xs" leftSection={<FaStop size={10} />} onClick={stopService} loading={buttonLoading}>
                                Stop
                            </Button>
                        )}

                        <Menu>
                            <Menu.Target>
                                <Button variant="default" size="xs" leftSection={<IoSettingsSharp size={10} />}>
                                    Options
                                </Button>
                            </Menu.Target>
                            <Menu.Dropdown>
                                <Menu.Label>Actions</Menu.Label>
                                <Menu.Item leftSection={<BiRename size={14} />} onClick={() => setRenameModal(true)}>Rename Service</Menu.Item>
                                <Menu.Item leftSection={<IoSettingsSharp size={14} />} onClick={() => setEditModal(true)}>Settings</Menu.Item>
                            </Menu.Dropdown>
                        </Menu>

                        <Button variant="default" size="xs" leftSection={<FaTrash size={10} />} onClick={() => setDeleteModal(true)}>
                            Delete
                        </Button>
                    </Group>
                    <Tooltip label="View details" position="left">
                        <Box style={{ display: 'flex', alignItems: 'center', color: 'var(--text-secondary)' }}>
                            <MdChevronRight size={22} />
                        </Box>
                    </Tooltip>
                </Group>
            </Group>
        </Card>
        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${service.port}', causing the stopping of the firewall and deleting all the filters associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
        <RenameForm
            onClose={()=>setRenameModal(false)}
            opened={renameModal}
            service={service}
        />
        <AddEditService
            opened={editModal}
            onClose={()=>setEditModal(false)}
            edit={service}
        />
    </>
}
