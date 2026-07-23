import { ActionIcon, Badge, Box, Divider, Menu, Space, Title, Tooltip, Card, Group, Button, Text } from '@mantine/core';
import { useState } from 'react';
import { FaPlay, FaStop, FaTrash } from 'react-icons/fa';
import { porthijack, Service } from '../utils';
import YesNoModal from '../../YesNoModal';
import { errorNotify, isMediumScreen, okNotify } from '../../../js/utils';
import { BsArrowRepeat, BsTrashFill } from 'react-icons/bs';
import { BiRename } from 'react-icons/bi';
import RenameForm from './RenameForm';
import ChangeDestination from './ChangeDestination';
import { useForm } from '@mantine/form';
import { MenuDropDownWithButton } from '../../MainLayout';
import { TbHexagon } from "react-icons/tb";

export default function ServiceRow({ service }:{ service:Service }) {

    let status_color = service.active ? "teal": "red"

    const [buttonLoading, setButtonLoading] = useState(false)
    const [deleteModal, setDeleteModal] = useState(false)
    const [renameModal, setRenameModal] = useState(false)
    const [changeDestModal, setChangeDestModal] = useState(false)
    const isMedium = isMediumScreen()

    const form = useForm({
        initialValues: { proxy_port:service.proxy_port },
        validate:{ proxy_port: (value) => (value > 0 && value < 65536)? null : "Invalid proxy port" }
    })

    const stopService = async () => {
        setButtonLoading(true)
        
        await porthijack.servicestop(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} stopped successfully!`,`The service on ${service.public_port} has been stopped!`)
            }else{
                errorNotify(`An error as occurred during the stopping of the service ${service.public_port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the stopping of the service ${service.public_port}`,`Error: ${err}`)
        })
        setButtonLoading(false);
    }

    const startService = async () => {
        setButtonLoading(true)
        await porthijack.servicestart(service.service_id).then(res => {
            if(!res){
                okNotify(`Service ${service.name} started successfully!`,`The service on ${service.public_port} has been started!`)
            }else{
                errorNotify(`An error as occurred during the starting of the service ${service.public_port}`,`Error: ${res}`)
            }
        }).catch(err => {
            errorNotify(`An error as occurred during the starting of the service ${service.public_port}`,`Error: ${err}`)
        })
        setButtonLoading(false)
    }

    const deleteService = () => {
        porthijack.servicedelete(service.service_id).then(res => {
            if (!res){
                okNotify("Service delete complete!",`The service ${service.name} has been deleted!`)
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
            style={{ 
                borderColor: 'var(--fourth_color)', 
                transition: 'border-color 0.2s ease',
                '&:hover': { borderColor: 'var(--mantine-color-dark-4)' } 
            }}
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
                                {service.active ? "ENABLED" : "DISABLED"}
                            </Badge>
                        </Group>
                        <Group gap="xs" mt={4}>
                            <Text size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
                                FROM {service.ip_src}:{service.public_port}
                            </Text>
                            <Text size="xs" c="dimmed" style={{ letterSpacing: 0.5 }}>
                                • TO {service.ip_dst}:{service.proxy_port} ON {service.proto.toUpperCase()}
                            </Text>
                        </Group>
                    </Box>
                </Group>
                
                <Group gap="xs" onClick={(e) => e.stopPropagation()}>
                    {service.active ? (
                        <Button variant="default" size="xs" leftSection={<FaStop size={10} />} onClick={stopService} loading={buttonLoading}>
                            Stop
                        </Button>
                    ) : (
                        <Button variant="default" size="xs" leftSection={<FaPlay size={10} />} onClick={startService} loading={buttonLoading}>
                            Start
                        </Button>
                    )}
                    
                    <Menu>
                        <Menu.Target>
                            <Button variant="default" size="xs" leftSection={<BsArrowRepeat size={10} />}>
                                Options
                            </Button>
                        </Menu.Target>
                        <Menu.Dropdown>
                            <Menu.Label>Actions</Menu.Label>
                            <Menu.Item leftSection={<BiRename size={14} />} onClick={()=>setRenameModal(true)}>Rename service</Menu.Item>
                            <Menu.Item leftSection={<BsArrowRepeat size={14} />} onClick={()=>setChangeDestModal(true)}>Change hijacking destination</Menu.Item>
                        </Menu.Dropdown>
                    </Menu>
                    
                    <Button variant="default" size="xs" leftSection={<FaTrash size={10} />} onClick={() => setDeleteModal(true)}>
                        Delete
                    </Button>
                </Group>
            </Group>
        </Card>

        <YesNoModal
            title='Are you sure to delete this service?'
            description={`You are going to delete the service '${service.public_port}', causing the stopping of the firewall and deleting all the regex associated. This will cause the shutdown of your service! ⚠️`}
            onClose={()=>setDeleteModal(false) }
            action={deleteService}
            opened={deleteModal}
        />
        <RenameForm
            onClose={()=>setRenameModal(false)}
            opened={renameModal}
            service={service}
        />
        <ChangeDestination
            onClose={()=>setChangeDestModal(false)}
            opened={changeDestModal}
            service={service}
        />
    </>
}
