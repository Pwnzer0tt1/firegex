import { Text, Badge, Space, ActionIcon, Tooltip, Box, Card, Group } from '@mantine/core';
import { useState } from 'react';
import { PyFilter } from '../../js/models';
import { errorNotify, isMediumScreen, okNotify } from '../../js/utils';
import { FaPause, FaPlay } from 'react-icons/fa';
import { FaFilter } from "react-icons/fa";
import { nfproxy } from '../NFProxy/utils';
import { FaPencilAlt } from 'react-icons/fa';

export default function PyFilterView({ filterInfo }:{ filterInfo:PyFilter }) {

  const isMedium = isMediumScreen()

  const changeRegexStatus = () => {
    (filterInfo.active?nfproxy.pyfilterdisable:nfproxy.pyfilterenable)(filterInfo.service_id, filterInfo.name).then(res => {
      if(!res){
        okNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivated":"activated"} successfully!`,`Filter '${filterInfo.name}' has been ${filterInfo.active?"deactivated":"activated"}!`)
      }else{
        errorNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivation":"activation"} failed!`,`Error: ${res}`)
      }
    }).catch( err => errorNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivation":"activation"} failed!`,`Error: ${err}`))
  }

  return (
    <Card 
      withBorder 
      shadow="sm" 
      radius="md" 
      p="sm" 
      mb="sm"
      bg="transparent"
      style={{ borderColor: 'var(--fourth_color)', transition: 'border-color 0.2s ease' }}
    >
      <Group justify="space-between" align="center" wrap="nowrap">
        <Group gap="sm" align="center">
          <Badge size="xs" circle color={filterInfo.active ? "lime" : "red"} variant="filled" />
          <Text fw={600} style={{ fontFamily: 'monospace' }}>{filterInfo.name}</Text>
        </Group>

        <Group gap="xs" wrap="nowrap">
          <Badge size="sm" color="yellow" variant="light" leftSection={<FaFilter size={10} style={{ marginTop: 2 }} />}>
            {filterInfo.blocked_packets}
          </Badge>
          <Badge size="sm" color="orange" variant="light" leftSection={<FaPencilAlt size={10} style={{ marginTop: 2 }} />}>
            {filterInfo.edited_packets}
          </Badge>
          <Space w="xs" />
          <Tooltip label={filterInfo.active ? "Deactivate" : "Activate"} color={filterInfo.active ? "orange" : "teal"}>
            <ActionIcon 
              color={filterInfo.active ? "orange" : "teal"} 
              onClick={changeRegexStatus} 
              size="lg" 
              radius="md" 
              variant="light"
            >
              {filterInfo.active ? <FaPause size={16} /> : <FaPlay size={16} />}
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>
    </Card>
  )
}
