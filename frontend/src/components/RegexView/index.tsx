import { Text, Title, Badge, Space, ActionIcon, Tooltip, Box, Card, Code, Group } from '@mantine/core';
import { useState } from 'react';
import { RegexFilter } from '../../js/models';
import { b64decode, errorNotify, isMediumScreen, okNotify } from '../../js/utils';
import { BsTrashFill } from "react-icons/bs"
import YesNoModal from '../YesNoModal';
import { FaPause, FaPlay } from 'react-icons/fa';
import { useClipboard } from '@mantine/hooks';
import { FaFilter } from "react-icons/fa";

import { nfregex } from '../NFRegex/utils';

function RegexView({ regexInfo }:{ regexInfo:RegexFilter }) {

  const mode_string = regexInfo.mode === "C"? "C -> S":
                      regexInfo.mode === "S"? "S -> C":
                      regexInfo.mode === "B"? "C <-> S": "🤔"

  let regex_expr = b64decode(regexInfo.regex);

  const [deleteModal, setDeleteModal] = useState(false);
  const clipboard = useClipboard({ timeout: 500 });

  const deleteRegex = () => {
    nfregex.regexdelete(regexInfo.id).then(res => {
      if(!res){
        okNotify(`Regex ${regex_expr} deleted successfully!`,`Regex '${regex_expr}' ID:${regexInfo.id} has been deleted!`)
      }else{
        errorNotify(`Regex ${regex_expr} deleation failed!`,`Error: ${res}`)
      }
    }).catch( err => errorNotify(`Regex ${regex_expr} deleation failed!`,`Error: ${err}`))
  }

  const changeRegexStatus = () => {
    (regexInfo.active?nfregex.regexdisable:nfregex.regexenable)(regexInfo.id).then(res => {
      if(!res){
        okNotify(`Regex ${regex_expr} ${regexInfo.active?"deactivated":"activated"} successfully!`,`Regex with id '${regexInfo.id}' has been ${regexInfo.active?"deactivated":"activated"}!`)
      }else{
        errorNotify(`Regex ${regex_expr} ${regexInfo.active?"deactivation":"activation"} failed!`,`Error: ${res}`)
      }
    }).catch( err => errorNotify(`Regex ${regex_expr} ${regexInfo.active?"deactivation":"activation"} failed!`,`Error: ${err}`))
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
        <Box style={{ flexGrow: 1, overflow: 'hidden' }}>
          <Tooltip label="Click to copy regex" position="top-start">
            <Code 
              block 
              color="dark.8" 
              style={{ 
                cursor: 'pointer', 
                overflowX: 'auto', 
                whiteSpace: 'pre-wrap', 
                wordBreak: 'break-all',
                fontSize: '1.1rem',
                padding: '12px 16px',
                borderRadius: '8px',
                border: '1px solid var(--fourth_color)',
                backgroundColor: 'rgba(0,0,0,0.2)'
              }}
              onClick={() => {
                clipboard.copy(regex_expr)
                okNotify("Regex copied to clipboard!", `The regex '${regex_expr}' has been copied to the clipboard!`)
              }}
            >
              {regex_expr}
            </Code>
          </Tooltip>
        </Box>

        <Group gap="sm" wrap="nowrap" ml="md">
          <Tooltip label={regexInfo.active ? "Deactivate" : "Activate"} color={regexInfo.active ? "orange" : "teal"}>
            <ActionIcon 
              color={regexInfo.active ? "orange" : "teal"} 
              onClick={changeRegexStatus} 
              size="xl" 
              radius="md" 
              variant="light"
            >
              {regexInfo.active ? <FaPause size={18} /> : <FaPlay size={18} />}
            </ActionIcon>
          </Tooltip>
          <Tooltip label="Delete regex" color="red">
            <ActionIcon 
              color="red" 
              onClick={() => setDeleteModal(true)} 
              size="xl" 
              radius="md" 
              variant="light"
            >
              <BsTrashFill size={18} />
            </ActionIcon>
          </Tooltip>
        </Group>
      </Group>

      <Group gap="sm" mt="md">
        <Badge size="md" color="yellow" variant="light" leftSection={<FaFilter size={12} style={{ marginTop: 2 }} />}>
          {regexInfo.n_packets} packets
        </Badge>
        <Badge size="md" color={regexInfo.active ? "lime" : "red"} variant="light">
          {regexInfo.active ? "ACTIVE" : "DISABLED"}
        </Badge>
        <Badge size="md" color={regexInfo.is_case_sensitive ? "grape" : "pink"} variant="light">
          {regexInfo.is_case_sensitive ? "Strict" : "Loose"}
        </Badge>
        <Badge size="md" color="blue" variant="light">
          {mode_string}
        </Badge>
      </Group>

      <YesNoModal
        title='Are you sure to delete this regex?'
        description={`You are going to delete the regex '${regex_expr}'.`}
        onClose={() => setDeleteModal(false)}
        action={deleteRegex}
        opened={deleteModal}
      />
    </Card>
  )
}

export default RegexView;
