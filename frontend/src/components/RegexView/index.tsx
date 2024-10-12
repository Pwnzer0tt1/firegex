import { Grid, Text, Title, Badge, Space, ActionIcon, Tooltip, Box } from '@mantine/core';
import { useState } from 'react';
import { RegexFilter } from '../../js/models';
import { b64decode, errorNotify, getapiobject, okNotify } from '../../js/utils';
import { BsTrashFill } from "react-icons/bs"
import YesNoModal from '../YesNoModal';
import FilterTypeSelector from '../FilterTypeSelector';
import { FaPause, FaPlay } from 'react-icons/fa';
import { useClipboard } from '@mantine/hooks';


function RegexView({ regexInfo }:{ regexInfo:RegexFilter }) {

  const mode_string = regexInfo.mode === "C"? "C -> S":
                      regexInfo.mode === "S"? "S -> C":
                      regexInfo.mode === "B"? "S <-> C": "🤔"

  let regex_expr = b64decode(regexInfo.regex);

  const [deleteModal, setDeleteModal] = useState(false);
  const [deleteTooltipOpened, setDeleteTooltipOpened] = useState(false);
  const [statusTooltipOpened, setStatusTooltipOpened] = useState(false);
  const clipboard = useClipboard({ timeout: 500 });

  const deleteRegex = () => {
    getapiobject().regexdelete(regexInfo.id).then(res => {
      if(!res){
        okNotify(`Regex ${regex_expr} deleted successfully!`,`Regex '${regex_expr}' ID:${regexInfo.id} has been deleted!`)
      }else{
        errorNotify(`Regex ${regex_expr} deleation failed!`,`Error: ${res}`)
      }
    }).catch( err => errorNotify(`Regex ${regex_expr} deleation failed!`,`Error: ${err}`))
  }

  const changeRegexStatus = () => {
    (regexInfo.active?getapiobject().regexdisable:getapiobject().regexenable)(regexInfo.id).then(res => {
      if(!res){
        okNotify(`Regex ${regex_expr} ${regexInfo.active?"deactivated":"activated"} successfully!`,`Regex '${regex_expr}' ID:${regexInfo.id} has been ${regexInfo.active?"deactivated":"activated"}!`)
      }else{
        errorNotify(`Regex ${regex_expr} ${regexInfo.active?"deactivation":"activation"} failed!`,`Error: ${res}`)
      }
    }).catch( err => errorNotify(`Regex ${regex_expr} ${regexInfo.active?"deactivation":"activation"} failed!`,`Error: ${err}`))
  }

  return <Box className="firegex__regexview__box">
        <Grid>
          <Grid.Col span={2} className="center-flex">
            <Title order={4}>Regex:</Title> 
          </Grid.Col>
          <Grid.Col span={8}>
            <Box className="firegex__regexview__outer_regex_text">
              <Text className="firegex__regexview__regex_text" onClick={()=>{
                clipboard.copy(regex_expr)
                okNotify("Regex copied to clipboard!",`The regex '${regex_expr}' has been copied to the clipboard!`)
              }}>{regex_expr}</Text>
            </Box>
          </Grid.Col>
          <Grid.Col span={2} className='center-flex'>
            <Space w="xs" />
            <Tooltip label={regexInfo.active?"Deactivate":"Activate"} zIndex={0} color={regexInfo.active?"orange":"teal"} opened={statusTooltipOpened}>
              <ActionIcon color={regexInfo.active?"orange":"teal"} onClick={changeRegexStatus} size="xl" radius="md" variant="filled"
               onFocus={() => setStatusTooltipOpened(false)} onBlur={() => setStatusTooltipOpened(false)}
               onMouseEnter={() => setStatusTooltipOpened(true)} onMouseLeave={() => setStatusTooltipOpened(false)}
              >{regexInfo.active?<FaPause size="20px" />:<FaPlay size="20px" />}</ActionIcon>
            </Tooltip>
            <Space w="xs" />
            <Tooltip label="Delete regex" zIndex={0} color="red" opened={deleteTooltipOpened} >
              <ActionIcon color="red" onClick={()=>setDeleteModal(true)} size="xl" radius="md" variant="filled"
               onFocus={() => setDeleteTooltipOpened(false)} onBlur={() => setDeleteTooltipOpened(false)}
               onMouseEnter={() => setDeleteTooltipOpened(true)} onMouseLeave={() => setDeleteTooltipOpened(false)}
              ><BsTrashFill size={22} /></ActionIcon>
            </Tooltip>

            </Grid.Col>
          <Grid.Col className='center-flex' span={12}>
            <Box className='center-flex-row'>
              <FilterTypeSelector 
                  size="md"
                  color="gray"
                  disabled
                  value={regexInfo.is_blacklist?"blacklist":"whitelist"}
              />
              <Space h="md" />
              <Box className='center-flex'>
                <Badge size="md" color="cyan" variant="filled">Service: {regexInfo.service_id}</Badge>
                <Space w="xs" />
                <Badge size="md" color={regexInfo.active?"lime":"red"} variant="filled">{regexInfo.active?"ACTIVE":"DISABLED"}</Badge>
                <Space w="xs" />
                <Badge size="md" color="gray" variant="filled">ID: {regexInfo.id}</Badge>
                
              </Box>
            </Box>
            <Box className='flex-spacer' />
            <Box className='center-flex-row'>
              <Badge size="md" color={regexInfo.is_case_sensitive?"grape":"pink"} variant="filled">Case: {regexInfo.is_case_sensitive?"SENSIIVE":"INSENSITIVE"}</Badge>
              <Space h="xs" />
              <Badge size="md" color="yellow" variant="filled">Packets filtered: {regexInfo.n_packets}</Badge>
              <Space h="xs" />
              <Badge size="md" color="blue" variant="filled">Mode: {mode_string}</Badge>
            </Box>
          </Grid.Col>
        </Grid>
        <YesNoModal
            title='Are you sure to delete this regex?'
            description={`You are going to delete the regex '${regex_expr}'.`}
            onClose={()=>setDeleteModal(false)}
            action={deleteRegex}
            opened={deleteModal}
        />
        
  </Box>
}

export default RegexView;
