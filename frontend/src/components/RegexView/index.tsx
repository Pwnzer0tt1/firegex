import { Text, Title, Badge, Space, ActionIcon, Tooltip, Box } from '@mantine/core';
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
  const [deleteTooltipOpened, setDeleteTooltipOpened] = useState(false);
  const [statusTooltipOpened, setStatusTooltipOpened] = useState(false);
  const clipboard = useClipboard({ timeout: 500 });
  const isMedium = isMediumScreen();

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

  return <Box className="firegex__regexview__box">
        <Box>
          <Box className='center-flex' style={{width: "100%"}}>
            <Box className="firegex__regexview__outer_regex_text">
              <Text className="firegex__regexview__regex_text" onClick={()=>{
                clipboard.copy(regex_expr)
                okNotify("Regex copied to clipboard!",`The regex '${regex_expr}' has been copied to the clipboard!`)
              }}>{regex_expr}</Text>
            </Box>
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
          </Box>
          <Box display="flex" mt="sm" ml="xs">
            <Badge size="md" color="yellow" variant="filled"><FaFilter style={{ marginBottom: -2}} /> {regexInfo.n_packets}</Badge>
            <Space w="xs" />
            <Badge size="md" color={regexInfo.active?"lime":"red"} variant="filled">{regexInfo.active?"ACTIVE":"DISABLED"}</Badge>
            <Space w="xs" />
            <Badge size="md" color={regexInfo.is_case_sensitive?"grape":"pink"} variant="filled">{regexInfo.is_case_sensitive?"Strict":"Loose"}</Badge>
            <Space w="xs" />
            <Badge size="md" color="blue" variant="filled">{mode_string}</Badge>
          </Box>
        </Box>
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
