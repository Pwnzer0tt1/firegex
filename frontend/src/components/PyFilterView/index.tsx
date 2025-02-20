import { Text, Badge, Space, ActionIcon, Tooltip, Box } from '@mantine/core';
import { useState } from 'react';
import { PyFilter } from '../../js/models';
import { errorNotify, okNotify } from '../../js/utils';
import { FaPause, FaPlay } from 'react-icons/fa';
import { FaFilter } from "react-icons/fa";
import { nfproxy } from '../NFProxy/utils';
import { FaPencilAlt } from 'react-icons/fa';

export default function PyFilterView({ filterInfo }:{ filterInfo:PyFilter }) {

  const [deleteTooltipOpened, setDeleteTooltipOpened] = useState(false);
  const [statusTooltipOpened, setStatusTooltipOpened] = useState(false);

  const changeRegexStatus = () => {
    (filterInfo.active?nfproxy.pyfilterdisable:nfproxy.pyfilterenable)(filterInfo.filter_id).then(res => {
      if(!res){
        okNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivated":"activated"} successfully!`,`Filter with id '${filterInfo.filter_id}' has been ${filterInfo.active?"deactivated":"activated"}!`)
      }else{
        errorNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivation":"activation"} failed!`,`Error: ${res}`)
      }
    }).catch( err => errorNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivation":"activation"} failed!`,`Error: ${err}`))
  }

  return <Box className="firegex__regexview__box">
        <Box>
          <Box className='center-flex' style={{width: "100%"}}>
            <Box className="firegex__regexview__outer_regex_text">
              <Text className="firegex__regexview__regex_text">{filterInfo.name}</Text>
            </Box>
            <Space w="xs" />
            <Tooltip label={filterInfo.active?"Deactivate":"Activate"} zIndex={0} color={filterInfo.active?"orange":"teal"} opened={statusTooltipOpened}>
              <ActionIcon color={filterInfo.active?"orange":"teal"} onClick={changeRegexStatus} size="xl" radius="md" variant="filled"
              onFocus={() => setStatusTooltipOpened(false)} onBlur={() => setStatusTooltipOpened(false)}
              onMouseEnter={() => setStatusTooltipOpened(true)} onMouseLeave={() => setStatusTooltipOpened(false)}
              >{filterInfo.active?<FaPause size="20px" />:<FaPlay size="20px" />}</ActionIcon>
            </Tooltip>
          </Box>
          <Box display="flex" mt="sm" ml="xs">
            <Badge size="md" color="yellow" variant="filled"><FaFilter style={{ marginBottom: -2}} /> {filterInfo.blocked_packets}</Badge>
            <Space w="xs" />
            <Badge size="md" color="orange" variant="filled"><FaPencilAlt size={18} /> {filterInfo.edited_packets}</Badge>
            <Space w="xs" />
            <Badge size="md" color={filterInfo.active?"lime":"red"} variant="filled">{filterInfo.active?"ACTIVE":"DISABLED"}</Badge>
            
          </Box>
        </Box>
        
  </Box>
}
