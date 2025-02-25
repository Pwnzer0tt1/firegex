import { Text, Badge, Space, ActionIcon, Tooltip, Box } from '@mantine/core';
import { useState } from 'react';
import { PyFilter } from '../../js/models';
import { errorNotify, isMediumScreen, okNotify } from '../../js/utils';
import { FaPause, FaPlay } from 'react-icons/fa';
import { FaFilter } from "react-icons/fa";
import { nfproxy } from '../NFProxy/utils';
import { FaPencilAlt } from 'react-icons/fa';

export default function PyFilterView({ filterInfo }:{ filterInfo:PyFilter }) {

  const [statusTooltipOpened, setStatusTooltipOpened] = useState(false);
  const isMedium = isMediumScreen()

  const changeRegexStatus = () => {
    (filterInfo.active?nfproxy.pyfilterdisable:nfproxy.pyfilterenable)(filterInfo.name).then(res => {
      if(!res){
        okNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivated":"activated"} successfully!`,`Filter '${filterInfo.name}' has been ${filterInfo.active?"deactivated":"activated"}!`)
      }else{
        errorNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivation":"activation"} failed!`,`Error: ${res}`)
      }
    }).catch( err => errorNotify(`Filter ${filterInfo.name} ${filterInfo.active?"deactivation":"activation"} failed!`,`Error: ${err}`))
  }

  return <Box my="sm" display="flex" style={{alignItems:"center"}}>
      
      <Text className="firegex__regexview__pyfilter_text" style={{ width: "100%", alignItems: "center"}} display="flex" >
      <Badge size="sm" radius="lg" mr="sm" color={filterInfo.active?"lime":"red"} variant="filled" />
        {filterInfo.name}
        <Box className='flex-spacer' />
        <Space w="xs" />
        {isMedium?<>
          <Badge size="md" radius="md" color="yellow" variant="filled"><FaFilter style={{ marginBottom: -2, marginRight: 2}} /> {filterInfo.blocked_packets}</Badge>
          <Space w="xs" />
          <Badge size="md" radius="md" color="orange" variant="filled"><FaPencilAlt style={{ marginBottom: -1, marginRight: 2}} /> {filterInfo.edited_packets}</Badge>
          <Space w="lg" />
        </>:null}
        <Tooltip label={filterInfo.active?"Deactivate":"Activate"} zIndex={0} color={filterInfo.active?"orange":"teal"} opened={statusTooltipOpened}>
          <ActionIcon color={filterInfo.active?"orange":"teal"} onClick={changeRegexStatus} size="lg" radius="md" variant="filled"
          onFocus={() => setStatusTooltipOpened(false)} onBlur={() => setStatusTooltipOpened(false)}
          onMouseEnter={() => setStatusTooltipOpened(true)} onMouseLeave={() => setStatusTooltipOpened(false)}
          >{filterInfo.active?<FaPause size="20px" />:<FaPlay size="20px" />}</ActionIcon>
        </Tooltip>
      </Text>

  </Box>
}
