import React, { useEffect, useState } from 'react';
import { ActionIcon, Badge } from '@mantine/core';
import style from "./Header.module.scss";
import { generalstats } from '../../js/utils';
import { GeneralStats, update_freq } from '../../js/models';
import { BsPlusLg } from "react-icons/bs"
import { AiFillHome } from "react-icons/ai"
import { useLocation, useNavigate } from 'react-router-dom';

function Header() {
  
  const [generalStats, setGeneralStats] = useState<GeneralStats>({closed:0, regex:0, services:0});
  const location = useLocation()

  const navigator = useNavigate()

  const updateInfo = () => {
    generalstats().then(res => {
      setGeneralStats(res)
      setTimeout(updateInfo, update_freq)
    }).catch(
      err =>{
        setTimeout(updateInfo, update_freq)}
    )
  }

  useEffect(updateInfo,[]);

  return <div id="header-page" className={style.header}>
        <div className={style.logo} >LOGO</div>
        <div className="flex-spacer" />
        <Badge color="green" size="lg" variant="filled">Services: {generalStats.services}</Badge>
        <Badge style={{marginLeft:"10px"}} size="lg" color="yellow" variant="filled">Filtered Connections: {generalStats.closed}</Badge>
        <Badge style={{marginLeft:"10px"}} size="lg" color="violet" variant="filled">Regexes: {generalStats.regex}</Badge>
        <div style={{marginLeft:"20px"}}></div>
        { location.pathname !== "/"?
            <ActionIcon color="teal" style={{marginRight:"10px"}}
              size="xl" radius="md" variant="filled"
              onClick={()=>navigator("/")}>
              <AiFillHome size="25px" />
            </ActionIcon>
        :null}
        <ActionIcon color="blue" size="xl" radius="md" variant="filled"><BsPlusLg size="20px" /></ActionIcon>
        <div style={{marginLeft:"40px"}}></div>
  </div>
}

export default Header;
