import { Footer, Space } from '@mantine/core';
import image from "./pwnzer0tt1.svg"

import style from "./index.module.scss";
import { Link } from 'react-router-dom';

function FooterPage() {
  return <Footer id="footer" height={70} className={style.footer}>
        <img src={image} width={25} height={25} /> <Space w="xs" />Made by <div style={{marginLeft:"5px"}} /> <Link to="https://pwnzer0tt1.it">Pwnzer0tt1</Link> <Space w="xs" /> <img src={image} width={25} height={25} /> 
  </Footer>
}

export default FooterPage;
