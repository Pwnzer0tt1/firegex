import { Footer } from '@mantine/core';
import React from 'react';

import style from "./index.module.scss";

function FooterPage() {
  return <Footer id="footer" height={70} className={style.footer}>
        Made by Pwnzer0tt1
  </Footer>
}

export default FooterPage;
