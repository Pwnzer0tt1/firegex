import { TextInput } from '@mantine/core';
import React from 'react';
import { RegexFilter } from '../../js/models';
import { getHumanReadableRegex } from '../../js/utils';

import style from "./RegexView.module.scss";


function RegexView({ regexInfo }:{ regexInfo:RegexFilter }) {
  return <div className={style.box}>
        <TextInput
            disabled
            value={getHumanReadableRegex(regexInfo.regex)}
        />
        
  </div>
}

export default RegexView;
