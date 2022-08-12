import React from 'react';
import style from "./index.module.scss";

const InlineEdit = ({ value, setValue, ...others }:{ value:string, setValue: (s:string)=>void}) => {
  return (
    <span
      role="textbox"
      contentEditable
      className={style.click_to_edit}
      aria-label="Field name"
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === "Escape") {
          event.target.blur();
        }
      }}
      onBlur={(event) => {
        setValue((event.target as HTMLSpanElement).textContent ?? "");
      }}
      {...others}
    />
  )
}

export default InlineEdit;
