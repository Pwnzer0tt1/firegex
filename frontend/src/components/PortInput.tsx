import { NumberInput } from "@mantine/core"
import React, { useState } from "react"

export default function PortInput({ onInput, defaultValue, others, label, fullWidth }:
        { onInput?:React.FormEventHandler<HTMLInputElement>, defaultValue?:number, label?:React.ReactNode, others:any, fullWidth?:boolean }) {
    const [oldValue, setOldValue] = useState<string>(defaultValue?defaultValue.toString():"")
    return <NumberInput
        variant="filled"
        hideControls
        placeholder="80"
        label={label}
        min={1}
        max={65535}
        style={fullWidth?{}:{ width: "75px" }}
        onInput={(e) => {
            const value = parseInt((e.target as HTMLInputElement).value)
            if (value > 65535) {
                (e.target as HTMLInputElement).value = oldValue
            } else if (value < 1) {
                (e.target as HTMLInputElement).value = oldValue
            }else{
                (e.target as HTMLInputElement).value = value.toString()
            }
            setOldValue((e.target as HTMLInputElement).value)
            onInput?.(e)
        }}
        {...others}
    />
}