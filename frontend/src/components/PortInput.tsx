import { NumberInput, NumberInputProps } from "@mantine/core"
import React, { useState } from "react"

interface PortInputProps extends NumberInputProps {
    fullWidth?: boolean
}

const PortInput =  React.forwardRef<HTMLInputElement, PortInputProps>( (props, ref) => {
    const [oldValue, setOldValue] = useState<string>(props.defaultValue?props.defaultValue.toString():"")
    const {fullWidth, ...propeties} = props
    return <NumberInput
        variant={props.variant?props.variant:"filled"}
        hideControls
        placeholder="80"
        min={props.min?props.min:1}
        max={props.max?props.min:65535}
        style={fullWidth?props.style:{ width: "75px", ...props.style }}
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
            props.onInput?.(e)
        }}
        ref={ref}
        {...propeties}
    />

})

export default PortInput