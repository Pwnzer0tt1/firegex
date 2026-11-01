import { Input, NumberInput, NumberInputProps, TextInput, TextInputProps } from "@mantine/core"
import React, { useState } from "react"
import { regex_port, regex_range_port } from "../js/utils"

interface PortInputProps extends NumberInputProps {
    fullWidth?: boolean
}


const PortInput =  React.forwardRef<HTMLInputElement, PortInputProps>( (props, ref) => {
    const [oldValue, setOldValue] = useState<string>((props.value ?? props.defaultValue)?.toString() ?? "")
    const {fullWidth, onInput, style, ...propeties} = props
    return <NumberInput
        {...propeties}
        variant={props.variant?props.variant:"filled"}
        hideControls
        placeholder="80"
        min={props.min?props.min:1}
        max={props.max?props.max:65535}
        style={fullWidth?style:{ width: "75px", ...style }}
        onInput={(e) => {
            const target = e.target as HTMLInputElement
            target.value.match(regex_port)?setOldValue(target.value):target.value = oldValue
            onInput?.(e)
        }}
        ref={ref}
    />

})


interface PortRangeInputProps extends TextInputProps {
    fullWidth?: boolean,
    defaultValues?: number[]
}

export const PortRangeInput =  React.forwardRef<HTMLInputElement, PortRangeInputProps>( (props, ref) => {
    const {fullWidth, defaultValues, onInput, style, ...propeties} = props
    let defaultValuesInt = defaultValues
    if (defaultValuesInt?.length == 2 && defaultValuesInt[0] == defaultValuesInt[1]){
        defaultValuesInt = [defaultValuesInt[0]]
    }
    const initialDefault = defaultValuesInt ? defaultValuesInt.map(v => v.toString()).join("-") : props.defaultValue
    const [oldValue, setOldValue] = useState<string>((props.value ?? initialDefault)?.toString() ?? "")
    
    return <TextInput
        {...propeties}
        variant={props.variant?props.variant:"filled"}
        placeholder="1000-1337"
        style={fullWidth?style:{ width: "150px", ...style }}
        onInput={(e) => {
            const target = e.target as HTMLInputElement
            target.value.match(regex_range_port)?setOldValue(target.value):target.value = oldValue
            onInput?.(e)
        }}
        ref={ref}
        defaultValue={initialDefault}
    />

})

export default PortInput