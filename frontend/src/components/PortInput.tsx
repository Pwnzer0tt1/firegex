import { Input, NumberInput, NumberInputProps, TextInput, TextInputProps } from "@mantine/core"
import React, { useState } from "react"

interface PortInputProps extends NumberInputProps {
    fullWidth?: boolean
}

const valueParse = (raw_value:string, oldValue:string = "") => {
    const value = parseInt(raw_value)
    if (value > 65535) {
        return oldValue
    } else if (value < 1) {
        return oldValue
    }else{
        return value.toString()
    }
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
            const target = e.target as HTMLInputElement
            target.value = target.value?valueParse(target.value, oldValue):""
            setOldValue(target.value)
            props.onInput?.(e)
        }}
        ref={ref}
        {...propeties}
    />

})


interface PortRangeInputProps extends TextInputProps {
    fullWidth?: boolean,
    defaultValues?: number[]
}

export const PortRangeInput =  React.forwardRef<HTMLInputElement, PortRangeInputProps>( (props, ref) => {
    const oldValueStates = [
        useState<string>(props.defaultValue?props.defaultValue?.toString().split("-")[0]:""),
        useState<string|undefined>(props.defaultValue?.toString().split("-")[1])
    ]
    const {fullWidth, defaultValues, ...propeties} = props
    let defaultValuesInt = defaultValues
    if (defaultValuesInt?.length == 2 && defaultValuesInt[0] == defaultValuesInt[1]){
        defaultValuesInt = [defaultValuesInt[0]]
    }
    
    return <TextInput
        variant={props.variant?props.variant:"filled"}
        placeholder="1000-1337"
        style={fullWidth?props.style:{ width: "150px", ...props.style }}
        onInput={(e) => {
            const target = e.target as HTMLInputElement
            const splitted = target.value.split("-")
            const parsedValues = [splitted[0], splitted[1]].map((value, index) => {
                const res = value?valueParse(value,oldValueStates[index][0]):value
                if (res != oldValueStates[index][0]) oldValueStates[index][1](value)
                return res
            })
            target.value = parsedValues.filter((v, i) => (v !== undefined && (i != 0 || v !== ""))).join("-")
            props.onInput?.(e)
        }}
        ref={ref}
        defaultValue={defaultValuesInt?defaultValuesInt.map(v => v.toString()).join("-"):props.defaultValue}
        {...propeties}
    />

})

export default PortInput