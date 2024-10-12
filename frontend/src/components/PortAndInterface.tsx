import { Box, Space, Title } from "@mantine/core"
import React from "react"
import PortInput from "./PortInput";
import { UseFormReturnType } from "@mantine/form/lib/types";
import { InterfaceInput } from "./InterfaceInput";

type ItemProps = {
    value: string;
    netint: string;
} & any

const AutoCompleteItem = React.forwardRef<HTMLDivElement, ItemProps>(
    ({ netint, value, ...props }, ref) => <Box ref={ref} {...props}>
            ( <b>{netint}</b> ) -{">"} <b>{value}</b> 
    </Box>
);

export default function PortAndInterface({ form, int_name, port_name, label, orientation }:{ form:UseFormReturnType<any>, int_name:string, port_name:string, label?:string, orientation?:"line"|"column" }) {
   


   return <>
        {label?<>
            <Title order={6}>{label}</Title>
            <Space h="xs" /></> :null}
            <Box className={(!orientation || orientation == "line")?'center-flex':"center-flex-row"} style={{width:"100%"}}>
                <InterfaceInput
                    {...form.getInputProps(int_name)}
                />
                {(!orientation || orientation == "line")?
                    <><Space w="sm" /><span style={{marginTop:"-3px", fontSize:"1.5em"}}>:</span><Space w="sm" /></>:
                    <Space h="md" />}
                <PortInput {...form.getInputProps(port_name)} />
            </Box>
    </>
}