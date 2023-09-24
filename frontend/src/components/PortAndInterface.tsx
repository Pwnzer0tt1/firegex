import { AutocompleteItem, Select, Space, Title } from "@mantine/core"
import React, { useEffect, useState } from "react"
import { ipInterfacesQuery } from "../js/utils";
import PortInput from "./PortInput";
import { UseFormReturnType } from "@mantine/form/lib/types";
import { InterfaceInput } from "./InterfaceInput";

interface ItemProps extends AutocompleteItem {
    netint: string;
}

const AutoCompleteItem = React.forwardRef<HTMLDivElement, ItemProps>(
    ({ netint, value, ...props }: ItemProps, ref) => <div ref={ref} {...props}>
            ( <b>{netint}</b> ) -{">"} <b>{value}</b> 
    </div>
);


export default function PortAndInterface({ form, int_name, port_name, label, orientation }:{ form:UseFormReturnType<any>, int_name:string, port_name:string, label?:string, orientation?:"line"|"column" }) {
   


   return <>
        {label?<>
            <Title order={6}>{label}</Title>
            <Space h="xs" /></> :null}
            <div className={(!orientation || orientation == "line")?'center-flex':"center-flex-row"} style={{width:"100%"}}>
                <InterfaceInput
                    {...form.getInputProps(int_name)}
                />
                {(!orientation || orientation == "line")?
                    <><Space w="sm" /><span style={{marginTop:"-3px", fontSize:"1.5em"}}>:</span><Space w="sm" /></>:
                    <Space h="md" />}
                <PortInput {...form.getInputProps(port_name)} />
            </div>
    </>
}