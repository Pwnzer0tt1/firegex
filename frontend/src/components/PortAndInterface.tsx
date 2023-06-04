import { Autocomplete, AutocompleteItem, Space, Title } from "@mantine/core"
import React, { useEffect, useState } from "react"
import { getipinterfaces } from "../js/utils";
import PortInput from "./PortInput";
import { UseFormReturnType } from "@mantine/form/lib/types";

interface ItemProps extends AutocompleteItem {
    label: string;
}

const AutoCompleteItem = React.forwardRef<HTMLDivElement, ItemProps>(
    ({ label, value, ...props }: ItemProps, ref) => <div ref={ref} {...props}>
            ( <b>{label}</b> ) -{">"} <b>{value}</b> 
    </div>
);


export default function PortAndInterface({ form, int_name, port_name, label }:{ form:UseFormReturnType<any>, int_name:string, port_name:string, label?:string }) {
   
    const [ipInterfaces, setIpInterfaces] = useState<AutocompleteItem[]>([]);
    
    useEffect(()=>{
        getipinterfaces().then(data => {
            setIpInterfaces(data.map(item => ({label:item.name, value:item.addr})));
        })
    },[])

   return <>
        {label?<>
            <Title order={6}>{label}</Title>
            <Space h="xs" /></> :null}
        
        <div className='center-flex' style={{width:"100%"}}>
            <Autocomplete
                placeholder="10.1.1.1"
                itemComponent={AutoCompleteItem}
                data={ipInterfaces}
                {...form.getInputProps(int_name)}
                style={{width:"100%"}}
            />
            <Space w="sm" /><span style={{marginTop:"-3px", fontSize:"1.5em"}}>:</span><Space w="sm" />
            <PortInput {...form.getInputProps(port_name)} />
        </div>
    </>
}