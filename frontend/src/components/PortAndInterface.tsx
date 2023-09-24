import { AutocompleteItem, Select, Space, Title } from "@mantine/core"
import React, { useEffect, useState } from "react"
import { getipinterfaces } from "../js/utils";
import PortInput from "./PortInput";
import { UseFormReturnType } from "@mantine/form/lib/types";

interface ItemProps extends AutocompleteItem {
    netint: string;
}

const AutoCompleteItem = React.forwardRef<HTMLDivElement, ItemProps>(
    ({ netint, value, ...props }: ItemProps, ref) => <div ref={ref} {...props}>
            ( <b>{netint}</b> ) -{">"} <b>{value}</b> 
    </div>
);


export default function PortAndInterface({ form, int_name, port_name, label }:{ form:UseFormReturnType<any>, int_name:string, port_name:string, label?:string }) {
   
    const [ipInterfaces, setIpInterfaces] = useState<AutocompleteItem[]>([]);
    
    useEffect(()=>{
        getipinterfaces().then(data => {
            setIpInterfaces(data.map(item => ({netint:item.name, value:item.addr, label:item.addr})));
        })
    },[])

   return <>
        {label?<>
            <Title order={6}>{label}</Title>
            <Space h="xs" /></> :null}
            <div className='center-flex' style={{width:"100%"}}>
                <Select
                    placeholder="10.1.1.1"
                    itemComponent={AutoCompleteItem}
                    data={ipInterfaces}
                    searchable
                    dropdownPosition="bottom"
                    maxDropdownHeight={200}
                    creatable
                    getCreateLabel={(query) => `+ Use this: ${query}`}
                    onCreate={(query) => {
                        const item = { value: query, netint: "CUSTOM", label: query };
                        setIpInterfaces((current) => [...current, item]);
                        return item;
                    }}
                    {...form.getInputProps(int_name)}
                    style={{width:"100%"}}
                />
                <Space w="sm" /><span style={{marginTop:"-3px", fontSize:"1.5em"}}>:</span><Space w="sm" />
                <PortInput {...form.getInputProps(port_name)} />
            </div>
    </>
}