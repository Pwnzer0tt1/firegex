import { AutocompleteItem, Select, SelectProps } from "@mantine/core";
import React, { useState } from "react";
import { ipInterfacesQuery } from "../js/utils";


const AutoCompleteItem = React.forwardRef<HTMLDivElement, ItemProps>(
    ({ netint, value, ...props }: ItemProps, ref) => <div ref={ref} {...props}>
            ( <b>{netint}</b> ) -{">"} <b>{value}</b> 
    </div>
);

interface ItemProps extends AutocompleteItem {
    netint: string;
}

interface InterfaceInputProps extends Omit<SelectProps, "data">{
    initialCustomInterfaces?:AutocompleteItem[],
    includeInterfaceNames?:boolean
}

export const InterfaceInput = ({ initialCustomInterfaces, includeInterfaceNames, ...props }:InterfaceInputProps) => {

    const [customIpInterfaces, setCustomIpInterfaces] = useState<AutocompleteItem[]>(initialCustomInterfaces??[]);
    const interfacesQuery = ipInterfacesQuery()

    const getInterfaces = () => {
        if (interfacesQuery.isLoading || !interfacesQuery.data) return []
        if(includeInterfaceNames){
            const result = interfacesQuery.data.map(item => ({netint:"IP", value:item.addr, label:item.addr})) as AutocompleteItem[]
            interfacesQuery.data.map(item => item.name).filter((item, index, arr) => arr.indexOf(item) === index).forEach(item => result.push({netint:"INT", value:item, label:item}))
            return result
        }
        return (interfacesQuery.data.map(item => ({netint:item.name, value:item.addr, label:item.addr})) as AutocompleteItem[])
    }

    const interfaces = getInterfaces()

    return <Select
        placeholder="10.1.1.1"
        itemComponent={AutoCompleteItem}
        data={[...customIpInterfaces, ...interfaces]}
        searchable
        dropdownPosition="bottom"
        maxDropdownHeight={200}
        creatable
        getCreateLabel={(query) => `+ Use this: ${query}`}
        onCreate={(query) => {
            const item = { value: query, netint: "CUSTOM", label: query };
            setCustomIpInterfaces((current) => [...current, item]);
            return item;
        }}
        style={props.style?{width:"100%", ...props.style}:{width:"100%"}}
        {...props}
    />
}