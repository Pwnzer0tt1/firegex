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
    initialCustomInterfaces?:AutocompleteItem[]
}

export const InterfaceInput = (props:InterfaceInputProps) => {

    const { initialCustomInterfaces, ...propeties } = props

    const [customIpInterfaces, setCustomIpInterfaces] = useState<AutocompleteItem[]>(initialCustomInterfaces??[]);
    const interfacesQuery = ipInterfacesQuery()

    const interfaces = (!interfacesQuery.isLoading?
            (interfacesQuery.data!.map(item => ({netint:item.name, value:item.addr, label:item.addr})) as AutocompleteItem[]):
        [])

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
        {...propeties}
    />
}