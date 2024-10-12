import { Combobox, TextInput, useCombobox } from "@mantine/core";
import { useState } from "react";
import { ipInterfacesQuery } from "../js/utils";

interface ItemProps{
    value: string
    netint: string;
}

interface InterfaceInputProps{
    initialCustomInterfaces?:ItemProps[],
    includeInterfaceNames?:boolean,
    onChange?: (value:string) => void,
    value?:string,
    defaultValue?:string
}

export const InterfaceInput = ({ initialCustomInterfaces, includeInterfaceNames, onChange, value, defaultValue }:InterfaceInputProps) => {

    const [customIpInterfaces, setCustomIpInterfaces] = useState<ItemProps[]>(initialCustomInterfaces??[]);
    const interfacesQuery = ipInterfacesQuery()

    const getInterfaces = () => {
        if (interfacesQuery.isLoading || !interfacesQuery.data) return []
        if(includeInterfaceNames){
            const result = interfacesQuery.data.map(item => ({netint:"IP", value:item.addr})) as ItemProps[]
            interfacesQuery.data.map(item => item.name).filter((item, index, arr) => arr.indexOf(item) === index).forEach(item => result.push({netint:"INT", value:item}))
            return result
        }
        return (interfacesQuery.data.map(item => ({netint:item.name, value:item.addr})) as ItemProps[])
    }

    const interfaces = getInterfaces()

    const combobox = useCombobox({
        onDropdownClose: () => {
            combobox.resetSelectedOption()
        },
    });

    const data = [...customIpInterfaces, ...interfaces]
    const [selectedValue, setSelectedValue] = useState<string | null>(null);
    const [search, setSearch] = useState('');
    
    const exactOptionMatch: ItemProps|undefined = data.find((item) => item.value === search);

    const filteredOptions = data.filter((item) => item.value.toLowerCase().includes(search.toLowerCase().trim())).sort((a, b) => {
        if (exactOptionMatch != null) {
            if (a.value == exactOptionMatch.value) return -1
            if (b.value == exactOptionMatch.value) return 1
        }
        return a.value.localeCompare(b.value)
    });

    const options = filteredOptions.map((item) => (
        <Combobox.Option value={item.value} key={item.value}>
          ( <b>{item.netint}</b> ) -{">"} <b>{item.value}</b>
        </Combobox.Option>
    ));

    return <>
    <Combobox
        store={combobox}
        withinPortal={false}
        position="bottom-end"
        onOptionSubmit={(value) => {
            if (value === '$create') {
                const item = { value: search, netint: "CUSTOM" };
                setCustomIpInterfaces((current) => [...current, item]);
                setSelectedValue(search);
                onChange?.(search)
            } else {
                setSelectedValue(value);
                setSearch(value);
                onChange?.(value)
            }
            combobox.closeDropdown();
        }}
    >

    <Combobox.Target>
        <TextInput
          style={{width:"100%"}}
          defaultValue={defaultValue}
          rightSection={<Combobox.Chevron />}
          value={value??(defaultValue?undefined:search)}
          placeholder="10.1.1.1"
          rightSectionPointerEvents="none"
            onChange={(event) => {
                combobox.openDropdown();
                combobox.updateSelectedOptionIndex();
                setSearch(event.currentTarget.value)
                onChange?.(event.currentTarget.value)

            }}
            onClick={(e) => {
                combobox.openDropdown()
            }}
            onFocus={(e) => {
                combobox.openDropdown()
            }}
          onBlur={(e) => {
            combobox.closeDropdown();
            setSearch(selectedValue??'');
          }}
        />
      </Combobox.Target>

      <Combobox.Dropdown>
        <Combobox.Options mah={100} style={{ overflowY: 'auto' }}>
          {options}
          {(exactOptionMatch==null) && search.trim().length > 0 && (
            <Combobox.Option value="$create">+ Use this: {search}</Combobox.Option>
          )}
        </Combobox.Options>
      </Combobox.Dropdown>
    </Combobox>
    </>
}