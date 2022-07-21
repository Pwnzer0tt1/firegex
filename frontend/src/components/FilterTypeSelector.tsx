import { Box, Center, SegmentedControl } from "@mantine/core";
import React from "react";
import { FaListAlt } from "react-icons/fa";
import { TiCancel } from "react-icons/ti";

export default function FilterTypeSelector(props:any){
    return <SegmentedControl
        data={[
            {
            value: 'blacklist',
            label: (
                <Center style={{color:"#FFF"}}>
                <TiCancel size={23} color="red"/>
                <Box ml={10}>Blacklist</Box>
                </Center>
            ),
            },
            {
            value: 'whitelist',
            label: (
                <Center style={{color:"#FFF"}}>
                <FaListAlt size={16} color="gray"/>
                <Box ml={10}>Whitelist</Box>
                </Center>
            ),
            },
        ]}
        {...props}
    />
}