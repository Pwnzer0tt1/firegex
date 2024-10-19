import { SegmentedControl, SegmentedControlProps } from "@mantine/core";
import { RuleMode, Table } from "./utils";
import { table } from "console";



export const ModeSelector = (props:Omit<SegmentedControlProps, "data"> & { table: Table }) => {
    const isFilterTable = props.table == Table.FILTER
    return <SegmentedControl
        data={[
            {
                value: RuleMode.IN,
                label: isFilterTable?'IN':'PREROUTING',
            },
            ...(isFilterTable?[{
                value: RuleMode.FORWARD,
                label: 'FWD',
            }]:[]),
            {
                value: RuleMode.OUT,
                label: isFilterTable?'OUT':'POSTROUTING',
            }
        ]}
        size={props.size?props.size:"xs"}
        {...props}
    />
}