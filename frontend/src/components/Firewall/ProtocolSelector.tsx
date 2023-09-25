import { SegmentedControl, SegmentedControlProps } from "@mantine/core";
import { Protocol } from "./utils";


export const ProtocolSelector = (props:Omit<SegmentedControlProps, "data">) => (
    <SegmentedControl
        data={[
            {
                value: Protocol.TCP,
                label: 'TCP',
            },
            {
                value: Protocol.UDP,
                label: 'UDP',
            },
            {
                value: Protocol.ANY,
                label: 'ANY',
            }
        ]}
        size={props.size?props.size:"xs"}
        {...props}
    />
)