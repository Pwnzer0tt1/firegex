import { SegmentedControl, SegmentedControlProps } from "@mantine/core";
import { RuleMode } from "./utils";



export const ModeSelector = (props:Omit<SegmentedControlProps, "data">) => (
    <SegmentedControl
        data={[
            {
                value: RuleMode.IN,
                label: 'Inbound',
            },
            {
                value: RuleMode.OUT,
                label: 'Outbound',
            }
        ]}
        size={props.size?props.size:"xs"}
        {...props}
    />
)