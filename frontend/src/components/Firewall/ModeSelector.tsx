import { SegmentedControl, SegmentedControlProps } from "@mantine/core";
import { RuleMode } from "./utils";



export const ModeSelector = (props:Omit<SegmentedControlProps, "data">) => (
    <SegmentedControl
        data={[
            {
                value: RuleMode.IN,
                label: 'IN',
            },
            {
                value: RuleMode.FORWARD,
                label: 'FWD',
            },
            {
                value: RuleMode.OUT,
                label: 'OUT',
            }
        ]}
        size={props.size?props.size:"xs"}
        {...props}
    />
)