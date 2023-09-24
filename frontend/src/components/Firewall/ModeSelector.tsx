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
                value: RuleMode.OUT,
                label: 'OUT',
            }
        ]}
        {...props}
    />
)