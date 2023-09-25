import { SegmentedControl, SegmentedControlProps } from "@mantine/core";
import { ActionType } from "./utils";


export const ActionTypeSelector = (props:Omit<SegmentedControlProps, "data">) => (
    <SegmentedControl
        data={[
            {
                value: ActionType.ACCEPT,
                label: 'Accept',
            },
            {
                value: ActionType.REJECT,
                label: 'Reject',
            },
            {
                value: ActionType.DROP,
                label: 'Drop',
            }
        ]}
        size={props.size?props.size:"xs"}
        {...props}
    />
)