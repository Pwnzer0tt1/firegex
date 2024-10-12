import { ActionIcon, ActionIconProps, PolymorphicComponentProps } from "@mantine/core"
import { ImCheckmark, ImCross } from "react-icons/im"

interface IOnOffButtonProps extends Omit<PolymorphicComponentProps<"button",ActionIconProps>, "value">{
    value: boolean,
}

export const OnOffButton = ({value, ...props}:IOnOffButtonProps) => {
    return <ActionIcon color={props.color?props.color:(value?"green":"red")} {...props}>
            {value?<ImCheckmark size={14} />:<ImCross size={12} />}
    </ActionIcon>
}