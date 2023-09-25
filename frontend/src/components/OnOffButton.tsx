import { ActionIcon, ActionIconProps } from "@mantine/core"
import { ImCross } from "react-icons/im"
import { TiTick } from "react-icons/ti"
import {PolymorphicComponentProps} from "@mantine/utils"



interface IOnOffButtonProps extends Omit<PolymorphicComponentProps<"button",ActionIconProps>, "value">{
    value: boolean,
}

export const OnOffButton = ({value, ...props}:IOnOffButtonProps) => {
    return <ActionIcon color={props.color?props.color:(value?"green":"red")} {...props}>
            {value?<TiTick size={20} />:<ImCross size={12} />}
    </ActionIcon>
}