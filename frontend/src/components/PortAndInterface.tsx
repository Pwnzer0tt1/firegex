import { Box, Space, Text, Title } from "@mantine/core"
import { UseFormReturnType } from "@mantine/form";
import { InterfaceInput } from "./InterfaceInput";
import PortInput from "./PortInput";

export default function PortAndInterface({
    form,
    int_name,
    port_name,
    label,
    description,
    orientation,
    includeInterfaceNames = true,
}: {
    form: UseFormReturnType<any>,
    int_name: string,
    port_name: string,
    label?: string,
    /** One line under the label, for what the field takes that is not obvious. */
    description?: string,
    orientation?: "line" | "column",
    includeInterfaceNames?: boolean,
}) {
    const line = !orientation || orientation == "line"
    // One message under the pair, because either half can be the wrong one and they
    // sit on a single line. The address box never received the form's `error` at all,
    // so "Invalid IP address or interface name" was computed on every submit and shown
    // nowhere; both boxes still turn red, which is what says which half it was.
    const error = form.getInputProps(int_name).error ?? form.getInputProps(port_name).error

    return <>
        {label ? <>
            <Title order={6}>{label}</Title>
            {description ? <Text size="xs" c="dimmed" mt={2}>{description}</Text> : null}
            <Space h="xs" /></> : null}
        <Box className={line ? 'center-flex' : "center-flex-row"} style={{ width: "100%" }}>
            <InterfaceInput
                {...form.getInputProps(int_name)}
                error={!!form.getInputProps(int_name).error}
                includeInterfaceNames={includeInterfaceNames}
            />
            {line ?
                <><Space w="sm" /><span style={{ marginTop: "-3px", fontSize: "1.5em" }}>:</span><Space w="sm" /></> :
                <Space h="md" />}
            <PortInput {...form.getInputProps(port_name)} error={!!form.getInputProps(port_name).error} />
        </Box>
        {error ? <Text size="xs" c="red" mt={4}>{error}</Text> : null}
    </>
}
