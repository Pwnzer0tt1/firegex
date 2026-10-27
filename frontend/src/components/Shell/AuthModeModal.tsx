import { Alert, Button, Code, Group, List, Modal, Notification, Space, Text } from "@mantine/core";
import { useState } from "react"
import { ImCross } from "react-icons/im";
import { MdWarning } from "react-icons/md";
import { setAuthMode } from "../../js/utils";

/**
 * Hand access control to whatever sits in front of firegex, and take it back.
 *
 * The two directions are not symmetrical, and the modal says which one you are in.
 * Turning authentication on again takes a session from before it was turned off — this
 * browser keeps its token, so the operator who did it can undo it — or the host. A
 * browser arriving afterwards cannot, which is what stops a passer-by from setting their
 * own password and keeping the operator out for good.
 *
 * The page is reloaded afterwards rather than patched: the sockets were authorised under
 * the rule that just changed and have been dropped, and coming back through the front
 * door is how the interface finds out what the rules are now.
 */
function AuthModeModal({ opened, onClose, disable }: {
    opened: boolean, onClose: () => void,
    /** True to turn authentication off, false to put it back on. */
    disable: boolean,
}) {
    const [loadingBtn, setLoadingBtn] = useState(false)
    const [error, setError] = useState<null | string>(null)

    const submitRequest = async () => {
        setLoadingBtn(true)
        await setAuthMode(disable).then(res => {
            if (!res) {
                window.location.reload()
            } else {
                setError(res)
            }
        }).catch(err => setError(err.toString()))
        setLoadingBtn(false)
    }

    return <Modal size="lg" opened={opened} onClose={onClose} closeOnClickOutside={false} centered
        title={disable ? "Turn authentication off" : "Turn authentication back on"}>
        {disable
            ? <>
                <Alert color="red" icon={<MdWarning size={20} />}
                    title="Everyone who can reach firegex becomes an administrator">
                    <Text size="sm">
                        No password is asked for and no token is checked. Only do this when
                        something in front of firegex is doing the checking for you — a
                        reverse proxy that authenticates, or a network nobody else is on.
                    </Text>
                </Alert>
                <Space h="md" />
                <List size="sm" spacing={6}>
                    <List.Item>The password stays stored, but nothing asks for it.</List.Item>
                    <List.Item>
                        It lasts until firegex restarts. To keep it that way, run{" "}
                        <Code>python3 run.py config --unsafe-disable-auth</Code> on the host.
                    </List.Item>
                    <List.Item>
                        This browser keeps its session, so it can turn authentication back on.
                        A browser that arrives afterwards cannot — that takes the host:{" "}
                        <Code>python3 run.py config --no-unsafe-disable-auth</Code>.
                    </List.Item>
                </List>
            </>
            : <>
                <Text size="sm">
                    The stored password is asked for again, and every request needs a
                    session. Anyone using firegex right now without one will be asked to
                    log in.
                </Text>
                <Space h="md" />
                <List size="sm" spacing={6}>
                    <List.Item>
                        This works because this browser still holds a session from before
                        authentication was turned off.
                    </List.Item>
                    <List.Item>
                        It lasts until firegex restarts. To keep it that way, run{" "}
                        <Code>python3 run.py config --no-unsafe-disable-auth</Code> on the host.
                    </List.Item>
                </List>
            </>}
        <Group justify="space-between" mt="xl">
            <Button variant="subtle" color="gray" onClick={onClose}>Leave it as it is</Button>
            <Button loading={loadingBtn} color={disable ? "red" : "teal"} onClick={submitRequest}>
                {disable ? "Turn authentication off" : "Turn authentication on"}
            </Button>
        </Group>
        <Space h="md" />
        {error ? <>
            <Notification icon={<ImCross size={14} />} color="red" onClose={() => { setError(null) }}>
                Error: {error}
            </Notification><Space h="md" /></> : null}
    </Modal>
}

export default AuthModeModal;
