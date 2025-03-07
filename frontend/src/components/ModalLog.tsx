import { Code, Modal, ScrollArea } from "@mantine/core"

export const ModalLog = (
    { title, opened, close, data }:
    {
        title: string,
        opened: boolean,
        close: () => void,
        data: string,
    }
) => {
    return <Modal size="90%" title={title} opened={opened} onClose={close} centered>
        <ScrollArea h={500} style={{ maxWidth: "100%",whiteSpace: "break-spaces"}} scrollbars="y">
           <Code block mih={500} style={{ maxWidth: "100%",whiteSpace: "break-spaces"}}>{data}</Code>
        </ScrollArea>
    </Modal>
}