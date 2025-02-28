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
        <ScrollArea h={500} style={{ minWidth: "100%",whiteSpace: "pre-wrap"}}>
           <Code block mih={500}>{data}</Code>
        </ScrollArea>
    </Modal>
}