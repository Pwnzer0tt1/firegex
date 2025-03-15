import { ActionIcon, ActionIconProps, Box, Container, Modal, ScrollArea, ScrollAreaAutosize, Title, Tooltip } from "@mantine/core";
import { useState } from "react";
import { FaBookBookmark } from "react-icons/fa6";
import { NFRegexDocs } from "./NFRegex/NFRegexDocs";
import { NFProxyDocs } from "./NFProxy/NFProxyDocs";
import { PortHijackDocs } from "./PortHijack/PortHijackDocs";
import { EnumToPrimitiveUnion } from "../js/utils";

export enum DocType{
    NFREGEX = "nfregex",
    NFPROXY = "nfproxy",
    PORTHIJACK = "porthijack",
}


export const DocsButton = ({ doc, ...props }: { doc: EnumToPrimitiveUnion<DocType> } & ActionIconProps) => {
    const [open, setOpen] = useState(false);

    return <Box>
        <Tooltip label="Read the documentation" color="pink">
            <ActionIcon color="pink" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled" {...props}><FaBookBookmark size="20px" /></ActionIcon>
        </Tooltip>
        <Modal opened={open} onClose={() => setOpen(false)} fullScreen title={
            <Title order={2}>Firegex Docs 📕</Title>
        } scrollAreaComponent={ScrollArea.Autosize}>
            <Container style={{padding: "1rem", maxWidth:"90vw"}}>
                {
                    doc == DocType.NFREGEX ? 
                        <NFRegexDocs />:
                    doc == DocType.NFPROXY ?
                        <NFProxyDocs />:
                    doc == DocType.PORTHIJACK ?
                        <PortHijackDocs />:
                    <Title order={3}>Docs not found</Title>
                }
            </Container>
        </Modal>
    </Box>
}

