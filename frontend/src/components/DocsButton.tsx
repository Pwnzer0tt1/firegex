import { ActionIcon, Box, Modal, ScrollArea, Title, Tooltip } from "@mantine/core";
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


export const DocsButton = ({ doc }: { doc: EnumToPrimitiveUnion<DocType> }) => {
    const [open, setOpen] = useState(false);

    return <Box>
        <Tooltip label="Add a new service" color="pink">
            <ActionIcon color="pink" onClick={()=>setOpen(true)} size="lg" radius="md" variant="filled"><FaBookBookmark size="20px" /></ActionIcon>
        </Tooltip>
        <Modal opened={open} onClose={() => setOpen(false)} fullScreen title={
            <Title order={2}>Firegex Docs 📕</Title>
        } scrollAreaComponent={ScrollArea.Autosize}>
            {
                doc == DocType.NFREGEX ? 
                    <NFRegexDocs />:
                doc == DocType.NFPROXY ?
                    <NFProxyDocs />:
                doc == DocType.PORTHIJACK ?
                    <PortHijackDocs />:
                <Title order={3}>Docs not found</Title>
            }
        </Modal>
    </Box>
}

