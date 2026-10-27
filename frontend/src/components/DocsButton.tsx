import { ActionIcon, ActionIconProps, Box, Container, Modal, ScrollArea, ScrollAreaAutosize, Title, Tooltip } from "@mantine/core";
import { useState } from "react";
import { FaBookBookmark } from "react-icons/fa6";
import { ServicesDocs } from "./Services/ServicesDocs";
import { FirewallDocs } from "./Firewall/FirewallDocs";
import { EnumToPrimitiveUnion } from "../js/utils";

export enum DocType{
    SERVICES = "services",
    FIREWALL = "firewall",
}


export const DocsButton = ({ doc, ...props }: { doc: EnumToPrimitiveUnion<DocType> } & ActionIconProps) => {
    const [open, setOpen] = useState(false);

    return <Box>
        <Tooltip label="Read the documentation">
            <ActionIcon onClick={()=>setOpen(true)} size="lg" radius="md" variant="default" aria-label="Documentation" {...props}><FaBookBookmark size="16px" /></ActionIcon>
        </Tooltip>
        <Modal opened={open} onClose={() => setOpen(false)} fullScreen title={
            <Title order={3}>Firegex documentation</Title>
        } scrollAreaComponent={ScrollArea.Autosize}>
            <Container style={{padding: "1rem", maxWidth:"90vw"}}>
                {
                    doc == DocType.SERVICES ?
                        <ServicesDocs />:
                    doc == DocType.FIREWALL ?
                        <FirewallDocs />:
                    <Title order={3}>Docs not found</Title>
                }
            </Container>
        </Modal>
    </Box>
}

