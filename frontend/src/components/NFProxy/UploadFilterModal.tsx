import { Button, FileButton, Group, Modal, Notification, Space } from "@mantine/core";
import { nfproxy, Service } from "./utils";
import { useEffect, useState } from "react";
import { ImCross } from "react-icons/im";
import { okNotify } from "../../js/utils";

export const UploadFilterModal = ({ opened, onClose, service }: { opened: boolean, onClose: () => void, service?: Service }) => {
    const close = () =>{
        onClose()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)
    const [file, setFile] = useState<File | null>(null);
    
    useEffect(() => {
        if (opened && file){
            file.bytes().then( code => {
                console.log(code.toString())
                setSubmitLoading(true)
                nfproxy.setpyfilterscode(service?.service_id??"",code.toString()).then( res => {
                    if (!res){
                        setSubmitLoading(false)
                        close();
                        okNotify(`Service ${name} code updated`, `Successfully updated code for service ${name}`)
                    }
                }).catch( err => {
                    setSubmitLoading(false)
                    setError("Error: "+err)
                })
            })
        }
    }, [opened, file])
    
    return <Modal opened={opened && service != null} onClose={onClose} title="Upload filter Code" size="xl" closeOnClickOutside={false} centered>
            <Space h="md" />
            <Group justify="center">
                <FileButton onChange={setFile} accept=".py" multiple={false}>
                {(props) => <Button {...props}>Upload filter python code</Button>}
                </FileButton>
            </Group>

            {error?<>
                <Space h="md" />
                <Notification icon={<ImCross size={14} />} color="red" onClose={()=>{setError(null)}}>
                    Error: {error}
                </Notification>
            </>:null}
            <Space h="md" />

    </Modal>

}