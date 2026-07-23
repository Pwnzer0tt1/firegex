import { Button, FileButton, Group, Modal, Notification, Space, Textarea, ActionIcon, Tooltip } from "@mantine/core";
import { nfproxy, Service } from "./utils";
import { useEffect, useState } from "react";
import { ImCross } from "react-icons/im";
import { okNotify } from "../../js/utils";
import { MdUploadFile, MdSave } from "react-icons/md";
import { TbCode } from "react-icons/tb";
import Editor from "@monaco-editor/react";
import { Box } from "@mantine/core";

export const EditFilterModal = ({ opened, onClose, service }: { opened: boolean, onClose: () => void, service?: Service }) => {
    const close = () => {
        onClose()
        setError(null)
    }

    const [submitLoading, setSubmitLoading] = useState(false)
    const [error, setError] = useState<string|null>(null)
    const [code, setCode] = useState<string>("");
    
    // Fetch code on open
    useEffect(() => {
        if (opened && service) {
            nfproxy.getpyfilterscode(service.service_id).then(fetchedCode => {
                setCode(fetchedCode || "");
            }).catch(err => {
                setError("Error fetching code: " + err);
            });
        }
    }, [opened, service])

    const handleSave = () => {
        if (!service) return;
        setSubmitLoading(true);
        nfproxy.setpyfilterscode(service.service_id, code).then(res => {
            if (!res) {
                okNotify(`Service ${service.name} code updated`, `Successfully updated python code for proxy filter.`);
                close();
            } else {
                setError("Error: " + res);
            }
        }).catch(err => {
            setError("Error: " + err);
        }).finally(() => {
            setSubmitLoading(false);
        });
    }

    const handleFileUpload = (file: File | null) => {
        if (file) {
            file.text().then(text => {
                setCode(text);
                okNotify("File loaded", "Python code loaded into editor. Remember to save changes.");
            });
        }
    }

    return (
        <Modal 
            opened={opened && service != null} 
            onClose={close} 
            title={
                <Group gap="xs">
                    <TbCode size={20} color="var(--accent-color)" />
                    Python Script Editor
                </Group>
            } 
            size="80%" 
            closeOnClickOutside={false} 
            centered
            styles={{ body: { display: 'flex', flexDirection: 'column', height: '70vh' } }}
        >
            <Box style={{ flexGrow: 1, border: '1px solid var(--fourth_color)', borderRadius: 8, overflow: 'hidden' }}>
                <Editor
                    height="100%"
                    language="python"
                    theme="vs-dark"
                    value={code}
                    onChange={(value) => setCode(value || "")}
                    options={{
                        minimap: { enabled: false },
                        fontSize: 14,
                        fontFamily: 'JetBrains Mono, monospace',
                        lineHeight: 1.5,
                        scrollBeyondLastLine: false,
                        smoothScrolling: true,
                    }}
                />
            </Box>

            <Space h="md" />
            
            <Group justify="space-between" mt="auto">
                <FileButton onChange={handleFileUpload} accept=".py" multiple={false}>
                    {(props) => (
                        <Button variant="light" color="gray" leftSection={<MdUploadFile size={16}/>} {...props}>
                            Load from .py file
                        </Button>
                    )}
                </FileButton>

                <Group>
                    <Button variant="default" onClick={close}>Cancel</Button>
                    <Button 
                        color="cyan" 
                        leftSection={<MdSave size={16} />} 
                        onClick={handleSave} 
                        loading={submitLoading}
                    >
                        Save Code
                    </Button>
                </Group>
            </Group>

            {error ? (
                <>
                    <Space h="md" />
                    <Notification icon={<ImCross size={14} />} color="red" onClose={() => setError(null)}>
                        {error}
                    </Notification>
                </>
            ) : null}
        </Modal>
    );
}
