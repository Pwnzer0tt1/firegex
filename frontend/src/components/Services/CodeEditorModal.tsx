import { Alert, Badge, Box, Button, Code, FileButton, Group, Loader, Modal, Space, Text, Tooltip } from '@mantine/core';
import Editor, { Monaco } from "@monaco-editor/react";
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useRef, useState } from 'react';
import { MdUploadFile } from 'react-icons/md';
import { TbCode } from 'react-icons/tb';
import { getErrorMessage, okNotify } from '../../js/utils';
import { registerPyfilterHints } from './pyfilterHints';
import { CodeCheck, pyfilterApiQuery, serviceQueryKey, services } from './utils';

/**
 * Deliberately a working example rather than a sketch: every parameter is annotated
 * with a model, which is what decides when the filter is called, and the return is a
 * packet statement. A filter whose parameters are unannotated is simply never valid.
 */
const STARTER = `from firegex.pyfilters import pyfilter, ACCEPT, REJECT
from firegex.pyfilters.models import HttpRequest


@pyfilter
def block_path_traversal(http_request: HttpRequest):
    """Called once the request line and headers have been parsed."""
    if b"../" in http_request.url.encode():
        return REJECT
    return ACCEPT
`;

export default function CodeEditorModal({ opened, onClose, serviceId, filterId, filterName }: {
    opened: boolean,
    onClose: () => void,
    serviceId: string,
    filterId: string,
    filterName: string,
}) {
    const queryClient = useQueryClient()
    const [code, setCode] = useState("")
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [check, setCheck] = useState<CodeCheck | null>(null)
    const [checking, setChecking] = useState(false)
    const api = pyfilterApiQuery()
    const monacoRef = useRef<Monaco | null>(null)
    const editorRef = useRef<any>(null)
    const disposeHints = useRef<(() => void) | null>(null)

    // Checked as you pause, by the process that will run it. The answer carries the
    // line, so the reason lands where the mistake is instead of in a message that
    // leaves you to go and find it.
    useEffect(() => {
        if (!opened) return
        const timer = setTimeout(() => {
            setChecking(true)
            services.checkCode(serviceId, filterId, code)
                .then(setCheck)
                .catch(() => setCheck(null))
                .finally(() => setChecking(false))
        }, 700)
        return () => clearTimeout(timer)
    }, [code, opened, serviceId, filterId])

    // The marker is what makes the error findable; the text under the editor is what
    // makes it readable. Both come from the same answer.
    useEffect(() => {
        const monaco = monacoRef.current
        const editor = editorRef.current
        if (!monaco || !editor) return
        const model = editor.getModel()
        if (!model) return
        const bad = check && !check.ok ? check.error : null
        monaco.editor.setModelMarkers(model, "firegex", bad && bad.line > 0 ? [{
            severity: monaco.MarkerSeverity.Error,
            message: `${bad.type}: ${bad.message}`,
            startLineNumber: bad.line,
            endLineNumber: bad.line,
            startColumn: bad.column > 0 ? bad.column : 1,
            endColumn: Math.max((bad.text?.length ?? 0) + 1, 2),
        }] : [])
    }, [check])

    useEffect(() => () => { disposeHints.current?.() }, [])

    useEffect(() => {
        if (!opened) return
        setError(null)
        services.code(serviceId, filterId)
            // The endpoint answers text/plain, so an empty file is an empty string
            // rather than a missing value.
            .then(current => setCode(typeof current === "string" && current !== "" ? current : STARTER))
            .catch(err => setError(getErrorMessage(err)))
    }, [opened, serviceId, filterId])

    const onMount = (editor: any, monaco: Monaco) => {
        editorRef.current = editor
        monacoRef.current = monaco
        if (api.data) {
            disposeHints.current?.()
            disposeHints.current = registerPyfilterHints(monaco, api.data)
        }
    }

    // The description arrives asynchronously; if it lands after the editor mounted, the
    // providers are registered then rather than never.
    useEffect(() => {
        if (!api.data || !monacoRef.current) return
        disposeHints.current?.()
        disposeHints.current = registerPyfilterHints(monacoRef.current, api.data)
    }, [api.data])

    const save = () => {
        setLoading(true)
        services.setCode(serviceId, filterId, code).then(res => {
            setLoading(false)
            if (res) { setError(res); return }
            queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            onClose()
            okNotify("Filter updated", "Reloaded without dropping a single connection")
        }).catch(err => {
            setLoading(false)
            // Code that will not load is refused and the previous file keeps running.
            // Saying why beats a generic failure.
            setError(getErrorMessage(err))
        })
    }

    const loadFile = (file: File | null) => {
        if (file) file.text().then(setCode)
    }

    return <Modal
        opened={opened}
        onClose={onClose}
        title={<Group gap="xs"><TbCode size={20} color="var(--accent-color)" />{filterName}</Group>}
        size="80%"
        closeOnClickOutside={false}
        centered
        styles={{ body: { display: 'flex', flexDirection: 'column', height: '70vh' } }}
    >
        <Text size="xs" c="dimmed" mb="xs">
            Runs in a process of its own, so a filter that hangs is killed rather than
            stalling the traffic. Each connection gets its own module globals.
        </Text>
        <Box style={{ flexGrow: 1, border: '1px solid var(--fourth_color)', borderRadius: 8, overflow: 'hidden' }}>
            <Editor
                height="100%"
                language="python"
                theme="vs-dark"
                value={code}
                onMount={onMount}
                onChange={value => setCode(value || "")}
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
        {/* What the check just said, under the editor where the code is. A refusal
            names the line and shows it; a file that loads says what it defines and
            which protocol that makes it, which is the thing operators most often get
            wrong by assumption. */}
        <Box mt="xs">
            {error ? <Alert color="red" p="xs" mb="xs" withCloseButton onClose={() => setError(null)}>
                <Text size="xs">{error}</Text>
            </Alert> : null}
            {check && !check.ok && check.error ? <Alert color="red" p="xs" variant="light">
                <Group gap="xs" wrap="nowrap" align="flex-start">
                    <Text size="xs" style={{ flex: 1 }}>
                        <b>{check.error.type}</b>
                        {check.error.line > 0 ? <> at line <b>{check.error.line}</b></> : null}
                        {" — "}{check.error.message}
                        {check.error.text ? <><br /><Code>{check.error.text.trim()}</Code></> : null}
                    </Text>
                    {check.error.traceback ? <Tooltip label={check.error.traceback} multiline w={520}
                        position="top-end" styles={{ tooltip: { fontFamily: 'monospace', fontSize: 11 } }}>
                        <Badge size="xs" variant="outline" color="red" style={{ cursor: 'help' }}>
                            traceback
                        </Badge>
                    </Tooltip> : null}
                </Group>
            </Alert> : null}
            {check?.ok ? <Group gap="xs">
                <Badge size="xs" radius="sm" variant="light" color="teal">loads</Badge>
                <Text size="xs" c="dimmed">
                    {check.filters.length} function{check.filters.length === 1 ? "" : "s"}
                    {check.filters.length ? `: ${check.filters.join(", ")}` : ""}
                    {" • speaks "}<b>{check.proto}</b>
                </Text>
                {checking ? <Loader size={12} /> : null}
            </Group> : null}
        </Box>
        <Space h="md" />
        <Group justify="space-between" mt="auto">
            <FileButton onChange={loadFile} accept=".py" multiple={false}>
                {props => (
                    <Button variant="light" color="gray" leftSection={<MdUploadFile size={16} />} {...props}>
                        Load from .py file
                    </Button>
                )}
            </FileButton>
            <Button loading={loading} onClick={save}>Save and apply</Button>
        </Group>
    </Modal>
}
