import { Box, Button, FileButton, Group, Text, Textarea } from '@mantine/core';
import { useState } from 'react';
import { TbFileUpload } from 'react-icons/tb';

/** How much of a file is worth reading. A PEM bundle is a few kilobytes; anything
 *  this size is not one, and reading it whole would freeze the tab to prove it. */
const MAX_BYTES = 512 * 1024

/**
 * A PEM field that can be typed into, pasted into, picked from disk, or dropped onto.
 *
 * The three ways in exist because the material arrives differently depending on where
 * the operator is standing: a certificate copied out of a chat message is pasted, one
 * sitting in `~/certs` is dropped, and one somewhere with a long path is picked. Only
 * pasting used to be possible, which meant opening the file in an editor first — and a
 * key that has been through an editor is a key that may have lost its trailing newline
 * or gained a stray character, neither of which is visible in a textarea.
 *
 * The file is read in the browser and put into the same field a paste lands in, so
 * there is one value being validated and submitted however it got there. Nothing is
 * uploaded separately: a second endpoint taking a file would be a second way for the
 * key to reach the backend, and the key is the one thing worth having exactly one of.
 */
export default function PemInput({ label, placeholder, expect, value, onChange, error }: {
    label: string,
    placeholder: string,
    /** The PEM header this field is meant to hold, used to warn about a swap. */
    expect: string,
    value: string,
    onChange: (value: string) => void,
    error?: React.ReactNode,
}) {
    const [dragging, setDragging] = useState(false)
    const [fileError, setFileError] = useState<string | null>(null)

    const load = async (file: File | null) => {
        if (!file) return
        setFileError(null)
        if (file.size > MAX_BYTES) {
            setFileError(`${file.name} is ${Math.round(file.size / 1024)} KB — too large to be PEM material`)
            return
        }
        try {
            const text = await file.text()
            // A DER or PKCS#12 file has no header to find, and pasting its bytes into a
            // textarea produces something that looks like corruption rather than like
            // the wrong format. Say which it is while the file name is still known.
            if (!text.includes("-----BEGIN")) {
                setFileError(`${file.name} is not PEM: no '-----BEGIN' in it. A .der or .p12 has to be converted first.`)
                return
            }
            onChange(text)
        } catch (err) {
            setFileError(`${file.name} could not be read: ${err}`)
        }
    }

    const swapped = value !== "" && !value.includes(expect) && value.includes("-----BEGIN")

    return <Box
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={e => {
            e.preventDefault()
            setDragging(false)
            load(e.dataTransfer.files?.[0] ?? null)
        }}
        style={{
            borderRadius: 8,
            outline: dragging ? '2px dashed var(--mantine-color-blue-5)' : '2px dashed transparent',
            outlineOffset: 4,
            transition: 'outline-color 120ms',
        }}
    >
        <Group justify="space-between" align="flex-end" mb={4} wrap="nowrap">
            <Text size="sm" fw={500}>{label}</Text>
            <FileButton onChange={load} accept=".pem,.crt,.cer,.key,.txt,application/x-pem-file,text/plain">
                {props => <Button {...props} size="compact-xs" variant="subtle"
                    leftSection={<TbFileUpload size={13} />}>
                    Load from file
                </Button>}
            </FileButton>
        </Group>
        <Textarea autosize minRows={2} maxRows={5}
            placeholder={dragging ? "Drop the file here" : placeholder}
            styles={{ input: { fontFamily: 'monospace' } }}
            value={value}
            onChange={e => { setFileError(null); onChange(e.currentTarget.value) }}
            error={error}
        />
        {fileError ? <Text size="xs" c="red" mt={4}>{fileError}</Text> : null}
        {swapped && !fileError ? <Text size="xs" c="yellow" mt={4}>
            This holds a {value.includes("PRIVATE KEY-----") ? "private key" : "certificate"},
            not what this field is for — the two are probably the other way round.
        </Text> : null}
        {!fileError && !swapped ? <Text size="xs" c="dimmed" mt={4}>
            Paste it, or drop a file anywhere on this field.
        </Text> : null}
    </Box>
}
