import { Alert, Button, Group, Modal, SegmentedControl, Space, Switch, Text, TextInput } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { okNotify } from '../../js/utils';
import RegexDebugger from './RegexDebugger';
import { Mode, Regex, serviceQueryKey, services, Transport } from './utils';

/** UTF-8 bytes to base64, because the API carries a pattern as bytes. */
const encode = (text: string) => {
    const bytes = new TextEncoder().encode(text)
    let binary = ""
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return btoa(binary)
}

/** UTF-8 text out of the base64 the API carries. */
const decode = (b64: string) => {
    try {
        const binary = atob(b64)
        const bytes = Uint8Array.from(binary, c => c.charCodeAt(0))
        return new TextDecoder().decode(bytes)
    } catch {
        return ""
    }
}

/**
 * Add a pattern, or change one that is already there.
 *
 * One modal for both, because they are the same form and the same validation — the
 * engine is asked whether it would accept the pattern either way. Editing keeps the
 * rule's row, so it keeps its place in the filter and its counters; the one exception
 * is the pattern text itself, where the counter is reset because a count is about what
 * a rule matched and the rule now matches something else.
 */
export default function AddRegexModal({ opened, onClose, serviceId, filterId, transport, edit }: {
    opened: boolean,
    onClose: () => void,
    serviceId: string,
    filterId: string,
    /** The service's network layer, which decides whether rewriting is possible at all. */
    transport?: string,
    /** When given, the modal edits this pattern instead of adding one. */
    edit?: Regex,
}) {
    const queryClient = useQueryClient()
    const [submitting, setSubmitting] = useState(false)
    const [error, setError] = useState<string | null>(null)
    const [debugOpen, setDebugOpen] = useState(false)

    const form = useForm({
        initialValues: {
            regex: "",
            mode: Mode.BOTH as string,
            case_sensitive: true,
        },
        validate: { regex: v => v !== "" ? null : "A pattern is required" },
    })

    useEffect(() => {
        if (!opened) return
        setError(null)
        if (edit) form.setValues({
            regex: decode(edit.regex),
            mode: edit.mode,
            case_sensitive: edit.case_sensitive,
        })
        else form.reset()
    }, [opened, edit?.regex_id])

    const close = () => { onClose(); form.reset(); setError(null) }

    const submit = async (values: typeof form.values) => {
        setSubmitting(true)
        setError(null)
        const body = {
            regex: encode(values.regex),
            mode: values.mode,
            case_sensitive: values.case_sensitive,
        }
        try {
            const err = edit
                ? await services.editRegex(serviceId, filterId, edit.regex_id, body)
                : await services.addRegex(serviceId, filterId, body)
            if (err) setError(err)
            else {
                okNotify(edit ? "Pattern updated" : "Pattern added",
                    "It is already in force; no connection was dropped")
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
                close()
            }
        } catch (err) {
            setError(`${err}`)
        }
        setSubmitting(false)
    }

    return <>
        <Modal size="lg" opened={opened} onClose={close} centered
            title={edit ? "Edit this pattern" : "Add a pattern"}>
            <form onSubmit={form.onSubmit(submit)}>
                <TextInput label="Pattern" placeholder="FLAG\{[a-z0-9]+\}"
                    styles={{ input: { fontFamily: 'monospace' } }}
                    {...form.getInputProps('regex')} />
                <Space h="md" />

                

                <Text size="sm" fw={500}>Which direction to match</Text>
                <Text size="xs" c="dimmed" mb={6}>
                    A leaked flag shows up on the way out; an exploit on the way in.
                </Text>
                <SegmentedControl fullWidth
                    data={[
                        { label: 'Both ways', value: Mode.BOTH },
                        { label: 'Client to service', value: Mode.CLIENT_TO_SERVER },
                        { label: 'Service to client', value: Mode.SERVER_TO_CLIENT },
                    ]}
                    {...form.getInputProps('mode')} />
                <Space h="md" />

                <Switch label="Case sensitive"
                    {...form.getInputProps('case_sensitive', { type: 'checkbox' })} />

                {edit ? <Text size="xs" c="dimmed" mt="md">
                    The rule keeps its place and its counters. Changing the pattern
                    itself clears them: a count is about what a rule matched, and this
                    one would then match something else.
                </Text> : null}

                <Group justify="space-between" mt="xl">
                    <Button variant="light" color="grape" onClick={() => setDebugOpen(true)}>
                        Try it first
                    </Button>
                    <Button loading={submitting} type="submit">{edit ? "Save" : "Add pattern"}</Button>
                </Group>
            </form>
            {error ? <Alert color="red" mt="md" withCloseButton onClose={() => setError(null)}>{error}</Alert> : null}
        </Modal>
        <RegexDebugger opened={debugOpen} onClose={() => setDebugOpen(false)}
            initial={form.values.regex ? [{
                expr: form.values.regex,
                caseSensitive: form.values.case_sensitive,
            }] : undefined} />
    </>
}
