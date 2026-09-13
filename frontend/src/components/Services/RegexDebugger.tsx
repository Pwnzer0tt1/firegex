import { ActionIcon, Switch, Alert, Box, Button, Code, Group, Modal, ScrollArea, Space, Stack, Text, Textarea, TextInput } from '@mantine/core';
import { useEffect, useMemo, useState } from 'react';
import { BsPlusLg, BsTrashFill } from 'react-icons/bs';
import { DebugResult, services } from './utils';

/** One pattern under test, with a stable key so React does not reorder the inputs. */
type Draft = {
    key: string,
    expr: string,
    caseSensitive: boolean,
}

/**
 * Byte offsets in, character offsets out.
 *
 * The engine matches bytes and answers in byte offsets, but a textarea holds UTF-16
 * characters. For an all-ASCII sample the two agree and this is the identity; the
 * moment somebody pastes a UTF-8 payload — which is exactly the kind of thing worth
 * testing a pattern against — they stop agreeing and the highlighting drifts.
 */
function encodeSample(text: string) {
    const encoder = new TextEncoder()
    const byteToChar: number[] = []
    const bytes: number[] = []
    for (let charIndex = 0; charIndex < text.length; charIndex++) {
        const unit = text.charCodeAt(charIndex)
        // A surrogate pair is two characters carrying one code point; encoding them
        // separately would produce replacement bytes instead of the real ones.
        const isHighSurrogate = unit >= 0xd800 && unit <= 0xdbff
        const piece = isHighSurrogate ? text.slice(charIndex, charIndex + 2) : text[charIndex]
        for (const byte of encoder.encode(piece)) {
            byteToChar.push(charIndex)
            bytes.push(byte)
        }
        if (isHighSurrogate) charIndex++
    }
    byteToChar.push(text.length) // so an end offset one past the last byte still maps
    let binary = ""
    for (const byte of bytes) binary += String.fromCharCode(byte)
    return { b64: btoa(binary), byteToChar }
}

/** Merge the matched ranges into non-overlapping spans of the sample. */
function highlight(text: string, ranges: { start: number, end: number }[]) {
    if (ranges.length === 0) return [{ text, matched: false }]
    const sorted = [...ranges].sort((a, b) => a.start - b.start || b.end - a.end)
    const merged: { start: number, end: number }[] = []
    for (const range of sorted) {
        const last = merged[merged.length - 1]
        // Overlapping matches are normal — two patterns can cover the same bytes —
        // and nesting a mark inside a mark would just look like a rendering bug.
        if (last && range.start <= last.end) last.end = Math.max(last.end, range.end)
        else merged.push({ ...range })
    }
    const out: { text: string, matched: boolean }[] = []
    let cursor = 0
    for (const range of merged) {
        if (range.start > cursor) out.push({ text: text.slice(cursor, range.start), matched: false })
        out.push({ text: text.slice(range.start, range.end), matched: true })
        cursor = range.end
    }
    if (cursor < text.length) out.push({ text: text.slice(cursor), matched: false })
    return out
}

let nextKey = 0

/**
 * A regex tester inside firegex, running the engine that will enforce the answer.
 *
 * The point is that it cannot disagree with production. A tester built on JavaScript's
 * own RegExp would accept backreferences and lookarounds hyperscan rejects, and would
 * happily match things that will never match on the wire — so an operator would tune a
 * pattern here and find out mid-round that it was never valid.
 */
export default function RegexDebugger({ opened, onClose, initial }: {
    opened: boolean,
    onClose: () => void,
    /** Patterns to start from, usually the ones already in the filter. */
    initial?: { expr: string, caseSensitive: boolean, }[],
}) {
    const [drafts, setDrafts] = useState<Draft[]>([])
    const [sample, setSample] = useState("")
    const [result, setResult] = useState<DebugResult | null>(null)
    const [failed, setFailed] = useState<string | null>(null)
    const [running, setRunning] = useState(false)

    useEffect(() => {
        if (!opened) return
        const seed = (initial && initial.length > 0) ? initial : [{ expr: "", caseSensitive: true }]
        setDrafts(seed.map(p => ({
            key: `p${nextKey++}`,
            expr: p.expr,
            caseSensitive: p.caseSensitive,
        })))
    }, [opened])

    const encoded = useMemo(() => encodeSample(sample), [sample])
    const payload = JSON.stringify(
        drafts.map(d => [d.expr, d.caseSensitive, ])
    ) + " " + sample

    useEffect(() => {
        if (!opened) return
        const usable = drafts.filter(d => d.expr !== "")
        if (usable.length === 0) { setResult(null); setFailed(null); return }
        // Debounced: the operator is typing a pattern, and everything in between is a
        // pattern they have not finished writing.
        const timer = setTimeout(() => {
            setRunning(true)
            services.debug(
                usable.map(d => ({
                    id: d.key,
                    expr: d.expr,
                    case_sensitive: d.caseSensitive,
                    
                    
                })),
                encoded.b64,
            ).then(res => { setResult(res); setFailed(null) })
                .catch(err => { setResult(null); setFailed(err?.toString() ?? "the engine could not be reached") })
                .finally(() => setRunning(false))
        }, 250)
        return () => clearTimeout(timer)
    }, [payload, opened])

    const errorFor = (key: string) => result?.errors?.find(e => e.id === key)?.error
    const unscannableFor = (key: string) => result?.unscannable?.find(e => e.id === key)
    const countFor = (key: string) => result?.matches?.filter(m => m.id === key).length ?? 0

    const ranges = (result?.matches ?? []).map(m => ({
        start: encoded.byteToChar[m.start] ?? 0,
        end: encoded.byteToChar[m.end] ?? sample.length,
    }))
    const pieces = highlight(sample, ranges)

    const update = (key: string, patch: Partial<Draft>) =>
        setDrafts(d => d.map(item => item.key === key ? { ...item, ...patch } : item))

    return <Modal size="xl" opened={opened} onClose={onClose} centered title="Test a pattern">
        <Text size="sm" c="dimmed">
            Matched by hyperscan, the same engine that runs on the wire, so a pattern that
            works here works there and one it rejects is rejected here too.
        </Text>
        <Space h="md" />

        <Stack gap="xs">
            {drafts.map(draft => {
                const error = errorFor(draft.key)
                return <Box key={draft.key} p="sm" bg="dark.8" style={{ borderRadius: 8 }}>
                    <Group align="flex-start" wrap="nowrap">
                        <ActionIcon color="red" variant="subtle" mt={4} onClick={() => setDrafts(d => d.filter(item => item.key !== draft.key))}>
                            <BsTrashFill />
                        </ActionIcon>
                        <Stack style={{ flexGrow: 1 }} gap={4}>
                            <TextInput placeholder="Pattern" value={draft.expr}
                                onChange={(e) => update(draft.key, { expr: e.target.value })}
                                error={error} styles={{ input: { fontFamily: 'monospace' } }} />
                            <Group>
                                <Switch label="Case sensitive" size="xs" checked={draft.caseSensitive}
                                    onChange={(e) => update(draft.key, { caseSensitive: e.currentTarget.checked })} />
                            </Group>
                        </Stack>
                    </Group>
                </Box>
            })}
        </Stack>
        <Space h="xs" />
        <Button size="xs" variant="light" leftSection={<BsPlusLg size={12} />}
            onClick={() => setDrafts(d => [...d, {
                key: `p${nextKey++}`, expr: "", caseSensitive: true,
                
            }])}>
            Another pattern
        </Button>

        <Space h="md" />
        <Textarea
            label="Sample traffic"
            description="Whatever you would expect to see on the wire."
            autosize minRows={4} maxRows={10}
            styles={{ input: { fontFamily: 'monospace' } }}
            value={sample}
            onChange={e => setSample(e.currentTarget.value)}
        />

        <Space h="md" />
        <Text size="sm" fw={500}>Matches</Text>
        <Space h="xs" />
        <ScrollArea.Autosize mah={220}>
            <Code block style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all', minHeight: 60 }}>
                {sample === "" ? <Text size="sm" c="dimmed">Paste something above to see what matches.</Text>
                    : pieces.map((piece, i) => piece.matched
                        ? <mark key={i} style={{ background: '#ffd43b', color: '#000', borderRadius: 2 }}>{piece.text}</mark>
                        : <span key={i}>{piece.text}</span>)}
            </Code>
        </ScrollArea.Autosize>

    const update        {result?.truncated ?
            <Alert color="yellow" mt="md" title="Too many matches to show">
                Only the first thousand are listed. A pattern that matches this often will
                block on the first connection carrying any of it.
            </Alert> : null}
        {result?.error ? <Alert color="red" mt="md">{result.error}</Alert> : null}
        {failed ? <Alert color="red" mt="md">{failed}</Alert> : null}

        <Group justify="flex-end" mt="lg">
            <Text size="xs" c="dimmed">{running ? "matching..." : ""}</Text>
            <Button variant="light" onClick={onClose}>Close</Button>
        </Group>
    </Modal>
}
