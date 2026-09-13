import { ActionIcon, Badge, Box, Button, Card, Code, Collapse, Group, Space, Stack, Switch, Text, Tooltip } from '@mantine/core';
import { CodeHighlight } from '@mantine/code-highlight';
import { useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { BsPlusLg, BsTrashFill } from 'react-icons/bs';
import { MdEdit } from 'react-icons/md';
import { FaCode, FaRegClone } from 'react-icons/fa';
import { MdDragIndicator, MdExpandLess, MdExpandMore } from 'react-icons/md';
import { VscRegex } from 'react-icons/vsc';
import { errorNotify, okNotify } from '../../js/utils';
import YesNoModal from '../YesNoModal';
import AddRegexModal from './AddRegexModal';
import CodeEditorModal from './CodeEditorModal';
import RegexDebugger from './RegexDebugger';
import { Filter, filterCodeQuery, filterFunctionsQuery, filterRegexesQuery, FilterKind, modeLabel, Regex, serviceQueryKey, services } from './utils';

const decode = (b64: string) => {
    try { return decodeURIComponent(escape(atob(b64))) } catch { return atob(b64) }
}

/**
 * One link in the chain, with whatever it holds.
 *
 * A regex filter holds patterns, compiled together into one hyperscan database — which
 * is why they live inside a filter rather than each being one. A pyfilter holds a
 * Python module.
 */
export default function FilterCard({ filter, serviceId, dragHandle, position, transport, proto }: {
    filter: Filter,
    serviceId: string,
    dragHandle?: any,
    position: number,
    /** The service's network layer, which decides whether rewriting is offered at all. */
    transport?: string,
    /** The service's transport protocol, which decides what a filter is actually shown. */
    proto?: string,
}) {
    const queryClient = useQueryClient()
    const isRegex = filter.kind === FilterKind.REGEX
    const regexes = filterRegexesQuery(isRegex ? serviceId : "", isRegex ? filter.filter_id : "")
    const functions = filterFunctionsQuery(isRegex ? "" : serviceId, isRegex ? "" : filter.filter_id)
    const [addOpen, setAddOpen] = useState(false)
    // Which pattern the edit modal is about, kept separately from whether it is open:
    // clearing it on close would turn the dialog back into "Add a pattern" while it is
    // still fading out.
    const [editing, setEditing] = useState<Regex | null>(null)
    const [editOpen, setEditOpen] = useState(false)
    const [codeOpen, setCodeOpen] = useState(false)
    const [debugOpen, setDebugOpen] = useState(false)
    const [deleteOpen, setDeleteOpen] = useState(false)
    // Open by default: for a pyfilter the code *is* the filter, and a card that hides it
    // shows a name and a counter — everything about the thing except what it does. It
    // still collapses, for a chain long enough that the page needs scrolling.
    const [showCode, setShowCode] = useState(true)
    const [busy, setBusy] = useState(false)
    const code = filterCodeQuery(isRegex ? "" : serviceId, isRegex ? "" : filter.filter_id)

    const refresh = () => queryClient.invalidateQueries({ queryKey: serviceQueryKey })

    const run = async (what: () => Promise<string | undefined>, failure: string) => {
        setBusy(true)
        try {
            const err = await what()
            if (err) errorNotify(failure, err)
            else refresh()
        } catch (err) {
            errorNotify(failure, `${err}`)
        }
        setBusy(false)
    }

    return <>
        <Card withBorder radius="md" p="md" w="100%" bg="transparent"
            style={{ borderColor: filter.active ? 'var(--fourth_color)' : 'var(--mantine-color-dark-4)' }}>
            <Group justify="space-between" wrap="nowrap" align="flex-start">
                <Group gap="xs" wrap="nowrap" align="center">
                    {dragHandle ? <Box {...dragHandle} style={{ cursor: 'grab', color: 'var(--text-secondary)' }}>
                        <MdDragIndicator size={20} />
                    </Box> : null}
                    <Badge circle variant="light" color="gray">{position + 1}</Badge>
                    {isRegex ? <VscRegex size={18} /> : <FaCode size={16} />}
                    <Box>
                        <Group gap="xs" align="center">
                            <Text fw={600}>{filter.name}</Text>
                            <Badge size="xs" radius="sm" variant="light" color={isRegex ? "violet" : "cyan"}>
                                {isRegex ? "REGEX" : "PYFILTER"}
                            </Badge>
                            {/* Only when it says something. A pyfilter's `tcp` is the
                                library's name for "asks for nothing in particular", and
                                showing it beside a service that speaks UDP read as a
                                contradiction — two different things wearing the same
                                three letters. */}
                            {!isRegex && filter.proto === "http" ?
                                <Tooltip position="bottom"
                                    label="Read off the code: asking for an HttpRequest is what makes a filter an HTTP one">
                                    <Badge size="xs" radius="sm" variant="outline" color="gray">
                                        HTTP
                                    </Badge>
                                </Tooltip> : null}
                            {filter.blocked > 0 ?
                                <Badge size="xs" radius="sm" variant="light" color="yellow">
                                    {filter.blocked} blocked
                                </Badge> : null}
                        </Group>
                        <Text size="xs" c="dimmed" mt={2}>
                            {isRegex
                                ? `${filter.n_regexes} pattern${filter.n_regexes === 1 ? "" : "s"}, matched in one pass`
                                : `${filter.n_functions} function${filter.n_functions === 1 ? "" : "s"}` +
                                  (filter.n_functions_active < filter.n_functions
                                      ? `, ${filter.n_functions - filter.n_functions_active} switched off`
                                      : "") +
                                  // What it is actually shown, which depends on what the
                                  // service carries — a datagram has no stream to assemble.
                                  (filter.proto === "http"
                                      ? " • over parsed HTTP requests and responses"
                                      : proto === "udp"
                                          ? " • over raw datagrams"
                                          : " • over raw payloads and TCP streams")}
                        </Text>
                    </Box>
                </Group>

                <Group gap="xs" wrap="nowrap">
                    <Tooltip label={filter.active ? "Stop consulting this filter" : "Put this filter back in the chain"} position="bottom">
                        <Switch checked={filter.active} disabled={busy}
                            onChange={e => run(
                                () => services.editFilter(serviceId, filter.filter_id, { active: e.currentTarget.checked }),
                                "Could not change the filter",
                            )} />
                    </Tooltip>
                    {isRegex
                        ? <>
                            <Tooltip label="Try a pattern against a sample" position="bottom">
                                <ActionIcon variant="light" color="grape" onClick={() => setDebugOpen(true)}>
                                    <FaRegClone size={14} />
                                </ActionIcon>
                            </Tooltip>
                            <Tooltip label="Add a pattern" position="bottom">
                                <ActionIcon variant="light" onClick={() => setAddOpen(true)}>
                                    <BsPlusLg size={14} />
                                </ActionIcon>
                            </Tooltip>
                        </>
                        : <>
                            <Tooltip label={showCode ? "Hide the code" : "Show the code"} position="bottom">
                                <ActionIcon variant="subtle" onClick={() => setShowCode(v => !v)}>
                                    {showCode ? <MdExpandLess size={18} /> : <MdExpandMore size={18} />}
                                </ActionIcon>
                            </Tooltip>
                            <Tooltip label="Edit the code" position="bottom">
                                <ActionIcon variant="light" onClick={() => setCodeOpen(true)}>
                                    <FaCode size={14} />
                                </ActionIcon>
                            </Tooltip>
                        </>}
                    <Tooltip label="Remove this filter" position="bottom">
                        <ActionIcon variant="light" color="red" onClick={() => setDeleteOpen(true)}>
                            <BsTrashFill size={14} />
                        </ActionIcon>
                    </Tooltip>
                </Group>
            </Group>

            {isRegex && regexes.data && regexes.data.length > 0 ? <>
                <Space h="sm" />
                <Stack gap={6}>
                    {regexes.data.map(rx => <Group key={rx.regex_id} justify="space-between" wrap="nowrap">
                        <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
                            <Code style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {decode(rx.regex)}
                            </Code>
                            <Badge size="xs" variant="light" color="red">block</Badge>
                            <Badge size="xs" variant="outline" color="gray">{modeLabel(rx.mode)}</Badge>
                            {rx.case_sensitive ? null :
                                <Badge size="xs" variant="outline" color="gray">any case</Badge>}
                            {rx.blocked > 0 ?
                                <Badge size="xs" variant="light" color="yellow">{rx.blocked}</Badge> : null}
                        </Group>
                        <Group gap={4} wrap="nowrap">
                            <Switch size="xs" checked={rx.active} disabled={busy}
                                onChange={e => run(
                                    () => services.editRegex(serviceId, filter.filter_id, rx.regex_id, { active: e.currentTarget.checked }),
                                    "Could not change the pattern",
                                )} />
                            <Tooltip label="Edit this pattern" position="bottom">
                                <ActionIcon size="sm" variant="subtle" disabled={busy}
                                    onClick={() => { setEditing(rx); setEditOpen(true) }}>
                                    <MdEdit size={13} />
                                </ActionIcon>
                            </Tooltip>
                            <ActionIcon size="sm" variant="subtle" color="red" disabled={busy}
                                onClick={() => run(
                                    () => services.deleteRegex(serviceId, filter.filter_id, rx.regex_id),
                                    "Could not delete the pattern",
                                )}>
                                <BsTrashFill size={12} />
                            </ActionIcon>
                        </Group>
                    </Group>)}
                </Stack>
            </> : null}

            {/* One line per `@pyfilter` the code defines. The code says which exist;
                these switches say which run, without the code being edited — deleting a
                function to stop consulting it and pasting it back to resume is what
                this replaces. */}
            {!isRegex && (functions.data?.length ?? 0) > 0 ? <>
                <Space h="sm" />
                <Stack gap={6}>
                    {functions.data!.map(fn => <Group key={fn.name} justify="space-between" wrap="nowrap">
                        <Group gap="xs" wrap="nowrap" style={{ minWidth: 0 }}>
                            <Code style={{ opacity: fn.active ? 1 : 0.5 }}>{fn.name}()</Code>
                            {fn.blocked > 0 ?
                                <Badge size="xs" variant="light" color="yellow">{fn.blocked}</Badge> : null}
                            {fn.active ? null :
                                <Badge size="xs" variant="outline" color="gray">off</Badge>}
                        </Group>
                        <Tooltip position="left"
                            label={fn.active ? "Stop calling this function" : "Call this function again"}>
                            <Switch size="xs" checked={fn.active} disabled={busy}
                                onChange={e => run(
                                    () => services.editFunction(serviceId, filter.filter_id, fn.name,
                                        { active: e.currentTarget.checked }),
                                    `Could not change ${fn.name}`,
                                )} />
                        </Tooltip>
                    </Group>)}
                </Stack>
            </> : null}

            {!isRegex && (functions.data?.length ?? 0) === 0 ? <>
                <Space h="sm" />
                <Group gap="xs">
                    <Text size="xs" c="dimmed">
                        No <Code>@pyfilter</Code> function yet, so this filter inspects nothing.
                    </Text>
                    <Button size="compact-xs" variant="light" onClick={() => setCodeOpen(true)}>
                        Write one
                    </Button>
                </Group>
            </> : null}

            {!isRegex ? <Collapse expanded={showCode}>
                <Space h="sm" />
                <Box style={{ maxHeight: 320, overflow: 'auto', borderRadius: 8 }}>
                    <CodeHighlight code={code.data ?? "# loading…"} language="python"
                        withCopyButton copyLabel="Copy the filter" />
                </Box>
            </Collapse> : null}

            {isRegex && filter.n_regexes === 0 ? <>
                <Space h="sm" />
                <Group gap="xs">
                    <Text size="xs" c="dimmed">No patterns yet, so this filter blocks nothing.</Text>
                    <Button size="compact-xs" variant="light" onClick={() => setAddOpen(true)}>Add one</Button>
                </Group>
            </> : null}
        </Card>

        <AddRegexModal opened={addOpen} onClose={() => setAddOpen(false)}
            serviceId={serviceId} filterId={filter.filter_id} transport={transport} />
        <AddRegexModal opened={editOpen} onClose={() => setEditOpen(false)}
            serviceId={serviceId} filterId={filter.filter_id} transport={transport}
            edit={editing ?? undefined} />
        <CodeEditorModal opened={codeOpen} onClose={() => setCodeOpen(false)}
            serviceId={serviceId} filterId={filter.filter_id} filterName={filter.name} />
        <RegexDebugger opened={debugOpen} onClose={() => setDebugOpen(false)}
            initial={(regexes.data ?? []).map(rx => ({
                expr: decode(rx.regex),
                caseSensitive: rx.case_sensitive,
            }))} />
        <YesNoModal
            title="Remove this filter?"
            description={`'${filter.name}' and everything in it will be deleted. The service keeps running with the rest of its chain.`}
            opened={deleteOpen}
            onClose={() => setDeleteOpen(false)}
            action={() => run(() => services.deleteFilter(serviceId, filter.filter_id), "Could not remove the filter")}
        />
    </>
}
