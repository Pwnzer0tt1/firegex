import { ActionIcon, Badge, Button, Group, Menu, Tooltip } from '@mantine/core';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { FaPlay, FaStop, FaTrash } from 'react-icons/fa';
import { IoSettingsSharp } from 'react-icons/io5';
import { MdMoreHoriz } from 'react-icons/md';
import { TbAlertTriangle } from 'react-icons/tb';
import { bareAddress, errorNotify, okNotify } from '../../js/utils';
import { LEVEL_COLOR, Pill, serviceStateLabel, serviceTone, Sparkline } from '../Shell/ui';
import YesNoModal from '../YesNoModal';
import AddEditService from './AddEditService';
import { Address, L4, protoLabel, Service, serviceQueryKey, services, Transport } from './utils';

/** What the network layer means, in one line, where the operator is choosing. */
export const transportLabel = (transport: string) => ({
    [Transport.PROXY]: "PROXY",
    [Transport.NFQUEUE]: "NFQUEUE",
    [Transport.EXTERNAL]: "YOUR PROXY",
}[transport] ?? transport.toUpperCase())

/**
 * What a service's layer does, in one short line, for the tooltip on its badge.
 *
 * Short on purpose: a tooltip is glanced at, not read. The whole trade between the
 * layers is explained where the choice is made (`LayerChoice.tsx`) and in
 * `docs/services.md`; this only has to remind an operator which one they picked.
 */
export const transportSummary = (transport: string, proto: string) => {
    if (transport === Transport.EXTERNAL) return "Handed to your own proxy; no filters"
    if (transport === Transport.NFQUEUE) return "Packets inspected in place; fails open"
    if (proto === L4.HTTP) return "HTTP/1.1, /2 and /3 through one chain"
    if (proto === L4.QUIC) return "QUIC decrypted; each stream filtered"
    if (proto === L4.UDP) return "Relayed per address; state per flow"
    return "Connection terminated and reopened"
}

/** How long a warning stays on the row after it happened, unless the log is cleared first. */
const PROBLEM_SHOWN_MS = 60 * 60 * 1000

/**
 * The newest warning or error in the service's log, on the row, for an hour.
 *
 * The log is on the service's own page, and a problem there waits for somebody to open
 * it — the notification says it once, this keeps saying it for whoever looks at the list
 * afterwards. Clearing the log is how it is dismissed.
 */
export function ProblemBadge({ service }: { service: Service }) {
    const problem = service.problem
    if (!problem || Date.now() - problem.at > PROBLEM_SHOWN_MS) return null
    const error = problem.level === "error"
    return <Tooltip position="bottom" multiline w={380}
        label={`${new Date(problem.at).toLocaleTimeString(undefined, { hour12: false })} · ${problem.text}`}>
        <Badge color={error ? LEVEL_COLOR.error : LEVEL_COLOR.warn} variant="light" size="xs" radius="sm"
            leftSection={<TbAlertTriangle size={10} />}>
            {error ? "ERROR" : "WARNING"}
        </Badge>
    </Tooltip>
}

/** Where a service is reachable, short enough to sit on one line. */
export const addressSummary = (addresses: Address[]) => {
    if (!addresses || addresses.length === 0) return "no address yet"
    const first = `${bareAddress(addresses[0].ip_int)}:${addresses[0].port}`
    return addresses.length === 1 ? first : `${first} +${addresses.length - 1} more`
}

/**
 * Everything about a service that is not start/stop.
 *
 * One component, used both in the list and on the service's own page: the two used to
 * offer different buttons for the same service — an "Options" menu holding only
 * settings in one place, a row of separate buttons in the other — so which actions
 * existed depended on where you happened to be looking at it from.
 */
export function ServiceMenu({ onSettings, onDelete, compact }: {
    onSettings: () => void, onDelete: () => void,
    /** An icon instead of a labelled button, for the tight space at the end of a row. */
    compact?: boolean,
}) {
    return <Menu position="bottom-end">
        <Menu.Target>
            {compact
                ? <ActionIcon variant="default" size={26} aria-label="Options"><MdMoreHoriz size={16} /></ActionIcon>
                : <Button variant="default" size="xs" leftSection={<MdMoreHoriz size={14} />}>Options</Button>}
        </Menu.Target>
        <Menu.Dropdown>
            <Menu.Label>Network layer</Menu.Label>
            <Menu.Item leftSection={<IoSettingsSharp size={14} />} onClick={onSettings}>
                Settings
            </Menu.Item>
            <Menu.Divider />
            <Menu.Item color="red" leftSection={<FaTrash size={12} />} onClick={onDelete}>
                Delete this service
            </Menu.Item>
        </Menu.Dropdown>
    </Menu>
}

/** How far back the sparkline and the "recent" count look. */
const RECENT_SECONDS = 15 * 60

/**
 * What a service refused in the last {@link RECENT_SECONDS}, one number per bucket.
 *
 * Keyed exactly as `serviceStatsQuery` keys a relative range, so the list and the
 * service's own page share one cache entry instead of asking twice. Polled, because a
 * block does not emit the `update` event (a flood of them would flood every browser),
 * and the point of this column is to show an attack starting.
 */
function useRecentBlocks(service: Service) {
    const enabled = service.n_filters > 0
    const stats = useQuery({
        queryKey: [...serviceQueryKey, service.service_id, "stats", RECENT_SECONDS, "auto"],
        queryFn: () => services.stats(service.service_id, { seconds: RECENT_SECONDS }),
        enabled,
        refetchInterval: 30_000,
    })
    if (!enabled || !stats.data) return { perBucket: [] as number[], total: null as number | null }
    const { buckets, series, total } = stats.data
    const perBucket = buckets.map((_, i) => series.reduce((sum, s) => sum + (s.counts[i] ?? 0), 0))
    return { perBucket, total }
}

/** A number in the table, or a dash where there is nothing it could be. */
const Num = ({ value }: { value: number | null }) => value === null
    ? <span className="fg-dash">—</span>
    : <span className="fg-num" style={{ color: value > 0 ? "var(--fg-text)" : "var(--fg-text-muted)" }}>
        {value.toLocaleString()}
    </span>

/**
 * One service as a row of the overview table.
 *
 * Everything an operator scans for during a round is a column — state, filters, what
 * was refused lately and the shape of it — and everything else is one click away on
 * the service's own page. Start and stop stay on the row because they are the action
 * the problem strip most often asks for.
 */
export default function ServiceTableRow({ service, onClick }: { service: Service, onClick: () => void }) {
    const queryClient = useQueryClient()
    const [loading, setLoading] = useState(false)
    const [deleteModal, setDeleteModal] = useState(false)
    const [editModal, setEditModal] = useState(false)
    const recent = useRecentBlocks(service)

    const running = service.status === "active"
    const tone = serviceTone(service)
    const external = service.transport === Transport.EXTERNAL
    const first = service.addresses?.[0]

    const act = async (what: "start" | "stop") => {
        setLoading(true)
        try {
            const err = what === "start"
                ? await services.start(service.service_id)
                : await services.stop(service.service_id)
            if (err) errorNotify(`Could not ${what} ${service.name}`, err)
            else {
                okNotify(`Service ${service.name} ${what === "start" ? "started" : "stopped"}`,
                    addressSummary(service.addresses))
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }
        } catch (err) {
            errorNotify(`Could not ${what} ${service.name}`, `${err}`)
        }
        setLoading(false)
    }

    const remove = async () => {
        try {
            const err = await services.remove(service.service_id)
            if (err) errorNotify("Could not delete the service", err)
            else {
                okNotify("Service deleted", `${service.name} is gone`)
                queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            }
        } catch (err) {
            errorNotify("Could not delete the service", `${err}`)
        }
    }

    return <>
        <tr className={tone === "danger" ? "danger" : tone === "warn" ? "warn" : undefined} onClick={onClick}>
            <td>
                <Group gap={8} wrap="nowrap">
                    <span className="fg-svc-name">{service.name}</span>
                    <ProblemBadge service={service} />
                </Group>
                <Tooltip position="bottom" disabled={(service.addresses?.length ?? 0) < 2}
                    label={(service.addresses ?? []).map(a => `${bareAddress(a.ip_int)}:${a.port}/${a.proto}`).join(", ")}>
                    <div className="fg-svc-sub">
                        {first
                            ? <>{first.port}/{first.proto} · {bareAddress(first.ip_int)}
                                {service.addresses.length > 1 ? ` +${service.addresses.length - 1}` : ""}</>
                            : "no address yet"}
                    </div>
                </Tooltip>
            </td>
            <td><Pill tone={tone}>{serviceStateLabel(service)}</Pill></td>
            <td className="fg-hide-sm">
                <Tooltip position="bottom" label={transportSummary(service.transport, service.proto)}>
                    <span className="fg-tag"><b>{transportLabel(service.transport)}</b>{protoLabel(service.proto)}</span>
                </Tooltip>
            </td>
            <td className="fg-hide-sm" style={{ whiteSpace: "nowrap" }}>
                {external
                    ? <span className="fg-dash">—</span>
                    : service.n_filters === 0
                        ? <span style={{ color: "var(--fg-warn)" }}>none</span>
                        : <span>{service.n_filters} filter{service.n_filters === 1 ? "" : "s"}</span>}
            </td>
            <td className="num fg-hide-sm"><Num value={external ? null : recent.total} /></td>
            <td className="num fg-hide-md"><Num value={external ? null : service.n_blocked} /></td>
            <td className="fg-hide-lg"><Sparkline values={recent.perBucket} width={100} /></td>
            <td onClick={e => e.stopPropagation()} style={{ width: 1 }}>
                <Group gap={6} wrap="nowrap" justify="flex-end">
                    <Button variant="default" size="compact-sm" loading={loading}
                        leftSection={running ? <FaStop size={9} /> : <FaPlay size={9} />}
                        onClick={() => act(running ? "stop" : "start")}>
                        {running ? "Stop" : "Start"}
                    </Button>
                    <span className="fg-hide-sm">
                        <ServiceMenu compact onSettings={() => setEditModal(true)} onDelete={() => setDeleteModal(true)} />
                    </span>
                </Group>
            </td>
        </tr>
        <YesNoModal
            title="Delete this service?"
            description={`This stops protecting ${addressSummary(service.addresses)} and deletes every filter attached to it. The service itself keeps running, unprotected.`}
            onClose={() => setDeleteModal(false)}
            action={remove}
            opened={deleteModal}
        />
        <AddEditService opened={editModal} onClose={() => setEditModal(false)} edit={service} />
    </>
}
