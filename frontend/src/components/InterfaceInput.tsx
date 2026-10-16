import { Badge, Box, Combobox, Group, Loader, Text, TextInput, useCombobox } from "@mantine/core";
import { useViewportSize } from "@mantine/hooks";
import { useMemo, useState } from "react";
import { TbCheck, TbDeviceDesktopSearch, TbPlugConnected } from "react-icons/tb";
import { bareAddress, ipInterfacesQuery, isInterfaceName, isIpAddress } from "../js/utils";

/** A value the caller wants offered beside what the host actually has (`ANY`, a CIDR). */
export interface InterfaceOption {
    value: string
    /** The badge it is listed under. */
    netint: string
    label?: string
}

interface InterfaceInputProps {
    initialCustomInterfaces?: InterfaceOption[]
    /** Whether interface *names* are a valid answer here, or only addresses. */
    includeInterfaceNames?: boolean
    onChange?: (value: string) => void
    value?: string
    defaultValue?: string
    placeholder?: string
    error?: React.ReactNode
    disabled?: boolean
}

type Kind = { label: string, color: string }

/** One width for the badge everywhere it appears, so the field and the list line up. */
export const BADGE_WIDTH = 86

/**
 * The narrowest the note beside a value may be squeezed before it moves to its own line.
 * Just wide enough for `on docker0`; the point of having one at all is that without it a
 * long value took every pixel and left the note wrapping towards a character per line.
 */
const DETAIL_FLOOR = 80

/**
 * How wide the list is: what *this* host needs, between a floor and a ceiling.
 *
 * Three ways of deciding this were wrong before this one. Left to the content it
 * collapsed to the field's width, because content allowed to wrap asks for less than it
 * needs to stay on one line — 200px of list in a firewall rule. Pinned to the widest row
 * any host could produce, every list was that wide whether or not anything in it was
 * long, which beside a field half the size reads as a panel that escaped. A floor alone
 * put the one long address back over three lines.
 *
 * So it is measured from the longest value actually in the list: a host whose addresses
 * are `10.60.3.1` and `wg0` gets the floor, and one carrying a full-length IPv6 gets the
 * room to show it with its note beside it. Monospace is what makes this honest — every
 * character is the same width, so the arithmetic is the layout's, not a guess.
 */
const DROPDOWN_FLOOR = 420
const DROPDOWN_CEILING = 560
//: The value is `size="sm"` monospace, whose advance is 0.6em of 14px.
const CH = 8.5
//: What the row costs before the value: the list's padding, the option's, the badge and
//  the two gaps, plus the floor the note keeps for itself.
const ROW_CHROME = 36 + BADGE_WIDTH + 16 + DETAIL_FLOOR

const dropdownWidth = (longestValue: number, viewport: number) => {
    const room = Math.max(240, viewport - 24)
    const needed = ROW_CHROME + Math.ceil(longestValue * CH)
    return Math.min(room, Math.max(
        Math.min(DROPDOWN_FLOOR, room),
        Math.min(needed, DROPDOWN_CEILING),
    ))
}

/**
 * What the operator has typed, named.
 *
 * The badge is not decoration: an interface name and an address are matched by
 * completely different nftables rules, and a typo in one reads as the other — `eth-0`
 * is a perfectly good interface name and a perfectly wrong address. Saying which one
 * firegex understood, while it is being typed, is the cheapest place to catch that.
 */
export const addressKind = (value: string, interfacesAllowed = true): Kind => {
    //: `/32` and `/128` are how the backend spells one address, not a range.
    const v = bareAddress(value.trim())
    if (v === "") return { label: "ANY", color: "gray" }
    if (isIpAddress(v, { cidr: true }))
        return v.includes("/")
            ? { label: v.includes(":") ? "IPv6 NET" : "IPv4 NET", color: "violet" }
            : { label: v.includes(":") ? "IPv6" : "IPv4", color: "teal" }
    // Named red where this field does not take one, rather than blue and then refused on
    // submit: the two are told apart by eye here, and "that is an interface" is only
    // reassuring somewhere an interface is an answer.
    if (isInterfaceName(v))
        return interfacesAllowed
            ? { label: "INTERFACE", color: "blue" }
            : { label: "INVALID", color: "red" }
    return { label: "INVALID", color: "red" }
}

type Row = {
    value: string
    /** What is written in bold on the option. */
    title: string
    /** The dimmed half: an interface's addresses, or an address's interface. */
    detail: string
    badge: string
    color: string
    group: string
    /** Lowercased haystack, so typing an interface name also finds its addresses. */
    haystack: string
}

/**
 * A link-local address is not a place anybody dials.
 *
 * Every interface carries an `fe80::` it was never configured with — offering them
 * doubles the list with addresses that would put a service where no client will look
 * for it, which is the same reason `udp_relay_host()` picks them last on the backend.
 * They are still accepted if one is typed; they are just not *offered*, and an
 * interface that has nothing else says so rather than listing one.
 */
const isLinkLocal = (addr: string) =>
    addr.toLowerCase().startsWith("fe80:") || addr.startsWith("169.254.")

const IFACES_GROUP = "Network interfaces"
const ADDRS_GROUP = "Addresses on this host"
const PRESET_GROUP = "Common choices"

/**
 * Where an address — or an interface — is chosen.
 *
 * Both, because the datapath takes both, and the two are genuinely different things
 * rather than two spellings of one: an address is a place, an interface is *wherever
 * that cable currently is*, which is what you want for a link whose address is handed
 * out by somebody else. So the list says which is which, and an interface carries the
 * addresses it holds right now — the one question an operator has when choosing between
 * them is "and what is on it".
 *
 * Free text is still the point: this is a combobox and not a select, because the
 * address a service will answer on does not have to exist on this host yet.
 */
export const InterfaceInput = ({
    initialCustomInterfaces, includeInterfaceNames, onChange, value, defaultValue,
    placeholder, error, disabled,
}: InterfaceInputProps) => {
    const interfacesQuery = ipInterfacesQuery()
    const { width: viewport } = useViewportSize()

    const controlled = value !== undefined
    const [internal, setInternal] = useState(defaultValue ?? "")
    const current = controlled ? value : internal
    //: What is being *searched for*, which is only the same as the value while typing.
    //  Opening the dropdown clears it, so a click always shows the whole host rather
    //  than the one option whose name is already in the box.
    const [query, setQuery] = useState<string | null>(null)

    const combobox = useCombobox({ onDropdownClose: () => combobox.resetSelectedOption() })

    const rows = useMemo<Row[]>(() => {
        const addrs = interfacesQuery.data ?? []
        //: One entry per interface, carrying every address it holds.
        const byIface = new Map<string, string[]>()
        //: …and the other way round, because one address can be on more than one.
        const byAddr = new Map<string, string[]>()
        for (const { name, addr } of addrs) {
            if (!byIface.has(name)) byIface.set(name, [])
            if (!byIface.get(name)!.includes(addr)) byIface.get(name)!.push(addr)
            if (!byAddr.has(addr)) byAddr.set(addr, [])
            if (!byAddr.get(addr)!.includes(name)) byAddr.get(addr)!.push(name)
        }

        const presets: Row[] = (initialCustomInterfaces ?? []).map(item => ({
            value: item.value,
            title: item.label ?? (item.value === "" ? "Any address" : item.value),
            detail: "",
            badge: item.netint,
            color: "gray",
            group: PRESET_GROUP,
            haystack: `${item.label ?? ""} ${item.value} ${item.netint}`.toLowerCase(),
        }))

        const ifaces: Row[] = includeInterfaceNames
            ? [...byIface.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([name, ips]) => ({
                value: name,
                title: name,
                // A no-break space before each separator, so a line that has to wrap
                // breaks *between* two addresses and never leaves a dot stranded at the
                // start of the next one.
                detail: ips.some(ip => !isLinkLocal(ip))
                    ? ips.filter(ip => !isLinkLocal(ip)).join("\u00a0· ")
                    : (ips.length > 0 ? "link-local only" : "no address assigned"),
                badge: "INTERFACE",
                color: "blue",
                group: IFACES_GROUP,
                haystack: `${name} ${ips.join(" ")}`.toLowerCase(),
            }))
            : []

        const ips: Row[] = [...byAddr.entries()]
            .filter(([addr]) => !isLinkLocal(addr))
            .sort((a, b) => (a[0].includes(":") === b[0].includes(":"))
                ? a[0].localeCompare(b[0])
                : (a[0].includes(":") ? 1 : -1))
            .map(([addr, names]) => ({
                value: addr,
                title: addr,
                detail: `on ${names.join(", ")}`,
                badge: addr.includes(":") ? "IPv6" : "IPv4",
                color: "teal",
                group: ADDRS_GROUP,
                haystack: `${addr} ${names.join(" ")}`.toLowerCase(),
            }))

        const seen = new Set(presets.map(p => p.value))
        return [...presets, ...[...ifaces, ...ips].filter(r => !seen.has(r.value))]
    }, [interfacesQuery.data, includeInterfaceNames, initialCustomInterfaces])

    const search = (query ?? "").toLowerCase().trim()
    const visible = search === "" ? rows : rows.filter(r => r.haystack.includes(search))
    const exact = rows.some(r => r.value === (query ?? current).trim())

    const commit = (v: string) => {
        if (!controlled) setInternal(v)
        onChange?.(v)
    }

    /**
     * The badge is a column; everything else lives in the one beside it.
     *
     * Not three items in one wrapping row, which is what this was: a value too long to
     * sit beside the badge wrapped to the *container's* left edge, under the badge,
     * leaving a row three lines tall whose address started nowhere near the addresses
     * above it. Inside its own column it wraps under itself instead, and the detail
     * follows it — the value and its note stay one block, aligned down the list.
     *
     * Which of the two is the long one changes with the group — the addresses a link
     * carries in one, the address itself in the other — so neither is given a fixed
     * share: the value takes what it needs and the detail keeps a floor just wide
     * enough for `on docker0`, below which it moves to its own line rather than being
     * squeezed towards a character per line. The floor is what the longest address on
     * a host leaves over at the list's width, so that row stays on one line too.
     *
     * The tick goes next to the value rather than at the end of the row, because the
     * end of the row is a place that moves.
     */
    const option = (row: Row) => <Combobox.Option value={row.value} key={`${row.group}/${row.value}`}
        active={row.value === current}>
        <Group gap="xs" wrap="nowrap" align="flex-start">
            <Badge size="xs" variant="light" color={row.color}
                style={{ flexShrink: 0, width: BADGE_WIDTH, marginTop: 2 }}>{row.badge}</Badge>
            <Group gap="xs" wrap="wrap" align="baseline"
                style={{ flex: '1 1 auto', minWidth: 0, rowGap: 0 }}>
                <Text size="sm" ff="monospace" style={{ minWidth: 0, overflowWrap: 'anywhere' }}>
                    {row.title}
                </Text>
                {row.value === current
                    ? <TbCheck size={14} style={{ flexShrink: 0 }} color="var(--mantine-color-teal-4)" />
                    : null}
                {row.detail ? <Text size="xs" c="dimmed" ff="monospace"
                    style={{
                        flex: `1 1 ${DETAIL_FLOOR}px`, minWidth: DETAIL_FLOOR,
                        textAlign: 'right', overflowWrap: 'anywhere',
                    }}>{row.detail}</Text> : null}
            </Group>
        </Group>
    </Combobox.Option>

    const group = (name: string, icon: React.ReactNode) => {
        const inside = visible.filter(r => r.group === name)
        if (inside.length === 0) return null
        return <Combobox.Group label={<Group gap={6}>{icon}<span>{name}</span></Group>}>
            {inside.map(option)}
        </Combobox.Group>
    }

    const kind = addressKind(current ?? "", includeInterfaceNames !== false)
    const typed = (query ?? "").trim()
    const typedKind = addressKind(typed, includeInterfaceNames !== false)

    return <Combobox
        store={combobox}
        width={dropdownWidth(
            rows.reduce((longest, r) => Math.max(longest, r.title.length), 0),
            viewport,
        )}
        // Portalled, so the list is not clipped by whatever it sits in: inside a firewall
        // rule's card it used to be cut off halfway down the options.
        position="bottom-start"
        disabled={disabled}
        onOptionSubmit={(v) => {
            commit(v)
            setQuery(null)
            combobox.closeDropdown()
        }}
    >
        <Combobox.Target>
            <TextInput
                style={{ width: "100%" }}
                disabled={disabled}
                error={error}
                value={query ?? current ?? ""}
                placeholder={placeholder ?? (includeInterfaceNames
                    ? "IP address or interface name" : "IP address")}
                leftSectionWidth={BADGE_WIDTH + 16}
                leftSection={<Badge size="xs" variant="light" color={kind.color}
                    style={{ width: BADGE_WIDTH }}>{kind.label}</Badge>}
                rightSection={interfacesQuery.isLoading ? <Loader size={14} /> : <Combobox.Chevron />}
                rightSectionPointerEvents="none"
                onChange={(event) => {
                    const v = event.currentTarget.value
                    setQuery(v)
                    commit(v)
                    combobox.openDropdown()
                    combobox.updateSelectedOptionIndex()
                }}
                // Opening clears the search rather than filtering by whatever is already
                // in the box: the value is usually an exact option, and filtering by it
                // would show the operator only the thing they were trying to change.
                onClick={() => { setQuery(null); combobox.openDropdown() }}
                onFocus={() => { setQuery(null); combobox.openDropdown() }}
                onBlur={() => { setQuery(null); combobox.closeDropdown() }}
            />
        </Combobox.Target>

        <Combobox.Dropdown>
            <Combobox.Options mah={260} style={{ overflowY: 'auto' }}>
                {group(PRESET_GROUP, null)}
                {group(IFACES_GROUP, <TbPlugConnected size={13} />)}
                {group(ADDRS_GROUP, <TbDeviceDesktopSearch size={13} />)}
                {!exact && typed.length > 0 ? <Combobox.Option value={typed}>
                    <Group gap="xs" wrap="nowrap">
                        <Badge size="xs" variant="light" color={typedKind.color}
                            style={{ flexShrink: 0, width: BADGE_WIDTH }}>{typedKind.label}</Badge>
                        <Text size="sm">Use <Text span ff="monospace">{typed}</Text></Text>
                    </Group>
                </Combobox.Option> : null}
                {visible.length === 0 && typed.length === 0 ? <Combobox.Empty>
                    {interfacesQuery.isLoading ? "Reading this host's interfaces…"
                        : "This host reports no address"}
                </Combobox.Empty> : null}
            </Combobox.Options>
            <Box px="xs" py={6} style={{ borderTop: '1px solid var(--mantine-color-dark-4)' }}>
                <Text size="xs" c="dimmed">
                    {includeInterfaceNames
                        ? "An interface name follows the link: whatever address it is given, the rules match on the name. An address protects that one address only."
                        : "One address here, not an interface name — the rules built from it need a single address to rewrite."}
                </Text>
            </Box>
        </Combobox.Dropdown>
    </Combobox>
}
