import { Accordion, ActionIcon, Alert, Box, Button, Code, Group, Modal, NumberInput, Space, Switch, Text, TextInput, Tooltip } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useQueryClient } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { BsPlusLg, BsTrashFill } from 'react-icons/bs';
import { errorNotify, isAddressOrInterface, isInterfaceName, okNotify } from '../../js/utils';
import { addressCapabilities } from './AddressOptions';
import AddressRow from './AddressRow';
import LayerChoice from './LayerChoice';
import PemInput from './PemInput';
import ProtocolChoice from './ProtocolChoice';
import { AddressForm, decrypts, L4, Upstream, Service, ServiceAddForm, serviceQueryKey, services, Transport } from './utils';

type AddressValues = {
    ip_int: string,
    port: number,
    proxy_ip: string,
    proxy_port: number,
    /** `http` only: what is spoken at this address. */
    edge: string,
    /** Where the service is, when it is not on this port. Empty means "it is". */
    target_port: number | string,
    /** What the service behind this address speaks. */
    upstream: string,
}

type FormValues = {
    name: string,
    proto: string,
    transport: string,
    fail_open: boolean,
    max_connections: number,
    over_limit_forwards: boolean,
    first_byte_timeout: number,
    tls_cert: string,
    tls_key: string,
    addresses: AddressValues[],
    autostart: boolean,
}

const emptyAddress = (): AddressValues => ({
    ip_int: "127.0.0.1", port: 80, proxy_ip: "127.0.0.1", proxy_port: 8080,
    // Only ever read on an `http` service, where each address says what is spoken at it;
    // everywhere else the service's own protocol decides and this is ignored.
    edge: L4.TCP,
    // Both behind the row's own button, and both absent unless they were set: an address
    // is where the service listens, forwarded as it arrived, until somebody says else.
    target_port: "",
    upstream: Upstream.SAME,
})

/**
 * Create or edit the network layer of a service.
 *
 * Only the network layer: what to do with the traffic is chosen afterwards, by
 * attaching filters, and can be changed without coming back here. That split is the
 * point of the whole module — a service used to have to be recreated to swap between
 * regexes and Python, because the choice of one was also the choice of the other.
 *
 * Addresses are a list, and only when the service is being created. Editing them later
 * happens on the service's own page, one at a time, because adding an address to a
 * running service costs nothing while changing anything here restarts it.
 */
export default function AddEditService({ opened, onClose, edit }: {
    opened: boolean,
    onClose: () => void,
    /** When given, the modal edits this service instead of creating one. */
    edit?: Service,
}) {
    const queryClient = useQueryClient()
    const [submitting, setSubmitting] = useState(false)
    const [error, setError] = useState<string | null>(null)
    //: Whether leaving the two fields empty means anything. It does not for a new
    //  service, nor for one whose TLS switch has never been accompanied by material.
    const stored = !!edit?.has_tls_material

    const form = useForm<FormValues>({
        initialValues: {
            name: "", proto: L4.TCP,
            transport: Transport.PROXY, fail_open: true,
            max_connections: 0, over_limit_forwards: false, first_byte_timeout: 0,
            tls_cert: "", tls_key: "",
            addresses: [emptyAddress()],
            autostart: true,
        },
        validate: {
            name: v => v !== "" ? null : "A name is required",
            // An empty field is "unchanged" only when there is something to leave
            // unchanged: turning TLS on for a service that was never given a certificate
            // used to be accepted here and refused by nginx on the next start, which is
            // a failure the operator meets long after the edit that caused it. What is
            // checked whenever something *was* typed is the PEM envelope, the same check
            // the backend makes — so the wrong field is named instead of the whole form.
            tls_cert: (v, values) => {
                if (!decrypts(values)) return null
                if (v === "") return stored ? null : "A certificate is required"
                return v.includes("-----BEGIN CERTIFICATE-----") ? null
                    : "Not a PEM certificate: no 'BEGIN CERTIFICATE' block in it"
            },
            tls_key: (v, values) => {
                if (!decrypts(values)) return null
                if (v === "") return stored ? null : "A private key is required"
                if (v.includes("ENCRYPTED PRIVATE KEY-----"))
                    return "Passphrase-protected keys cannot be used: decrypt it first"
                return v.includes("PRIVATE KEY-----") ? null
                    : "Not a PEM private key: no 'BEGIN PRIVATE KEY' block in it"
            },
            addresses: {
                ip_int: (v, values) => !isAddressOrInterface(v,
                    { cidr: values.transport !== Transport.EXTERNAL })
                    ? "Not an IP address, and not an interface name either"
                    : (values.transport === Transport.EXTERNAL && isInterfaceName(v)
                        ? "Your own proxy is handed one address: the return rule has to put the original port back, and an interface is not one address"
                        : null),
                port: v => (v > 0 && v < 65536) ? null : "Invalid port",
                proxy_port: (v, values) => (values.transport !== Transport.EXTERNAL || (v > 0 && v < 65536))
                    ? null : "Your proxy's port is required",
            },
        },
    })

    useEffect(() => {
        if (!opened) return
        setError(null)
        if (edit) form.setValues({
            name: edit.name, proto: edit.proto, transport: edit.transport,
            fail_open: edit.fail_open,
            max_connections: edit.max_connections, over_limit_forwards: edit.over_limit_forwards,
            first_byte_timeout: edit.first_byte_timeout,
            tls_cert: "", tls_key: "",
            addresses: [emptyAddress()],
            autostart: true,
        })
        else form.reset()
    }, [opened, edit?.service_id])

    const close = () => { onClose(); form.reset(); setError(null) }

    const submit = async (values: FormValues) => {
        setSubmitting(true)
        const isExternal = values.transport === Transport.EXTERNAL
        const addresses: AddressForm[] = values.addresses.map(a => {
            // Per address, because on an HTTPS service what an address can say depends on
            // what it is reached over.
            const caps = addressCapabilities(values.proto, values.transport, a.edge)
            return {
                ip_int: a.ip_int,
                port: a.port,
                // Sent only where it means something — the same rules the ⚙ on each row
                // offers them by. Everywhere else the backend refuses them rather than
                // letting a stored value sit there being read by nothing.
                ...(values.proto === L4.HTTP ? { edge: a.edge } : {}),
                ...(caps.canPublish && Number(a.target_port) && Number(a.target_port) !== a.port
                    ? { target_port: Number(a.target_port) } : {}),
                ...(caps.canChooseUpstream && a.upstream !== Upstream.SAME
                    ? { upstream: a.upstream } : {}),
                ...(isExternal ? { proxy_ip: a.proxy_ip, proxy_port: a.proxy_port } : {}),
            }
        })

        try {
            if (edit) {
                // Addresses are not sent: they have their own endpoints, so that adding
                // one does not drop the connections on the others.
                const err = await services.edit(edit.service_id, {
                    name: values.name, proto: values.proto, transport: values.transport,
                    fail_open: values.fail_open,
                    max_connections: values.max_connections,
                    over_limit_forwards: values.over_limit_forwards,
                    first_byte_timeout: values.first_byte_timeout,
                    ...(decrypts(values) && values.tls_cert !== "" ? { tls_cert: values.tls_cert } : {}),
                    ...(decrypts(values) && values.tls_key !== "" ? { tls_key: values.tls_key } : {}),
                })
                if (err) { setError(err); setSubmitting(false); return }
                okNotify("Service updated", `${values.name} now uses the ${values.transport} transport`)
            } else {
                const payload: ServiceAddForm = {
                    name: values.name, proto: values.proto, transport: values.transport,
                    fail_open: values.fail_open, addresses,
                    max_connections: values.max_connections,
                    over_limit_forwards: values.over_limit_forwards,
                    first_byte_timeout: values.first_byte_timeout,
                }
                if (decrypts(values) && values.tls_cert !== "") payload.tls_cert = values.tls_cert
                if (decrypts(values) && values.tls_key !== "") payload.tls_key = values.tls_key
                const res = await services.add(payload)
                if (res.status !== "ok" || !res.service_id) { setError(res.status); setSubmitting(false); return }
                if (values.autostart) {
                    const err = await services.start(res.service_id)
                    if (err) errorNotify("The service was created but would not start", err)
                }
                okNotify("Service added", addresses.length === 1
                    ? `${values.name} will front ${addresses[0].ip_int}:${addresses[0].port}`
                    : `${values.name} will front ${addresses.length} addresses`)
            }
            queryClient.invalidateQueries({ queryKey: serviceQueryKey })
            close()
        } catch (err) {
            setError(`${err}`)
        }
        setSubmitting(false)
    }

    const isProxy = form.values.transport === Transport.PROXY
    //: On NFQUEUE the same number means something narrower: how many UDP flows keep what
    //  their Python filters hold. A datagram has no close to observe, so that is the one
    //  thing there with nothing but a count and an idle timeout to bound it; a TCP stream
    //  lets go of its state when it closes, and a limit on it would do nothing.
    const limitsQueuedFlows = form.values.transport === Transport.NFQUEUE
        && form.values.proto === L4.UDP
    //: Whether the engine terminates and decrypts this service — TLS or QUIC. What the
    //  certificate fields, their validation and the payload all key off, because the two
    //  protocols need exactly the same thing from the operator.
    const isEncrypted = decrypts(form.values)
    // What the fold would tell you if you opened it. Built from what *differs* rather
    // than listing every setting, so a service nobody has tuned says so in three words
    // and a service that has been says exactly how.
    const changed = [
        isProxy && form.values.max_connections > 0
            ? `at most ${form.values.max_connections} at once`
            : null,
        isProxy && form.values.max_connections > 0 && form.values.over_limit_forwards
            ? "the excess forwarded unfiltered"
            : null,
        limitsQueuedFlows && form.values.max_connections > 0
            ? `at most ${form.values.max_connections} UDP flows held`
            : null,
        isProxy && form.values.first_byte_timeout > 0
            ? `silent for ${form.values.first_byte_timeout}s is closed`
            : null,
        !isProxy && !form.values.fail_open ? "fail-open off" : null,
    ].filter(Boolean) as string[]
    // Leaving TLS selected while the layer that can decrypt it is not would send a
    // combination the backend refuses, and the operator would be looking at a protocol
    // the form is no longer offering.
    //: The layer is not offered for a service that is decrypted, so it has to be set
    //  rather than assumed: a form that hides a control still submits its value.
    useEffect(() => {
        if (isEncrypted && form.values.transport !== Transport.PROXY)
            form.setFieldValue('transport', Transport.PROXY)
    }, [isEncrypted])
    useEffect(() => {
        if (form.values.transport === Transport.PROXY) return
        // Neither survives leaving the layer that honours it. A stored limit that does
        // nothing is the same trap as a stored protocol nothing can decrypt.
        if (isEncrypted) form.setFieldValue('proto', L4.TCP)
        if (form.values.first_byte_timeout !== 0) form.setFieldValue('first_byte_timeout', 0)
    }, [form.values.transport])
    useEffect(() => {
        if (!isProxy && !limitsQueuedFlows && form.values.max_connections !== 0)
            form.setFieldValue('max_connections', 0)
    }, [form.values.transport, form.values.proto])
    const isExternal = form.values.transport === Transport.EXTERNAL
    //: `http` is the one protocol whose addresses are not all on the same transport, so
    //  it is the one where each of them has to say which it is.
    const isHttp = form.values.proto === L4.HTTP
    // The form is tall — addresses are a list, and the layer choice explains itself — so
    // the fields scroll and the actions do not. A submit button that falls below the
    // fold of a modal is a button that is not there.
    return <Modal size="xl" opened={opened} onClose={close} centered closeOnClickOutside={false}
        title={edit ? `Edit ${edit.name}` : "Add a new service"}
        styles={{ body: { paddingBottom: 0 } }}>
        <form onSubmit={form.onSubmit(submit)}
            style={{ display: 'flex', flexDirection: 'column', maxHeight: '72vh' }}>
            <Box style={{ overflowY: 'auto', flex: 1, minHeight: 0, paddingRight: 10 }}>
                <TextInput label="Service name" placeholder="shop-api" {...form.getInputProps('name')} />
                <Space h="md" />

                <ProtocolChoice value={form.values.proto} transport={form.values.transport}
                    onChange={v => form.setFieldValue('proto', v)} />
                {/* Directly under the choice that asks for them, not at the far end of the
                form. They used to sit below the advanced settings, which put the reason
                and the request a screenful apart: an operator who had just picked HTTP for
                a service answering in the clear met the fields with nothing next to them
                saying which choice had produced them, and read it as firegex wanting a
                certificate for a service that has none. */}
                {isEncrypted ? <>
                    <Space h="md" />
                    <PemInput label="Certificate (PEM)"
                        placeholder={edit ? "unchanged" : "-----BEGIN CERTIFICATE-----"}
                        expect="-----BEGIN CERTIFICATE-----"
                        value={form.values.tls_cert}
                        onChange={v => form.setFieldValue('tls_cert', v)}
                        error={form.errors.tls_cert} />
                    <Space h="sm" />
                    <PemInput label="Private key (PEM)"
                        placeholder={edit ? "unchanged" : "-----BEGIN PRIVATE KEY-----"}
                        expect="PRIVATE KEY-----"
                        value={form.values.tls_key}
                        onChange={v => form.setFieldValue('tls_key', v)}
                        error={form.errors.tls_key} />
                    {stored ? <Text size="xs" c="dimmed" mt={6}>
                        Both are already stored: leave these empty to keep them.
                    </Text> : null}
                </> : null}
                <Space h="md" />

                {edit ? null : <>
                    <Group justify="space-between" align="center" wrap="nowrap">
                        <Box style={{ minWidth: 0 }}>
                            <Text size="sm" fw={500}>Addresses to protect</Text>
                            <Text size="xs" c="dimmed">
                                {isExternal
                                    ? "One service, one hand-off, as many addresses as it answers on — IPv4 and IPv6 together if that is how it is reachable."
                                    : "One service, one filter chain, as many ways in as it has — IPv4 and IPv6 together if that is how it is reachable, and an interface name where the address is not yours to know. One more way in is one more address here."}
                            </Text>
                        </Box>
                        <Tooltip label="Protect another address with the same chain" position="left">
                            <ActionIcon variant="light" style={{ flexShrink: 0 }}
                                onClick={() => form.insertListItem('addresses', emptyAddress())}>
                                <BsPlusLg size={14} />
                            </ActionIcon>
                        </Tooltip>
                    </Group>
                    <Space h="xs" />
                    {form.values.addresses.map((_, index) =>
                        <AddressRow key={index} form={form} index={index}
                            proto={form.values.proto} transport={form.values.transport}
                            canRemove={form.values.addresses.length > 1} />)}
                    {/* Said once under the list rather than as a validation error per row:
                    the operator is choosing between an address and an interface while they
                    fill it in, and being told afterwards that half of what the picker
                    offered was never available here is the worse way to learn it. */}
                    <Text size="xs" c="dimmed">
                        {isExternal
                            ? "Interface names are not offered on this layer: the return rule recognises your proxy by one address and port to put the original port back, and an interface is not one address."
                            : <>
                                An interface name — <Code>eth0</Code>, <Code>wg0</Code>, <Code>tun0</Code> —
                                protects whatever address that link currently carries, which is what you
                                want when somebody else hands it out. An address protects that one alone.
                                {(form.values.proto === L4.UDP || form.values.proto === L4.QUIC)
                                    && form.values.transport === Transport.PROXY
                                    ? " On UDP and QUIC this layer binds a relay to the interface's own address, so it has to have one; NFQUEUE needs none."
                                    : ""}
                            </>}
                    </Text>
                    <Space h="md" />
                </>}

                {/* Not a choice for a service that is decrypted: decrypting means
                terminating the connection, and one layer does that. A picker with two
                greyed-out options and one answer is a question nobody is being asked, so
                it is said in a line instead — said rather than dropped, because the layer
                is a real property of the service and an operator who has read about the
                trade should not have to wonder which side of it they are on. */}
                {isEncrypted
                    ? <Text size="xs" c="dimmed">
                        Carried by the <b>proxy</b> layer, which is the only one that can
                        decrypt: the connection is terminated here and reopened towards
                        the service.
                    </Text>
                    : <LayerChoice value={form.values.transport} proto={form.values.proto}
                        onChange={v => form.setFieldValue('transport', v)} />}
                <Space h="md" />

                {/* One fold for everything an operator sets once — after something went
                wrong, or before a competition — and then never looks at again. Left in
                the open they are three more things to read past on every service that is
                created, and the form's own submit button is already fighting for room.
                Folded is not hidden: the summary says what differs from the defaults, so
                a service that has been tuned says so without being opened.

                Which settings are in here depends on the layer, because they belong to
                different ones. The connection limits are the proxy layer's — it is the
                one that accepts a connection and dials the service, and those two
                descriptors are what a limit counts. Fail-open is NFQUEUE's: it hands the
                kernel a verdict on packets already in flight, and what it can run out of
                is queue. The hand-off layer runs nothing of ours, so it has neither. */}
                {isExternal ? null : <>
                    <Accordion variant="contained" chevronPosition="left"
                        styles={{ content: { paddingInline: 'var(--mantine-spacing-sm)' } }}>
                        <Accordion.Item value="advanced">
                            <Accordion.Control>
                                <Text size="sm" fw={500}>Advanced settings</Text>
                                <Text size="xs" c="dimmed">
                                    {changed.length > 0
                                        ? changed.join(" · ")
                                        : "Everything at its default."}
                                </Text>
                            </Accordion.Control>
                            <Accordion.Panel>
                                {isProxy ? <>
                                    <NumberInput
                                        label="Most connections at once"
                                        description={form.values.max_connections > 0
                                            ? "Counted across TCP connections and UDP flows together — they spend the same descriptors."
                                            : "0 means no limit. Without one, connections that are opened and then say nothing can exhaust firegex and take every other service down with this one."}
                                        min={0} step={64} allowDecimal={false}
                                        {...form.getInputProps('max_connections')}
                                    />
                                    <Space h="sm" />
                                    <NumberInput
                                        label="Close a connection that says nothing, after"
                                        suffix=" s"
                                        description={form.values.first_byte_timeout > 0
                                            ? "Until the first byte only, in either direction — a service that greets its client satisfies it too. Once a connection has spoken it is never closed for going quiet."
                                            : "0 means never. This is what a limit alone cannot do: a connection opened and left silent holds a descriptor here and one on your service, having asked for nothing."}
                                        min={0} step={5} allowDecimal={false}
                                        {...form.getInputProps('first_byte_timeout')}
                                    />
                                    {form.values.max_connections > 0 ? <>
                                        <Space h="sm" />
                                        <Switch
                                            label="Forward what does not fit, unfiltered"
                                            description={form.values.over_limit_forwards
                                                ? "The service stays reachable past the limit, and that traffic reaches it with nothing having looked at it."
                                                : "Off: what does not fit is refused. Nothing reaches the service unexamined, and clients are turned away while the limit holds."}
                                            {...form.getInputProps('over_limit_forwards', { type: 'checkbox' })}
                                        />
                                    </> : null}
                                </> : <>
                                    <Switch
                                        label="Keep forwarding if the filter stops answering"
                                        description="The kernel's fail-open backstop. Turning it off means traffic stops when the filter does."
                                        {...form.getInputProps('fail_open', { type: 'checkbox' })}
                                    />
                                    {limitsQueuedFlows ? <>
                                        <Space h="sm" />
                                        <NumberInput
                                            label="Most UDP flows at once"
                                            description={form.values.max_connections > 0
                                                ? "Past it, the flow quiet the longest loses what its Python filters were keeping, and starts over."
                                                : "0 means no limit: a flow keeps its Python filters' state until it has been quiet for a minute."}
                                            min={0} step={64} allowDecimal={false}
                                            {...form.getInputProps('max_connections')}
                                        />
                                    </> : null}
                                </>}
                            </Accordion.Panel>
                        </Accordion.Item>
                    </Accordion>
                    <Space h="md" />
                </>}


                {edit ? null : <>
                    <Space h="md" />
                    <Switch label="Start it immediately" {...form.getInputProps('autostart', { type: 'checkbox' })} />
                </>}

                {edit ?
                    <Alert color="yellow" mt="md">
                        Changing any of this restarts the service, which drops the connections it
                        is carrying. Adding an address, or adding and reordering filters, does not.
                    </Alert> : null}
                <Space h="md" />
            </Box>

            {/* Outside the scrolling area, so it is reachable however long the form
                gets. The error lives here too: a refusal you have to scroll to find is
                a refusal you do not see. */}
            <Box style={{
                flexShrink: 0, paddingBlock: 'var(--mantine-spacing-sm)',
                background: 'var(--mantine-color-body)',
            }}>
                {error ? <Alert color="red" mb="sm" withCloseButton onClose={() => setError(null)}>
                    {error}
                </Alert> : null}
                <Group justify="flex-end">
                    <Button loading={submitting} type="submit">{edit ? "Save" : "Add service"}</Button>
                </Group>
            </Box>
        </form>
    </Modal>
}
