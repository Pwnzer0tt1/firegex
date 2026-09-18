import { Box, NumberInput, SegmentedControl, Stack, Text } from '@mantine/core';
import PortAndInterface from '../PortAndInterface';
import { decrypts, L4, Transport, Upstream } from './utils';

/**
 * Everything an address can say beyond where it is, written once.
 *
 * Two places ask for it — the rows of the creation form, behind each row's ⚙, and the
 * modal on the service's own page — and they used to ask in two sets of words. The same
 * setting described twice reads as two settings, which is the whole reason this file
 * exists; the capability rules below were written twice as well, so the form could offer
 * something the backend then refused.
 *
 * The wording rule here: **say what firegex will do**, not what the field is called.
 * "The service is on port" and "The service behind speaks" were both true and both left
 * the operator to work out the effect for themselves.
 */

/** Which of these options exist at all for the service being configured. */
export function addressCapabilities(proto: string, transport: string) {
    const isExternal = transport === Transport.EXTERNAL
    return {
        isExternal,
        /** `http` is the one protocol whose addresses are not all the same. */
        isHttp: proto === L4.HTTP,
        //: Sending traffic somewhere other than where it arrived takes something that
        //  *dials*, and that is the layer rather than the protocol: the proxy opens the
        //  connection to the service, NFQUEUE opens nothing, and the hand-off layer
        //  leaves the question to the proxy you run yourself.
        canPublish: transport === Transport.PROXY,
        //: Only a service firegex decrypts has a leg of its own towards the service. On
        //  a cleartext one it terminates nothing, so there is nothing to put back.
        canChooseUpstream: decrypts({ proto }) && transport === Transport.PROXY,
    }
}

/** What clients speak at one address of an HTTPS service. Shared so the row, the modal
 *  and the badge on the service page cannot come to call them three different things. */
export const EDGE_OPTIONS = [
    { label: 'Clear', value: L4.TCP },
    { label: 'TLS', value: L4.TLS },
    { label: 'HTTP/3', value: L4.QUIC },
]

export const edgeHint = (edge: string) =>
    edge === L4.QUIC
        ? "A UDP port speaking HTTP/3."
        : edge === L4.TLS
            ? "Encrypted only: a client that arrives in the clear here is refused."
            : "Cleartext HTTP/1.1 and HTTP/2 — and a client that brings TLS anyway is taken too."

export const upstreamHint = (upstream: string) =>
    upstream === Upstream.TCP
        ? "Firegex decrypts and sends plain HTTP/1.1. Only firegex holds a certificate."
        : upstream === Upstream.TLS
            ? "Firegex encrypts with TLS, even for a client that arrived over HTTP/3."
            : "Firegex sends what the client sent, encrypted again — so the service holds a certificate of its own."

type Extras = {
    port: number,
    target_port?: number | string | null,
    upstream?: string | null,
    proxy_ip?: string | null,
    proxy_port?: number | null,
}

/**
 * What is switched on for one address, in a word each.
 *
 * Shown under the address in the form and beside it on the service page — the same
 * labels in both, because this is where an operator comes back to check what they set,
 * and finding it named differently is a reason to wonder whether it is the same thing.
 */
export function addressTags(values: Extras, caps: ReturnType<typeof addressCapabilities>) {
    const tags: { label: string, hint: string }[] = []
    const target = Number(values.target_port)
    if (caps.canPublish && target && target !== values.port) tags.push({
        label: `→ :${target}`,
        hint: `Clients arrive on :${values.port} — firegex dials the service on :${target}, which is where it listens.`,
    })
    if (caps.canChooseUpstream && values.upstream === Upstream.TCP) tags.push({
        label: "plaintext to the service",
        hint: upstreamHint(Upstream.TCP),
    })
    if (caps.canChooseUpstream && values.upstream === Upstream.TLS) tags.push({
        label: "TLS to the service",
        hint: upstreamHint(Upstream.TLS),
    })
    if (caps.isExternal && values.proxy_port) tags.push({
        label: `→ ${values.proxy_ip ?? "127.0.0.1"}:${values.proxy_port}`,
        hint: "Traffic for this address is handed to your own proxy there, and put back on the way out.",
    })
    return tags
}

/**
 * The controls themselves, over whichever form is asking.
 *
 * `field` is what turns `target_port` into the name this form knows it by — bare in the
 * modal, `addresses.3.target_port` in a row of the creation form.
 */
export default function AddressOptions({ form, field, values, proto, transport }: {
    form: any,
    field: (name: string) => string,
    /** This address's own values, which is what the descriptions read back. */
    values: Extras,
    proto: string,
    transport: string,
}) {
    const caps = addressCapabilities(proto, transport)
    const port = Number(values.port)
    const target = Number(values.target_port)
    const upstream = String(values.upstream ?? Upstream.SAME)

    return <Stack gap="sm">
        {/* The label names the fact, and the description says what firegex does with
            it, because an effect alone leaves the direction open when both ends are
            ports. "Send it to another port" was read as "expose it on another port" and
            filled in the other way round: the service's own port typed into the address,
            and the port to publish on typed here — a service intercepted where it already
            listens and published nowhere. Both descriptions name **both** ends for that
            reason, and the empty one says where a second way in actually comes from. */}
        {caps.canPublish ? <NumberInput size="xs"
            label="The service is on another port"
            description={target && target !== port
                ? `Clients arrive on :${port} — firegex dials the service on :${target}.`
                : `Empty: the service listens here, on :${port || "…"}. Another way in is another address, not a port here.`}
            placeholder={`${port}`}
            min={0} max={65535} allowDecimal={false}
            {...form.getInputProps(field("target_port"))} />
            : null}
        {caps.canChooseUpstream ? <Box>
            <Text size="xs" fw={500}>Send to the service</Text>
            <Text size="xs" c="dimmed" mb={4}>{upstreamHint(upstream)}</Text>
            <SegmentedControl size="xs" fullWidth
                data={[
                    { label: 'What arrived', value: Upstream.SAME },
                    { label: 'Plaintext', value: Upstream.TCP },
                    { label: 'TLS', value: Upstream.TLS },
                ]}
                {...form.getInputProps(field("upstream"))} />
        </Box> : null}
        {caps.isExternal ? <Box>
            <PortAndInterface form={form}
                int_name={field("proxy_ip")}
                port_name={field("proxy_port")}
                label="Hand it to your proxy at"
                includeInterfaceNames={false} />
            <Text size="xs" c="dimmed" mt={4}>
                Its own port: the way back is recognised by it, so two addresses cannot
                share one.
            </Text>
        </Box> : null}
    </Stack>
}
