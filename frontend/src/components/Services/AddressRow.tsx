import { ActionIcon, Badge, Box, Group, Popover, Space, Text, Tooltip } from '@mantine/core';
import { useState } from 'react';
import { BsTrashFill } from 'react-icons/bs';
import { IoSettingsSharp } from 'react-icons/io5';
import PortAndInterface from '../PortAndInterface';
import AddressOptions, { addressCapabilities, addressTags } from './AddressOptions';

/**
 * One address being filled in, and everything that can be said about it.
 *
 * The row itself stays what it was — where the service answers — because that is what
 * every address needs and most addresses need only that. How a web service's address is
 * reached is not on the row: the form groups the rows by it (HTTP, HTTPS, HTTP/3). Everything else is **behind one button**: traffic sent on to another port,
 * what firegex speaks to the service, the endpoint of somebody else's proxy. Those were
 * inline once, each of them, and a list of three addresses became a screenful of fields
 * for cases most services never have.
 *
 * What is set is said back on the row as **tags**, and a tag opens the panel it came
 * from: folded is not hidden, and an option an operator cannot see they set is an option
 * that will surprise them at the worst moment.
 *
 * Which options exist at all, and how they are worded, live in `AddressOptions`; the
 * service page reads them back with the same `addressTags`.
 */
export default function AddressRow({ form, index, proto, transport }: {
    form: any,
    index: number,
    /** What the service speaks, which decides which options exist at all. */
    proto: string,
    transport: string,
}) {
    const [open, setOpen] = useState(false)
    const address = form.values.addresses[index]
    const caps = addressCapabilities(proto, transport, address.edge)
    const tags = addressTags(address, caps)
    const anything = caps.canPublish || caps.canChooseUpstream || caps.isExternal

    return <Box mb="sm">
        <Group align="flex-end" wrap="nowrap" gap="xs">
            <Box style={{ flex: 1 }}>
                <PortAndInterface form={form}
                    int_name={`addresses.${index}.ip_int`}
                    port_name={`addresses.${index}.port`}
                    includeInterfaceNames={!caps.isExternal} />
            </Box>
            {anything ? <Popover opened={open} onChange={setOpen} width={330}
                position="bottom-end" withArrow shadow="md" radius="md">
                <Popover.Target>
                    <Tooltip label="More about this address" position="top" disabled={open}>
                        <ActionIcon variant="subtle" color="gray" mb={4}
                            onClick={() => setOpen(o => !o)}>
                            <IoSettingsSharp size={14} />
                        </ActionIcon>
                    </Tooltip>
                </Popover.Target>
                <Popover.Dropdown>
                    <Text size="xs" c="dimmed" mb="xs">
                        Only this address. Everything here is off unless you set it.
                    </Text>
                    <AddressOptions form={form} values={address}
                        field={name => `addresses.${index}.${name}`}
                        proto={proto} transport={transport} />
                </Popover.Dropdown>
            </Popover> : null}
            <ActionIcon variant="subtle" color="red" mb={4}
                onClick={() => form.removeListItem('addresses', index)}>
                <BsTrashFill size={14} />
            </ActionIcon>
        </Group>
        {/* What was set, under the address it was set on. Clicking one opens the panel
            it came from — a tag that says a thing is on and cannot take you to it is a
            label, and the operator is left hunting for where they set it. */}
        {tags.length > 0 ? <Group gap={6} mt={4} ml={4}>
            {tags.map(tag => <Tooltip key={tag.label} label={tag.hint} position="bottom"
                multiline w={280}>
                <Badge size="xs" variant="light" color="teal" radius="sm"
                    style={{ cursor: 'pointer' }} onClick={() => setOpen(true)}>
                    {tag.label}
                </Badge>
            </Tooltip>)}
        </Group> : null}
        <Space h={2} />
    </Box>
}
