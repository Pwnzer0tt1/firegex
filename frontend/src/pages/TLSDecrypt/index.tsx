import { ActionIcon, Box, Button, Checkbox, Code, Collapse, Group, Modal, NumberInput, Paper, Space, Table, Text, TextInput, Textarea, Title, Tooltip, FileButton } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useDisclosure } from "@mantine/hooks";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { FaPlay, FaStop, FaTrash, FaPencilAlt } from "react-icons/fa";
import { MdAdd } from "react-icons/md";
import { getapi, postapi, putapi, deleteapi, errorNotify, okNotify } from "../../js/utils";
import PortAndInterface from "../../components/PortAndInterface";
import { TbShieldLock } from "react-icons/tb";
import { DocsButton } from "../../components/DocsButton";

export const tlsStreamsQueryKey = ["tls_streams"];

interface TLSStream {
  id: string;
  name: string;
  ip_int: string;
  port: number;
  cert: string;
  key: string;
  status: string;
  ssl_port: number;
  clear_port: number;
}

const StreamFormModal = ({ opened, close, editStream }: { opened: boolean, close: () => void, editStream?: TLSStream | null }) => {
  const queryClient = useQueryClient();
  const [loading, setLoading] = useState(false);
  const isEdit = !!editStream;

  const form = useForm({
    initialValues: {
      name: "",
      ip_int: "",
      port: 443,
      cert: "",
      key: ""
    },
    validate: {
      name: (val) => val.length > 0 ? null : "Name is required",
      ip_int: (val) => val.length > 0 ? null : "Target IP is required",
      port: (val) => val > 0 && val <= 65535 ? null : "Invalid port",
      cert: (val) => val.length > 0 ? null : "Certificate is required",
      key: (val) => val.length > 0 ? null : "Private Key is required"
    }
  });

  useEffect(() => {
    if (opened) {
      if (editStream) {
        form.setValues({
          name: editStream.name,
          ip_int: editStream.ip_int,
          port: editStream.port,
          cert: editStream.cert,
          key: editStream.key
        });
      } else {
        form.reset();
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [opened, editStream?.id]);

  const mutation = useMutation({
    mutationFn: (values: typeof form.values) => {
      return isEdit ? putapi(`tls/streams/${editStream!.id}`, values) : postapi("tls/streams", values);
    },
    onSuccess: () => {
      okNotify(isEdit ? "Stream updated" : "Stream created", `The TLS stream was successfully ${isEdit ? "updated" : "created"}`);
      queryClient.invalidateQueries({ queryKey: tlsStreamsQueryKey });
      form.reset();
      close();
    },
    onError: (err: any) => {
      errorNotify(`Error ${isEdit ? "updating" : "creating"} stream`, err.toString());
    },
    onSettled: () => setLoading(false)
  });

  const handleFileUpload = (file: File | null, fieldName: string) => {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      const text = e.target?.result as string;
      form.setFieldValue(fieldName, text);
    };
    reader.readAsText(file);
  };

  return (
    <Modal opened={opened} onClose={close} title={<Group gap="xs"><TbShieldLock size={20} color="var(--accent-color)" /><Text fw={500}>{isEdit ? "Edit TLS Decrypt Stream" : "Add New TLS Decrypt Stream"}</Text></Group>} centered styles={{ body: { maxHeight: 'calc(100vh - 150px)', overflowY: 'auto' } }}>
      <form onSubmit={form.onSubmit((v) => { setLoading(true); mutation.mutate(v); })}>
        <TextInput label="Name" placeholder="My HTTPS Service" {...form.getInputProps("name")} required />
        <Space h="sm" />
        <PortAndInterface form={form} int_name="ip_int" port_name="port" label="Target" />
        <Space h="sm" />

        <Group justify="space-between" align="center" mb={4}>
          <Text size="sm" fw={500}>TLS Certificate (PEM format) <Text span c="red">*</Text></Text>
          <FileButton onChange={(file) => handleFileUpload(file, 'cert')} accept=".pem,.crt,.cer,.txt,*">
            {(props) => <Button {...props} size="xs" variant="subtle">Load from file</Button>}
          </FileButton>
        </Group>
        <Textarea placeholder="-----BEGIN CERTIFICATE-----..." minRows={4} styles={{ input: { fontFamily: 'monospace' } }} {...form.getInputProps("cert")} required />

        <Space h="sm" />

        <Group justify="space-between" align="center" mb={4}>
          <Text size="sm" fw={500}>TLS Private Key (PEM format) <Text span c="red">*</Text></Text>
          <FileButton onChange={(file) => handleFileUpload(file, 'key')} accept=".pem,.key,.txt,*">
            {(props) => <Button {...props} size="xs" variant="subtle">Load from file</Button>}
          </FileButton>
        </Group>
        <Textarea placeholder="-----BEGIN PRIVATE KEY-----..." minRows={4} styles={{ input: { fontFamily: 'monospace' } }} {...form.getInputProps("key")} required />
        <Space h="md" />
        <Group justify="right">
          <Button type="submit" loading={loading}>{isEdit ? "Save Changes" : "Create Stream"}</Button>
        </Group>
      </form>
    </Modal>
  );
};

const TLSDecrypt = () => {
  const queryClient = useQueryClient();
  const [opened, { open, close }] = useDisclosure(false);
  const [editStream, setEditStream] = useState<TLSStream | null>(null);

  const { data: streams, isLoading } = useQuery<TLSStream[]>({
    queryKey: tlsStreamsQueryKey,
    queryFn: () => getapi("tls/streams")
  });

  const actionMutation = useMutation({
    mutationFn: ({ action, id }: { action: string, id: string }) => {
      if (action === "delete") return deleteapi(`tls/streams/${id}`);
      return postapi(`tls/streams/${id}/${action}`);
    },
    onSuccess: (_, { action }) => {
      okNotify("Success", `Stream ${action} successful`);
      queryClient.invalidateQueries({ queryKey: tlsStreamsQueryKey });
    },
    onError: (err: any) => {
      errorNotify("Error", err.toString());
    }
  });

  const openAdd = () => { setEditStream(null); open(); };
  const openEdit = (stream: TLSStream) => { setEditStream(stream); open(); };

  return (
    <Box p="md">
      <Group justify="space-between" mb="md">
        <Title order={2}>TLS Decryption Streams</Title>
        <Group gap="xs">
          <DocsButton doc="tls" />
          <Button leftSection={<MdAdd />} onClick={openAdd}>Add Stream</Button>
        </Group>
      </Group>

      <Text c="dimmed" mb="xl">
        Manage central TLS decryption streams. These streams transparently decrypt inbound TLS traffic,
        forward it to inspection services like NFProxy/NFRegex in cleartext, and re-encrypt the traffic
        before sending it to the backend.
      </Text>

      <Box p="md" style={{ backgroundColor: 'var(--third_color)', borderRadius: '16px', border: '1px solid var(--fourth_color)', boxShadow: '0 8px 32px rgba(0,0,0,0.3)' }}>
        <Table highlightOnHover>
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Name</Table.Th>
              <Table.Th>Target</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Internal SSL Port</Table.Th>
              <Table.Th>Internal Clear Port</Table.Th>
              <Table.Th>Actions</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {streams?.map(stream => (
              <Table.Tr key={stream.id}>
                <Table.Td>{stream.name}</Table.Td>
                <Table.Td>{stream.ip_int}:{stream.port}</Table.Td>
                <Table.Td>
                  <Text c={stream.status === "active" ? "green" : "red"} fw={500}>
                    {stream.status.toUpperCase()}
                  </Text>
                </Table.Td>
                <Table.Td><Code>{stream.ssl_port}</Code></Table.Td>
                <Table.Td><Code>{stream.clear_port}</Code></Table.Td>
                <Table.Td>
                  <Group gap="xs">
                    {stream.status === "stop" ? (
                      <Tooltip label="Start Stream">
                        <ActionIcon color="green" onClick={() => actionMutation.mutate({ action: "start", id: stream.id })}>
                          <FaPlay />
                        </ActionIcon>
                      </Tooltip>
                    ) : (
                      <Tooltip label="Stop Stream">
                        <ActionIcon color="orange" onClick={() => actionMutation.mutate({ action: "stop", id: stream.id })}>
                          <FaStop />
                        </ActionIcon>
                      </Tooltip>
                    )}
                    <Tooltip label="Edit Stream">
                      <ActionIcon color="cyan" onClick={() => openEdit(stream)}>
                        <FaPencilAlt />
                      </ActionIcon>
                    </Tooltip>
                    <Tooltip label="Delete Stream">
                      <ActionIcon color="red" onClick={() => actionMutation.mutate({ action: "delete", id: stream.id })}>
                        <FaTrash />
                      </ActionIcon>
                    </Tooltip>
                  </Group>
                </Table.Td>
              </Table.Tr>
            ))}
            {streams?.length === 0 && (
              <Table.Tr>
                <Table.Td colSpan={6} ta="center">No streams found</Table.Td>
              </Table.Tr>
            )}
          </Table.Tbody>
        </Table>
      </Box>

      <StreamFormModal opened={opened} close={() => { close(); setEditStream(null); }} editStream={editStream} />
    </Box>
  );
};

export default TLSDecrypt;
