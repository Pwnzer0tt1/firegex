import { Box, Button, Select, Space, TextInput, Textarea, Title, Group, FileButton, Text } from '@mantine/core';
import { UseFormReturnType } from '@mantine/form';
import { useQuery } from '@tanstack/react-query';
import { useEffect, useState } from 'react';
import { getapi, regex_ipv4, regex_ipv6 } from '../js/utils';
import PortAndInterface from './PortAndInterface';
import { MdAdd } from 'react-icons/md';

interface TLSServiceFieldsProps {
    form: UseFormReturnType<any>;
    disabled?: boolean;
}

export default function TLSServiceFields({ form, disabled }: TLSServiceFieldsProps) {
    const { data: streams, isLoading } = useQuery<any[]>({
        queryKey: ["tls_streams"],
        queryFn: () => getapi("tls/streams")
    });

    const [isCreatingNew, setIsCreatingNew] = useState(false);

    useEffect(() => {
        // Don't auto-pick/overwrite the stream selection while editing an existing
        // service — its ip_int/port/tls_stream_id already reflect the bound stream.
        if (disabled) return;
        if (!isCreatingNew && form.values.tls_enabled && streams && streams.length > 0) {
            const match = streams.find(s => s.ip_int === form.values.ip_int && s.port === form.values.port);
            if (!match) {
                form.setFieldValue('ip_int', streams[0].ip_int);
                form.setFieldValue('port', streams[0].port);
                form.setFieldValue('tls_stream_id', streams[0].id);
            } else if (!form.values.tls_stream_id) {
                form.setFieldValue('tls_stream_id', match.id);
            }
        }
    }, [streams, isCreatingNew, form.values.tls_enabled, disabled]);

    const handleFileUpload = (file: File | null, fieldName: string) => {
        if (!file) return;
        const reader = new FileReader();
        reader.onload = (e) => {
            const text = e.target?.result as string;
            form.setFieldValue(fieldName, text);
        };
        reader.readAsText(file);
    };

    if (!form.values.tls_enabled) return null;

    return (
        <Box pt="md">
            <Group justify="space-between" align="center" mb="sm">
                <Title order={6}>TLS Decryption Target</Title>
                <Button size="xs" variant="light" leftSection={<MdAdd />} onClick={() => setIsCreatingNew(!isCreatingNew)} disabled={disabled}>
                    {isCreatingNew ? "Select Existing" : "Create New"}
                </Button>
            </Group>
            <Space h="sm" />

            {!isCreatingNew ? (
                <Select
                    data={streams?.map(s => ({
                        value: s.id,
                        label: `${s.name} (${s.ip_int}:${s.port})`
                    })) || []}
                    value={form.values.tls_stream_id || null}
                    onChange={(val) => {
                        if (val) {
                            form.setFieldValue('tls_stream_id', val);
                            const stream = streams?.find(s => s.id === val);
                            if (stream) {
                                form.setFieldValue('ip_int', stream.ip_int);
                                form.setFieldValue('port', stream.port);
                            }
                        }
                    }}
                    placeholder="Select a TLS Stream"
                    disabled={disabled || isLoading}
                />
            ) : (
                <>
                    <PortAndInterface form={form} int_name="ip_int" port_name="port" label="New TLS Stream Target IP & Port" />
                    <Space h="sm" />
                    
                    <Group justify="space-between" align="center" mb={4}>
                        <Text size="sm" fw={500}>TLS Certificate (PEM format) {isCreatingNew && form.values.tls_enabled && <Text span c="red">*</Text>}</Text>
                        <FileButton onChange={(file) => handleFileUpload(file, 'tls_cert')} accept=".pem,.crt,.cer,.txt,*">
                            {(props) => <Button {...props} size="xs" variant="subtle">Load from file</Button>}
                        </FileButton>
                    </Group>
                    <Textarea 
                        placeholder="-----BEGIN CERTIFICATE-----..." 
                        minRows={4} 
                        styles={{ input: { fontFamily: 'monospace' } }} 
                        {...form.getInputProps('tls_cert')} 
                        required={isCreatingNew && form.values.tls_enabled}
                    />
                    
                    <Space h="sm" />
                    
                    <Group justify="space-between" align="center" mb={4}>
                        <Text size="sm" fw={500}>TLS Private Key (PEM format) {isCreatingNew && form.values.tls_enabled && <Text span c="red">*</Text>}</Text>
                        <FileButton onChange={(file) => handleFileUpload(file, 'tls_key')} accept=".pem,.key,.txt,*">
                            {(props) => <Button {...props} size="xs" variant="subtle">Load from file</Button>}
                        </FileButton>
                    </Group>
                    <Textarea 
                        placeholder="-----BEGIN PRIVATE KEY-----..." 
                        minRows={4} 
                        styles={{ input: { fontFamily: 'monospace' } }} 
                        {...form.getInputProps('tls_key')} 
                        required={isCreatingNew && form.values.tls_enabled}
                    />
                </>
            )}
        </Box>
    );
}
