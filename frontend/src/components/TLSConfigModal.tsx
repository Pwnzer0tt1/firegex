import { Button, Group, Space, Textarea, Switch, Modal, Notification } from '@mantine/core';
import { useForm } from '@mantine/form';
import { useEffect, useState } from 'react';
import { ImCross } from "react-icons/im";
import { okNotify } from '../js/utils';
import { useQueryClient } from '@tanstack/react-query';

export interface Service {
    service_id: string;
    name: string;
    port: number;
    proto: string;
    ip_int: string;
    fail_open: boolean;
    tls_enabled: boolean;
    tls_cert?: string;
    tls_key?: string;
    ssl_port?: number;
    clear_port?: number;
}

interface TLSConfigModalProps {
    opened: boolean;
    onClose: () => void;
    service: Service;
    updateTlsConfig: (serviceId: string, data: { tls_enabled: boolean; tls_cert: string | null; tls_key: string | null }) => Promise<string | undefined>;
    queryKey: readonly unknown[];
}

export default function TLSConfigModal({ opened, onClose, service, updateTlsConfig, queryKey }: TLSConfigModalProps) {
    const queryClient = useQueryClient();
    const [submitLoading, setSubmitLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const form = useForm({
        initialValues: {
            tls_enabled: service.tls_enabled,
            tls_cert: service.tls_cert ?? "",
            tls_key: service.tls_key ?? "",
        },
        validate: {
            tls_cert: (value, values) => values.tls_enabled && !value.trim() ? "Certificate is required when TLS is enabled" : null,
            tls_key: (value, values) => values.tls_enabled && !value.trim() ? "Private key is required when TLS is enabled" : null,
        }
    });

    useEffect(() => {
        if (opened) {
            form.setValues({
                tls_enabled: service.tls_enabled,
                tls_cert: service.tls_cert ?? "",
                tls_key: service.tls_key ?? "",
            });
            setError(null);
        }
    }, [opened, service]);

    const close = () => {
        onClose();
        form.reset();
        setError(null);
    };

    const submitRequest = (values: { tls_enabled: boolean; tls_cert: string; tls_key: string }) => {
        setSubmitLoading(true);
        setError(null);

        const payload = {
            tls_enabled: values.tls_enabled,
            tls_cert: values.tls_enabled ? values.tls_cert : null,
            tls_key: values.tls_enabled ? values.tls_key : null,
        };

        updateTlsConfig(service.service_id, payload)
            .then((res) => {
                setSubmitLoading(false);
                if (!res) {
                    close();
                    okNotify(`TLS configuration updated`, `Successfully updated TLS configuration for service ${service.name}`);
                    queryClient.invalidateQueries({ queryKey });
                } else {
                    setError(`Error: [ ${res} ]`);
                }
            })
            .catch((err) => {
                setSubmitLoading(false);
                setError(`Request Failed! [ ${err} ]`);
            });
    };

    return (
        <Modal size="xl" title={`TLS Configuration - ${service.name}`} opened={opened} onClose={close} closeOnClickOutside={false} centered>
            <form onSubmit={form.onSubmit(submitRequest)}>
                <Switch
                    label="Enable TLS Decryption / Encryption"
                    description="Decrypt and encrypt incoming and outgoing traffic using Nginx stream proxy"
                    {...form.getInputProps('tls_enabled', { type: 'checkbox' })}
                />
                
                {form.values.tls_enabled && (
                    <>
                        <Space h="md" />
                        <Textarea
                            label="TLS Certificate (PEM format)"
                            placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                            minRows={6}
                            styles={{ input: { fontFamily: 'monospace' } }}
                            {...form.getInputProps('tls_cert')}
                        />
                        <Space h="md" />
                        <Textarea
                            label="TLS Private Key (PEM format)"
                            placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                            minRows={6}
                            styles={{ input: { fontFamily: 'monospace' } }}
                            {...form.getInputProps('tls_key')}
                        />
                    </>
                )}

                <Group mt="xl" justify="flex-end" mb="sm">
                    <Button loading={submitLoading} type="submit">Save Configuration</Button>
                </Group>

                {error && (
                    <>
                        <Space h="md" />
                        <Notification icon={<ImCross size={14} />} color="red" onClose={() => setError(null)}>
                            Error: {error}
                        </Notification>
                        <Space h="md" />
                    </>
                )}
            </form>
        </Modal>
    );
}
