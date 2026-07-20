import { Space, Switch, Textarea } from '@mantine/core';
import { UseFormReturnType } from '@mantine/form';
import { useEffect } from 'react';
import { getapi, regex_ipv4, regex_ipv6 } from '../js/utils';

interface TLSServiceFieldsProps {
    form: UseFormReturnType<any>;
    disabled?: boolean;
}

export default function TLSServiceFields({ form, disabled }: TLSServiceFieldsProps) {
    useEffect(() => {
        if (!form.values.tls_enabled || !form.values.ip_int || !form.values.port) {
            return;
        }

        const isIpValid = form.values.ip_int.match(regex_ipv4) || form.values.ip_int.match(regex_ipv6);
        const isPortValid = form.values.port > 0 && form.values.port < 65536;
        if (!isIpValid || !isPortValid) {
            return;
        }

        const debounceTimer = setTimeout(() => {
            getapi(`certificates?ip_int=${encodeURIComponent(form.values.ip_int)}&port=${form.values.port}`)
                .then(res => {
                    if (res && res.cert) {
                        form.setFieldValue('tls_cert', res.cert);
                    }
                    if (res && res.key) {
                        form.setFieldValue('tls_key', res.key);
                    }
                })
                .catch(err => {
                    console.error("Failed to fetch certificate", err);
                });
        }, 500);

        return () => clearTimeout(debounceTimer);
    }, [form.values.tls_enabled, form.values.ip_int, form.values.port]);

    useEffect(() => {
        if (disabled && form.values.tls_enabled) {
            form.setFieldValue('tls_enabled', false);
        }
    }, [disabled, form.values.tls_enabled]);

    return (
        <>
            <Space h="md" />
            <Switch
                label="Enable TLS Decryption / Encryption"
                description="Decrypt and encrypt incoming and outgoing traffic using Nginx stream proxy"
                disabled={disabled}
                {...form.getInputProps('tls_enabled', { type: 'checkbox' })}
            />
            {form.values.tls_enabled && (
                <>
                    <Space h="md" />
                    <Textarea
                        label="TLS Certificate (PEM format)"
                        placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                        minRows={4}
                        styles={{ input: { fontFamily: 'monospace' } }}
                        {...form.getInputProps('tls_cert')}
                    />
                    <Space h="md" />
                    <Textarea
                        label="TLS Private Key (PEM format)"
                        placeholder="-----BEGIN PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
                        minRows={4}
                        styles={{ input: { fontFamily: 'monospace' } }}
                        {...form.getInputProps('tls_key')}
                    />
                </>
            )}
        </>
    );
}
