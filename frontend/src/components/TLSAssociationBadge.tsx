import { Badge, Tooltip } from '@mantine/core';
import { useQuery } from '@tanstack/react-query';
import { getapi } from '../js/utils';
import { TbShieldLock } from 'react-icons/tb';

interface TLSStream {
    id: string;
    name: string;
    ip_int: string;
    port: number;
    status: string;
    ssl_port: number;
    clear_port: number;
}

export default function TLSAssociationBadge({ tlsStreamId, size = "xs" }: { tlsStreamId?: string | null, size?: string }) {
    const { data: streams } = useQuery<TLSStream[]>({
        queryKey: ["tls_streams"],
        queryFn: () => getapi("tls/streams")
    });

    if (!tlsStreamId) return null;
    const stream = streams?.find(s => s.id === tlsStreamId);

    return (
        <Tooltip
            multiline
            w={280}
            label={stream
                ? `Decrypts TLS stream "${stream.name}" (public target ${stream.ip_int}:${stream.port}). The filter inspects the decrypted traffic on loopback:${stream.clear_port}, then it gets re-encrypted before reaching the real backend.`
                : "Linked to a TLS Decrypt stream (stream details unavailable)"}
        >
            <Badge color="green" size={size as any} variant="light" radius="sm" leftSection={<TbShieldLock size={12} style={{ marginTop: 2 }} />}>
                TLS{stream ? `: ${stream.name}` : ""}
            </Badge>
        </Tooltip>
    )
}
