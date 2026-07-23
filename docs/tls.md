# 🔒 TLS Decryption

TLS Decryption is a decrypt-and-reinspect bridge for services that speak TLS natively. It exists because [Netfilter Regex](nfregex.md)/[Netfilter Proxy](nfproxy.md) can only inspect plaintext: if the real service terminates TLS itself, those modules would only ever see encrypted bytes. A TLS Decrypt stream terminates the public TLS connection, hands the plaintext to a local port where a filter service can attach, then re-encrypts before forwarding to the real backend.

This is **not** a generic "put TLS in front of a plaintext service" reverse proxy — the real backend is expected to also speak TLS natively (mirroring, for example, a CTF challenge service that does its own TLS).

## How to use it

1. Create a stream: the public `ip:port` clients connect to, and the certificate/key pair to present to them.
2. Start the stream.
3. Create an nfproxy or nfregex service with target type "TLS Decrypt", pointing at this stream, and start it. The filter now sees decrypted traffic.
4. You can edit a stream's certificate, IP or port at any time, even while services are attached to it — dependent services are automatically rebound to the new values, no manual reconfiguration needed.

### Start/stop cascade

Starting a filter service attached to a stopped TLS stream automatically starts the stream first. Stopping a TLS stream automatically stops every filter service attached to it (since there would be nothing left for them to inspect). A stream that still has a service attached to it can't be deleted — stop and detach (or delete) the dependent services first.

## How it works

Two loopback ports are involved, deterministically derived from a hash of the stream's public `ip:port` (so they don't need to be manually assigned or tracked):

1. `ssl_port` (loopback): [nginx](https://nginx.org/) terminates the public TLS connection here (TLS 1.2/1.3 only), using the stream's configured certificate/key, and forwards the **decrypted** traffic to `clear_port`.
2. `clear_port` (loopback): nginx re-encrypts the traffic (without verifying the real backend's certificate, since CTF services are commonly self-signed) and forwards it to the real `ip:port`.

The only unencrypted hop is the loopback leg between `ssl_port` and `clear_port` — this is exactly where an nfproxy/nfregex service attaches to see decrypted content. Traffic never touches the network unencrypted: both the public-facing leg and the leg to the real backend are TLS.

nftables DNATs the public `ip:port` to `ssl_port` so clients don't need to know about any of this — they just connect to the same address as always.
