# Firegex Python Library and CLI

This is the Python library for Firegex. It is used to get additional features of Firegex and use the feature of the command `fgex`.

## Installation

```bash
pip install -U firegex
```

fgex is an alias of firegex. You can use `fgex` instead of `firegex`.

## Command line usage:

```text
➤ fgex nfproxy -h

 Usage: fgex nfproxy [OPTIONS] FILTER_FILE ADDRESS PORT

 Run an nfproxy simulation

╭─ Arguments ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *    filter_file      TEXT     The path to the filter file [default: None] [required]                                                               │
│ *    address          TEXT     The address of the target to proxy [default: None] [required]                                                        │
│ *    port             INTEGER  The port of the target to proxy [default: None] [required]                                                           │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --proto                 [tcp|http]  The protocol to proxy [default: tcp]                                                                            │
│ --from-address          TEXT        The address of the local server [default: None]                                                                 │
│ --from-port             INTEGER     The port of the local server [default: 7474]                                                                    │
│                 -6                  Use IPv6 for the connection                                                                                     │
│ --help          -h                  Show this message and exit.                                                                                     │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## Library usage:

## NfProxy decorator

```python
from firegex.nfproxy import pyfilter
```
This decorator is used to create a filter for the nfproxy.
Example:
```python
@pyfilter
def my_filter(raw_packet: RawPacket): #Logging filter
    print(raw_packet.data)
```

## Data handlers

### RawPacket
```python
from firegex.nfproxy import RawPacket
```
This handler will be called every time arrives a packet from the network. It will receive a RawPacket object with the following properties:
- is_input: bool - It's true if the packet is an input packet, false if it's an output packet
- is_ipv6: bool - It's true if the packet is an ipv6 packet, false if it's an ipv4 packet
- is_tcp: bool - It's true if the packet is a tcp packet, false if it's an udp packet
- data: bytes - The data of the packet assembled and sorted from TCP
- l4_size: int - The size of the layer 4 data
- raw_packet_header_len: int - The size of the original packet header
- l4_data: bytes - The layer 4 payload of the packet
- raw_packet: bytes - The raw packet with IP and TCP headers

### TCPInputStream
Alias: TCPClientStream
```python
from firegex.nfproxy import TCPInputStream
```
This handler will be called every time a TCP stream is assembled in input. It will receive a TCPInputStream object with the following properties:
- data: bytes - The data of the packets assembled and sorted from TCP
- is_ipv6: bool - It's true if the packet is an ipv6 packet, false if it's an ipv4 packet
- total_stream_size: int - The size of the stream

### TCPOutputStream
Alias: TCPServerStream
```python
from firegex.nfproxy import TCPOutputStream
```
This handler will be called every time a TCP stream is assembled in output. It will receive a TCPOutputStream object with the following properties:
- data: bytes - The data of the packets assembled and sorted from TCP
- is_ipv6: bool - It's true if the packet is an ipv6 packet, false if it's an ipv4 packet
- total_stream_size: int - The size of the stream

### HttpRequest
```python
from firegex.nfproxy import HttpRequest
```
This handler will be called twice: one for the request headers and one for the request body. It will receive a HttpRequest object with the following properties:
- method: bytes - The method of the request
- url: str - The url of the request
- headers: dict - The headers of the request
- user_agent: str - The user agent of the request
- content_encoding: str - The content encoding of the request
- body: bytes - The body of the request
- headers_complete: bool - It's true if the headers are complete
- message_complete: bool - It's true if the message is complete
- http_version: str - The http version of the request
- keep_alive: bool - It's true if the request should keep alive
- should_upgrade: bool - It's true if the request should upgrade
- content_length: int - The content length of the request
- get_header(header: str, default=None): str - Get a header from the request without caring about the case
- total_size: int - The total size of the stream
- stream: bytes - The stream of the request

### HttpRequestHeader
```python
from firegex.nfproxy import HttpRequestHeader
```
This handler will be called only when the request headers are complete. It will receive a HttpRequestHeader object with the same properties as HttpRequest.

### HttpFullRequest
```python
from firegex.nfproxy import HttpFullRequest
```
This handler will be called only when the request is complete. It will receive a HttpFullRequest object with the same properties as HttpRequest.

### HttpResponse
```python
from firegex.nfproxy import HttpResponse
```
This handler will be called twice: one for the response headers and one for the response body. It will receive a HttpResponse object with the following properties:
- status_code: int - The status code of the response
- url: str - The url of the response
- headers: dict - The headers of the response
- user_agent: str - The user agent of the response
- content_encoding: str - The content encoding of the response
- body: bytes - The body of the response
- headers_complete: bool - It's true if the headers are complete
- message_complete: bool - It's true if the message is complete
- http_version: str - The http version of the response
- keep_alive: bool - It's true if the response should keep alive
- should_upgrade: bool - It's true if the response should upgrade
- content_length: int - The content length of the response
- get_header(header: str, default=None): str - Get a header from the response without caring about the case
- total_size: int - The total size of the stream
- stream: bytes - The stream of the response

### HttpResponseHeader
```python
from firegex.nfproxy import HttpResponseHeader
```
This handler will be called only when the response headers are complete. It will receive a HttpResponseHeader object with the same properties as HttpResponse.

### HttpFullResponse
```python
from firegex.nfproxy import HttpFullResponse
```
This handler will be called only when the response is complete. It will receive a HttpFullResponse object with the same properties as HttpResponse.
