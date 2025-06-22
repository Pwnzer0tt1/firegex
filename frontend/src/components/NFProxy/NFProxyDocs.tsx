import { CodeHighlight } from "@mantine/code-highlight";
import {
    Container,
    Title,
    Text,
    List,
    Code,
    Space,
    Badge,
    Box,
} from "@mantine/core";
import { CgEditBlackPoint } from "react-icons/cg";
import { EXAMPLE_PYFILTER } from "./utils";

const IMPORT_CODE_EXAMPLE = `from firegex.nfproxy import pyfilter, ACCEPT, REJECT`;

const FOO_FILTER_CODE = `from firegex.nfproxy import pyfilter, ACCEPT, REJECT

# This is NOT a filter
def useless_function() -> int:
    print("This is a useless function")
    return 42

@pyfilter
def none_filter(): # This is a filter that does nothing
    useless_function()
    return ACCEPT

`;

const TYPING_ARGS_EXAMPLE = `from firegex.nfproxy import pyfilter, ACCEPT, REJECT
from firegex.nfproxy.models import HttpRequest

@pyfilter
def filter_with_args(http_request: HttpRequest) -> int:
    if http_request.body:
      if b"ILLEGAL" in http_request.body:
        return REJECT
`;

const IMPORT_FULL_ACTION_STREAM = `from firegex.nfproxy import FullStreamAction

# Here the definition of FullStreamAction enum
class FullStreamAction(Enum):
    """Action to be taken by the filter when the stream is full"""
    FLUSH = 0
    ACCEPT = 1
    REJECT = 2
    DROP = 3
`;

const ENUM_IMPORT_AND_DEFINITION = `from firegex.nfproxy import ExceptionAction

# Here the definition of ExceptionAction enum
class ExceptionAction(Enum):
    """Action to be taken by the filter when an exception occurs (used in some cases)"""
    ACCEPT = 0    # Accept the packet that caused the exception
    DROP = 1      # Drop the connection that caused the exception
    REJECT = 2    # Reject the connection that caused the exception
    NOACTION = 3  # Do nothing, the excpetion will be signaled and the stream will be accepted without calling anymore the pyfilters (for the current stream)
`;

export const HELP_NFPROXY_SIM = `➤ fgex nfproxy -h

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
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯`;

const HttpBadge = () => {
    return (
        <Badge
            size="md"
            ml="xs"
            radius="md"
            variant="gradient"
            gradient={{ from: "red", to: "grape", deg: 107 }}
            style={{ fontSize: "13px", fontWeight: "bolder" }}
        >
            HTTP
        </Badge>
    );
};

const TCPBadge = () => {
    return (
        <Badge
            size="md"
            ml="xs"
            radius="md"
            variant="gradient"
            gradient={{ from: "indigo", to: "teal", deg: 164 }}
            style={{ fontSize: "13px", fontWeight: "bolder" }}
        >
            TCP
        </Badge>
    );
};

export const NFProxyDocs = () => {
    return (
        <>
            <Title order={1}>🌐 Netfilter Proxy Documentation</Title>

            <Title order={2} mt="xl" mb="sm">
                📖 Overview
            </Title>
            <Text size="lg">
                Netfilter Proxy is a simulated proxy that leverages{" "}
                <a href="https://netfilter.org/projects/libnetfilter_queue/">
                    nfqueue
                </a>{" "}
                to intercept network packets. It follows a similar workflow to
                NFRegex but introduces Python-based filtering capabilities,
                providing users with the flexibility to upload custom filters.
            </Text>

            <Title order={2} mt="lg" mb="sm">
                ⚙️ How to use Netfilter Proxy
            </Title>
            <Text size="lg">
                To use Netfilter Proxy, simply create and upload a Python
                filter. The filter is passed to the C++ binary, which then
                processes packets using the provided logic. This allows you to
                tailor the filtering behavior to your needs.
            </Text>
            <Title order={2} mt="lg" mb="sm">
                💡 How to write pyfilters?
            </Title>
            <Text size="lg">
                First of all install the firegex lib and update it running{" "}
                <Code>pip install -U fgex</Code>. After that you can use{" "}
                <Code>firegex</Code> module.
                <CodeHighlight
                    code={IMPORT_CODE_EXAMPLE}
                    language="python"
                    my="sm"
                />
                With this code we imported the <Code>pyfilter</Code> decorator
                and the <Code>ACCEPT</Code> and <Code>REJECT</Code> statements.
                <br />
                Let's create a first (useless) filter to see the syntax:
                <CodeHighlight
                    code={FOO_FILTER_CODE}
                    language="python"
                    my="sm"
                />
                You see that the filter must be decorated with the{" "}
                <Code>pyfilter</Code> decorator and must return a statement
                about how to manage that packet.
                <br />
                <Space h="sm" />
                You can save every data about the current flow in the global
                variables, the code you write will be executed only once for
                flow. The globals variables are isolated between flows. For each
                packet the filter functions will be called with the required
                paramethers and using the same globals as before.
                <br />
                <Space h="sm" />
                <strong>
                    Saving data in globals of other modules is not recommended,
                    because that memory is shared by the flows managed by the
                    same thread and lead to unexpected behaviors.
                </strong>
                <br />
                <Space h="sm" />
                <strong>
                    Global variables that starts with '__firegex' are reserved
                    for internal use, don't use them.
                </strong>
                <br />
                <Space h="sm" />
                You can manage when the function is called and also getting some
                data specifying some paramethers, using type decorators. Default
                values of the paramethers will be ignored, also kvargs values
                will be ignored.
                <br />
                <Space h="sm" />
                <strong>
                    Functions with no type decorator are considered invalid
                    pyfilters!
                </strong>
                <br />
                <Space h="sm" />
                <CodeHighlight
                    code={TYPING_ARGS_EXAMPLE}
                    language="python"
                    my="sm"
                />
                In this code we are filtering all the http requests that
                contains the word "ILLEGAL" in the body. All the other packets
                will be accepted (default behavior). The function will be called
                only if at least internally teh HTTP request header has been
                parsed, and also when the body will be parsed.
                <br />
                <Space h="sm" />
                If we have multiple paramether, the function will be called only
                if with the packet arrived is possible to build all the
                paramethers.
            </Text>
            <Title order={2} mt="lg" mb="sm">
                🔧 How can I test the filter?
            </Title>
            <Text size="lg">
                You can test your filter by using <Code>fgex</Code> command
                installed by firegex lib: This will run a local proxy to a
                remote destination with the filter you specified.
                <br />
                <Space h="sm" />
                This can be done by running for instance:{" "}
                <Code>
                    fgex nfproxy test_http.py 127.0.0.1 8080 --proto http
                </Code>
                <CodeHighlight code={HELP_NFPROXY_SIM} language="" my="sm" />
                You don't need to restart the proxy every time you change the
                filter, the filter will be reloaded automatically.
            </Text>
            <Title order={2} mt="lg" mb="sm">
                📦 Packet Statements
            </Title>
            <Text size="lg" my="xs">
                Here there are all the statments you can return from a filter:
                <List>
                    <List.Item>
                        <strong>ACCEPT: </strong> The packet will be accepted
                        and forwarded to the destination. (default if None is
                        returned)
                    </List.Item>
                    <List.Item>
                        <strong>REJECT: </strong> The connection will be closed
                        and all the packets will be dropped.
                    </List.Item>
                    <List.Item>
                        <strong>DROP: </strong> This packet and all the
                        following will be dropped. (This not simulate a
                        connection closure)
                    </List.Item>
                    <List.Item>
                        <strong>UNSTABLE_MANGLE: </strong> The packet will be
                        modified and forwarded. You can edit the packet only
                        with RawPacket data handler. (This is an unstable
                        statement, use it carefully)
                    </List.Item>
                </List>
            </Text>
            <Title order={2} mt="lg" mb="sm">
                ⚙️ Data Structures
            </Title>
            <Text size="lg" my="xs">
                Here there are all the data structure you can use for your
                filters:
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} /> RawPacket
                </Title>
                <Space w="sm" />
                <TCPBadge />
                <HttpBadge />
            </Box>
            <Text size="lg">
                This data is the raw packet processed by nfqueue. It contains:
            </Text>
            <Space h="sm" />
            <Text size="lg" ml="xs">
                <List>
                    <List.Item>
                        <strong>data: </strong> The raw packet data assembled by
                        libtins (read only).
                    </List.Item>
                    <List.Item>
                        <strong>is_input: </strong> It's true if the packet is
                        incoming, false if it's outgoing. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>is_ipv6: </strong> It's true if the packet is
                        IPv6, false if it's IPv4. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>is_tcp: </strong> It's true if the packet is
                        TCP, false if it's UDP. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>l4_size: </strong> The size of l4 payload (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>raw_packet_header_len: </strong> The size of the
                        raw packet header (read only)
                    </List.Item>
                    <List.Item>
                        <strong>raw_packet: </strong> The raw packet data with
                        ip and TCP header. You can edit all the packet content
                        and it will be modified if you send the UNSTABLE_MANGLE
                        statement.{" "}
                        <strong>
                            Be careful, beacause the associated layer 4 data can
                            be different from 'data' filed that instead arrives
                            from libtins.
                        </strong>
                        When you edit this field, l4_size and l4_data will be
                        updated automatically.
                    </List.Item>
                    <List.Item>
                        <strong>l4_data: </strong> The l4 payload data, directly
                        taken by the raw packet. You can edit all the packet
                        content and it will be modified if you send the
                        UNSTABLE_MANGLE statement.{" "}
                        <strong>
                            Be careful, beacause the associated layer 4 data can
                            be different from 'data' filed that instead arrives
                            from libtins.
                        </strong>{" "}
                        When you edit this field, l4_size and raw_packet will be
                        updated automatically.
                    </List.Item>
                </List>
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    TCPInputStream (alias: TCPClientStream)
                </Title>
                <Space w="sm" />
                <TCPBadge />
                <HttpBadge />
            </Box>
            <Text size="lg">
                This data is the TCP input stream: this handler is called only
                on is_input=True packets. The filters that handles this data
                will be called only in this case.
            </Text>
            <Space h="sm" />
            <Text size="lg" ml="xs">
                <List>
                    <List.Item>
                        <strong>data: </strong> The entire stream in input
                        direction. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>total_stream_size: </strong> The size of the
                        entire stream in input direction. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>is_ipv6: </strong> It's true if the stream is
                        IPv6, false if it's IPv4. (read only)
                    </List.Item>
                </List>
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    TCPOutputStream (alias TCPServerStream)
                </Title>
                <Space w="sm" />
                <TCPBadge />
                <HttpBadge />
            </Box>
            <Text size="lg">
                This data is the TCP output stream: this handler is called only
                on is_input=False packets. The filters that handles this data
                will be called only in this case.
            </Text>
            <Space h="sm" />
            <Text size="lg" ml="xs">
                <List>
                    <List.Item>
                        <strong>data: </strong> The entire stream in output
                        direction. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>total_stream_size: </strong> The size of the
                        entire stream in output direction. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>is_ipv6: </strong> It's true if the stream is
                        IPv6, false if it's IPv4. (read only)
                    </List.Item>
                </List>
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    HttpRequest
                </Title>
                <Space w="sm" />
                <HttpBadge />
            </Box>
            <Text size="lg">
                This data is the Http request processed by nfqueue. This handler
                can be called twice per request: once when the http headers are
                complete, and once when the body is complete.
            </Text>
            <Text size="lg">
                If the http data arrives in 1 single TCP packet, this handler
                will be called once
            </Text>
            <Space h="sm" />
            <Text size="lg" ml="xs">
                <List>
                    <List.Item>
                        <strong>url: </strong> The url of the request (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>headers: </strong> The headers of the request
                        (read only). The keys and values are exactly the same as
                        the original request (case sensitive). (values can be
                        list in case the same header field is repeated)
                    </List.Item>
                    <List.Item>
                        <strong>get_header(key:str, default = None): </strong> A
                        function that returns the value of a header: it matches
                        the key without case sensitivity. If the header is not
                        found, it returns the default value. (if the same header
                        field is repeated, its value is concatenated with a
                        comma, this function will never return a list)
                    </List.Item>
                    <List.Item>
                        <strong>user_agent: </strong> The user agent of the
                        request (read only)
                    </List.Item>
                    <List.Item>
                        <strong>content_encoding: </strong> The content encoding
                        of the request (read only)
                    </List.Item>
                    <List.Item>
                        <strong>content_length: </strong> The content length of
                        the request (read only)
                    </List.Item>
                    <List.Item>
                        <strong>body: </strong> The body of the request (read
                        only). It's None if the body has not arrived yet.
                    </List.Item>
                    <List.Item>
                        <strong>body_decoded: </strong> By default the body will
                        be decoded following the content encoding. gzip, br,
                        deflate and zstd are supported. If the decoding fails
                        and body is not None this paramether will be False.
                    </List.Item>
                    <List.Item>
                        <strong>http_version: </strong> The http version of the
                        request (read only)
                    </List.Item>
                    <List.Item>
                        <strong>keep_alive: </strong> It's true if the
                        connection was marked for keep alive, false if it's not.
                        (read only)
                    </List.Item>
                    <List.Item>
                        <strong>should_upgrade: </strong> It's true if the
                        connection should be upgraded, false if it's not. (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>upgrading_to_h2: </strong> It's true if the
                        connection is upgrading to h2, false if it's not. (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>ws_stream: </strong> It's a list of
                        websockets.frames.Frame decoded (permessage-deflate is
                        supported). (read only) [
                        <a href="https://websockets.readthedocs.io/en/stable/">
                            docs
                        </a>
                        ]
                    </List.Item>
                    <List.Item>
                        <strong>upgrading_to_ws: </strong> It's true if the
                        connection is upgrading to ws, false if it's not. (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>method: </strong> The method of the request
                        (read only)
                    </List.Item>
                    <List.Item>
                        <strong>headers_complete: </strong> It's true if the
                        headers are complete, false if they are not. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>message_complete: </strong> It's true if the
                        message is complete, false if it's not. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>total_size: </strong> The size of the entire
                        http request (read only)
                    </List.Item>
                    <List.Item>
                        <strong>stream: </strong> It's the buffer that contains
                        the stream of the websocket traffic in input. This is
                        used only if should_upgrade is True. (read only)
                    </List.Item>
                </List>
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    HttpRequestHeader
                </Title>
                <Space w="sm" />
                <HttpBadge />
            </Box>
            <Text size="lg">
                Same as HttpRequest, but this handler is called only when the
                headers are complete and body is not buffered. Body will always
                be None
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    HttpFullRequest
                </Title>
                <Space w="sm" />
                <HttpBadge />
            </Box>
            <Text size="lg">
                Same as HttpRequest, but this handler is called only when the
                request data is complete
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    HttpResponse
                </Title>
                <Space w="sm" />
                <HttpBadge />
            </Box>
            <Text size="lg">
                This data is the Http response processed by nfqueue. This
                handler can be called twice per response: once when the http
                headers are complete, and once when the body is complete.
            </Text>
            <Text size="lg">
                If the http data arrives in 1 single TCP packet, this handler
                will be called once
            </Text>
            <Space h="sm" />
            <Text size="lg" ml="xs">
                <List>
                    <List.Item>
                        <strong>url: </strong> The url of the response (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>headers: </strong> The headers of the response
                        (read only). The keys and values are exactly the same as
                        the original response (case sensitive). (values can be
                        list in case the same header field is repeated)
                    </List.Item>
                    <List.Item>
                        <strong>get_header(key:str, default = None): </strong> A
                        function that returns the value of a header: it matches
                        the key without case sensitivity. If the header is not
                        found, it returns the default value. (if the same header
                        field is repeated, its value is concatenated with a
                        comma, this function will never return a list)
                    </List.Item>
                    <List.Item>
                        <strong>user_agent: </strong> The user agent of the
                        response (read only)
                    </List.Item>
                    <List.Item>
                        <strong>content_encoding: </strong> The content encoding
                        of the response (read only)
                    </List.Item>
                    <List.Item>
                        <strong>content_length: </strong> The content length of
                        the response (read only)
                    </List.Item>
                    <List.Item>
                        <strong>body: </strong> The body of the response (read
                        only). It's None if the body has not arrived yet.
                    </List.Item>
                    <List.Item>
                        <strong>body_decoded: </strong> By default the body will
                        be decoded following the content encoding. gzip, br,
                        deflate and zstd are supported. If the decoding fails
                        and body is not None this paramether will be False.
                    </List.Item>
                    <List.Item>
                        <strong>http_version: </strong> The http version of the
                        response (read only)
                    </List.Item>
                    <List.Item>
                        <strong>keep_alive: </strong> It's true if the
                        connection was marked for keep alive, false if it's not.
                        (read only)
                    </List.Item>
                    <List.Item>
                        <strong>should_upgrade: </strong> It's true if the
                        connection should be upgraded, false if it's not. (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>upgrading_to_h2: </strong> It's true if the
                        connection is upgrading to h2, false if it's not. (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>ws_stream: </strong> It's a list of
                        websockets.frames.Frame decoded (permessage-deflate is
                        supported). (read only) [
                        <a href="https://websockets.readthedocs.io/en/stable/">
                            docs
                        </a>
                        ]
                    </List.Item>
                    <List.Item>
                        <strong>upgrading_to_ws: </strong> It's true if the
                        connection is upgrading to ws, false if it's not. (read
                        only)
                    </List.Item>
                    <List.Item>
                        <strong>status_code: </strong> The status code of the
                        response (read only) (int)
                    </List.Item>
                    <List.Item>
                        <strong>headers_complete: </strong> It's true if the
                        headers are complete, false if they are not. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>message_complete: </strong> It's true if the
                        message is complete, false if it's not. (read only)
                    </List.Item>
                    <List.Item>
                        <strong>total_size: </strong> The size of the entire
                        http response (read only)
                    </List.Item>
                    <List.Item>
                        <strong>stream: </strong> It's the buffer that contains
                        the stream of the websocket traffic in output. This is
                        used only if should_upgrade is True. (read only)
                    </List.Item>
                </List>
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    HttpResponseHeader
                </Title>
                <Space w="sm" />
                <HttpBadge />
            </Box>
            <Text size="lg">
                Same as HttpResponse, but this handler is called only when the
                headers are complete and body is not buffered. Body will always
                be None
            </Text>
            <Box display="flex" style={{ alignItems: "center" }}>
                <Title order={3} my="xs">
                    <CgEditBlackPoint style={{ marginBottom: -3 }} />{" "}
                    HttpFullResponse
                </Title>
                <Space w="sm" />
                <HttpBadge />
            </Box>
            <Text size="lg">
                Same as HttpResponse, but this handler is called only when the
                response data is complete
            </Text>
            <Title order={2} mt="lg" mb="sm">
                ⚠️ Stream Limiter
            </Title>
            <Text size="lg" my="xs">
                What happen if in a specific TCP stream you have a lot of data?
                The stream limiter will be activated and some action will be
                taken. You can configure the action performed by setting some
                option in the globals:
                <br />
                <Space h="sm" />
                First import the FullStreamAction enum:
                <CodeHighlight
                    code={IMPORT_FULL_ACTION_STREAM}
                    language="python"
                    my="sm"
                />
                Then you can set in the globals these options:
                <List>
                    <List.Item>
                        <strong>FGEX_STREAM_MAX_SIZE: </strong> Sets the maximum
                        size of the stream. If the stream exceeds this size, the
                        FGEX_FULL_STREAM_ACTION will be performed. (this limit
                        is applyed at the single stream related to the single
                        data handler). For example if TCPInputStream has reached
                        the limit but HttpResponse has not, the action will be
                        performed only on the TCPInputStream. The default is
                        1MB.
                    </List.Item>
                    <List.Item>
                        <strong>FGEX_FULL_STREAM_ACTION: </strong> Sets the
                        action performed when the stream exceeds the
                        FGEX_STREAM_MAX_SIZE. The default is
                        FullStreamAction.FLUSH.
                    </List.Item>
                </List>
                Heres will be explained every type of action you can set:
                <List>
                    <List.Item>
                        <strong>FLUSH: </strong> Flush the stream and continue
                        to acquire new packets (default)
                    </List.Item>
                    <List.Item>
                        <strong>DROP: </strong> Drop the next stream packets -
                        like a DROP action by filter
                    </List.Item>
                    <List.Item>
                        <strong>REJECT: </strong> Reject the stream and close
                        the connection - like a REJECT action by filter
                    </List.Item>
                    <List.Item>
                        <strong>ACCEPT: </strong> Stops to call pyfilters and
                        accept the traffic
                    </List.Item>
                </List>
            </Text>
            <Title order={2} mt="lg" mb="sm">
                ⚠️ Other Options
            </Title>
            <Text size="lg" my="xs">
                Here's other enums that you could need to use:
                <CodeHighlight
                    code={ENUM_IMPORT_AND_DEFINITION}
                    language="python"
                    my="sm"
                />
                Then you can set in the globals these options:
                <List>
                    <List.Item>
                        <strong>FGEX_INVALID_ENCODING_ACTION: </strong> Sets the
                        action performed when the stream has an invalid encoding
                        (due to a parser crash). The default is
                        ExceptionAction.REJECT.
                    </List.Item>
                </List>
            </Text>
            <Title order={2} mt="lg" mb="sm">
                🚀 How It Works
            </Title>
            <Text mb="sm" size="lg">
                The proxy is built on a multi-threaded architecture and
                integrates Python for dynamic filtering:
            </Text>
            <List>
                <List.Item>
                    <Text size="lg">
                        <strong>Packet Interception: </strong>
                        The{" "}
                        <a href="https://netfilter.org/projects/libnetfilter_queue/">
                            nfqueue
                        </a>{" "}
                        kernel module intercepts network packets(a{" "}
                        <a href="https://netfilter.org/">netfilter</a> module)
                        🔍
                        <br />
                        The rules for attach the nfqueue on the network traffic
                        is done by the nftables lib with json APIs by the python
                        manager.
                    </Text>
                </List.Item>
                <List.Item>
                    <Text size="lg">
                        <strong>Packet Reading: </strong>A dedicated thread
                        reads packets from{" "}
                        <a href="https://netfilter.org/projects/libnetfilter_queue/">
                            nfqueue
                        </a>
                        . 🧵
                    </Text>
                </List.Item>
                <List.Item>
                    <Text size="lg">
                        <strong>Multi-threaded Analysis: </strong>
                        The C++ binary launches multiple threads, each starting
                        its own Python interpreter. Thanks to Python 3.12’s
                        support for{" "}
                        <a href="https://peps.python.org/pep-0684/">
                            a per-interpeter GIL
                        </a>
                        , real multithreading is achieved. Traffic is
                        distributed among threads based on IP addresses and port
                        hashing, ensuring that packets belonging to the same
                        flow are processed by the same thread. ⚡️
                    </Text>
                </List.Item>
                <List.Item>
                    <Text size="lg">
                        <strong>Python Filter Integration: </strong>
                        Users can upload custom Python filters which are then
                        executed by the interpreter, allowing for dynamic and
                        flexible packet handling. 🐍
                    </Text>
                </List.Item>
                <List.Item>
                    <Text size="lg">
                        <strong>HTTP Parsing: </strong>
                        <a href="https://github.com/domysh/pyllhttp">
                            A Python wrapper for llhttp
                        </a>{" "}
                        (forked and adapted for working with multi-interpeters)
                        is used to parse HTTP connections, making it easier to
                        handle and analyze HTTP traffic. 📡
                    </Text>
                </List.Item>
            </List>
            <Space h="xl" />
            <Title order={2} mt="lg" mb="sm">
                📚 Additional Resources
            </Title>
            <Text size="lg">
                Here's a pyfilter code commented example:
                <CodeHighlight
                    code={EXAMPLE_PYFILTER}
                    language="python"
                    my="sm"
                />
            </Text>
        </>
    );
};
