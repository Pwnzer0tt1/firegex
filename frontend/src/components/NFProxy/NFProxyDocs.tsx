import { CodeHighlight } from "@mantine/code-highlight";
import { Container, Title, Text, List, Code, Space } from "@mantine/core";

const IMPORT_CODE_EXAMPLE = `from firegex.nfproxy import pyfilter, ACCEPT, REJECT`

const FOO_FILTER_CODE = `from firegex.nfproxy import pyfilter, ACCEPT, REJECT

# This is NOT a filter
def useless_function() -> int:
    print("This is a useless function")
    return 42

@pyfilter
def none_filter(): # This is a filter that does nothing
    useless_function()
    return ACCEPT

`


export const NFProxyDocs = () => {
  return (
    <Container size="xl">
      <Title order={1}>🌐 Netfilter Proxy Documentation</Title>

      <Title order={2} mt="xl" mb="sm">📖 Overview</Title>
      <Text size="lg">
        Netfilter Proxy is a simulated proxy that leverages <a href="https://netfilter.org/projects/libnetfilter_queue/">nfqueue</a> to intercept network packets.
        It follows a similar workflow to NFRegex but introduces Python-based filtering capabilities,
        providing users with the flexibility to upload custom filters.
      </Text>

      <Title order={2} mt="lg" mb="sm">⚙️ How to Use Netfilter Proxy</Title>
      <Text size="lg">
        To use Netfilter Proxy, simply create and upload a Python filter. The filter is passed to the C++ binary,
        which then processes packets using the provided logic. This allows you to tailor the filtering behavior
        to your needs.
      </Text>

      <Title order={2} mt="lg" mb="sm">🚀 How It Works</Title>
      <Text mb="sm" size="lg">
        The proxy is built on a multi-threaded architecture and integrates Python for dynamic filtering:
      </Text>
      <List>
        <List.Item>
          <Text size="lg">
            <strong>Packet Interception: </strong>
            The <a href="https://netfilter.org/projects/libnetfilter_queue/">nfqueue</a> kernel module intercepts network packets(a <a href="https://netfilter.org/">netfilter</a> module) 🔍<br />
            The rules for attach the nfqueue on the network traffic is done by the nftables lib with json APIs by the python manager.
          </Text>
        </List.Item>
        <List.Item>
          <Text size="lg">
            <strong>Packet Reading: </strong>
            A dedicated thread reads packets from <a href="https://netfilter.org/projects/libnetfilter_queue/">nfqueue</a>. 🧵
          </Text>
        </List.Item>
        <List.Item>
          <Text size="lg">
            <strong>Multi-threaded Analysis: </strong>
            The C++ binary launches multiple threads, each starting its own Python interpreter.
            Thanks to Python 3.12’s support for <a href="https://peps.python.org/pep-0684/">a per-interpeter GIL</a>, real multithreading is achieved.
            Traffic is distributed among threads based on IP addresses and port hashing, ensuring that
            packets belonging to the same flow are processed by the same thread. ⚡️
          </Text>
        </List.Item>
        <List.Item>
          <Text size="lg">
            <strong>Python Filter Integration: </strong>
            Users can upload custom Python filters which are then executed by the interpreter,
            allowing for dynamic and flexible packet handling. 🐍
          </Text>
        </List.Item>
 
        <List.Item>
          <Text size="lg">
            <strong>HTTP Parsing: </strong>
            <a href="https://github.com/domysh/pyllhttp">A Python wrapper for llhttp</a> (forked and adapted for working with multi-interpeters) is used to parse HTTP connections, making it easier to handle
            and analyze HTTP traffic. 📡
          </Text>
        </List.Item>
      </List>

      <Title order={2} mt="lg" mb="sm">💡 How to write pyfilters?</Title>
      <Text size="lg">
        First of all install the firegex lib and update it running <Code>pip install -U fgex</Code>.
        After that you can use <Code>firegex</Code> module.
        <CodeHighlight code={IMPORT_CODE_EXAMPLE} language="python" my="sm"/>
        With this code we imported the <Code>pyfilter</Code> decorator and the <Code>ACCEPT</Code> and <Code>REJECT</Code> constants.<br />
        Let's create a first (useless) filter to see the syntax:
        <CodeHighlight code={FOO_FILTER_CODE} language="python" my="sm"/>
        You see that the filter must be decorated with the <Code>pyfilter</Code> decorator and must return a statement about how to manage that packet.
        <br/><Space h="sm" />
        You can save every data about the current flow in the global variables, the code you write will be executed only once for flow. The globals are isolated between flows.
        For each packet the filter functions will be called with the required paramethers and the same globals as before.
        <br/><Space h="sm" />
        <strong>Saving data in globals of other modules is not recommended, because that memory is shared by the flows managed by the same thread and lead to unexpected behaviors.</strong>
        <br/><Space h="sm" />
        <strong>Global variables that starts with __firegex_ are reserved for internal use, don't use them.</strong>

      </Text>

    </Container>
  );
};
