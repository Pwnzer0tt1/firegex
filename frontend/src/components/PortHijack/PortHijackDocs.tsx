import { CodeHighlight } from "@mantine/code-highlight"
import { Code, Container, Space, Text, Title } from "@mantine/core"
import { HELP_NFPROXY_SIM } from "../NFProxy/NFProxyDocs"


export const PortHijackDocs = () => {
    return <>
          <Title order={1}>⚡️ Hijack port to proxy</Title>
    
          <Title order={2} mt="xl" mb="sm">📖 Overview</Title>
          <Text size="lg">
            'Hijack port to proxy' uses <a href="https://netfilter.org/">nftables</a> to redirect the traffic from an external IP to a localhost server.
            You are responsable to run and keep alive this server, that is your proxy. The original service will be accessible using loopback (127.0.0.1).
            In this way you can run your custom proxy without touching the service configuration.
          </Text>
    
          <Title order={2} mt="lg" mb="sm">⚙️ How to use Hijack port to proxy</Title>
          <Text size="lg">
            To use this feature, simply create your proxy, run it, than create a new service and set the proxy port and the external ip and port.
            The traffic will be redirected to your proxy, that will still be able to contact the original service using loopback.
            The responses of your proxy will be redirected to the original client, and teh proxy will see as the requests were made by the original client.
            <br /><Space h="sm" />
            You can use for instance the proxy simulator of nfproxy feature of firegex, and run it using nfproxy features. This will advantage you if for instance you need to mangle the traffic.
            changing packets it's possible but not sure to do with nfproxy, but the simulator can change the packets normally (on PacketRaw data is always == l4_data in the simulator, check the nfproxy docs for more info)
            <br /><Space h="sm" />
            You will need to install firegex library with <Code>pip install -U fgex</Code> and than use the simulator command
            <CodeHighlight code={HELP_NFPROXY_SIM} language="" my="sm"/>
            for instance: <Code>fgex nfproxy test_http.py 127.0.0.1 8080 --proto http --from-port 13377</Code>
          </Text>
          <Title order={2} mt="lg" mb="sm">🚀 How It Works</Title>
          <Text mb="sm" size="lg">
            This modules works in a simple way: this only thing done is to change the destination and source ip using <a href="https://netfilter.org/">nftables</a> rules so that the kernel will see that the request was done to the proxy port,
            but externaly the packets exists as connections to the original service. This mangle is done only for external packet arriving from the external ip indicated, localhost traffic won't be touched.
          </Text>
          <Space h="xl" />
        </>
}