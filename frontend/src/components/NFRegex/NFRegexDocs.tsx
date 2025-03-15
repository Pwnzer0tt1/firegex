import { Container, Title, Text, List } from "@mantine/core";

export const NFRegexDocs = () => {
  return (
    <>
        <Title order={1}>📡 Netfilter Regex Documentation</Title>

        <Title order={2} mt="xl" mb="sm">📖 Overview</Title>
        <Text size="lg">
            Netfilter Regex is a powerful feature that enables filtering of network packets using regular expressions. This capability is especially useful when you need to inspect packet content and match specific strings or patterns.
        </Text>

        <Title order={2} mt="lg" mb="sm">⚙️ How to Use Netfilter Regex</Title>
        <Text size="lg">
            To get started, create a service and attach a regular expression to it. Once the service is configured, apply it to a network interface to dynamically filter packets based on the defined regex.
        </Text>

        <Title order={2} mt="lg" mb="sm">🚀 How It Works</Title>
        <Text mb="sm" size="lg">
            The packet filtering process is implemented in C++ and involves several key steps:
        </Text>
        <List>
            <List.Item>
                <Text size="lg">
                    <strong>Packet Interception: </strong>
                    The <a href="https://netfilter.org/projects/libnetfilter_queue/">nfqueue</a> kernel module intercepts network packets (a <a href="https://netfilter.org/">netfilter</a> module) 🔍<br />
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
                    <strong>Packet Parsing: </strong>
                    Intercepted packets are parsed by <a href="https://libtins.github.io/">libtins</a>, a C++ library that extracts the payload from each packet. 📄
                </Text>
            </List.Item>
            <List.Item>
                <Text size="lg">
                    <strong>Multi-threaded Analysis: </strong>
                    Multiple threads analyze packets concurrently.
                    While the <a href="https://netfilter.org/projects/libnetfilter_queue/">nfqueue</a> module balances network
                    load based solely on IP addresses—resulting in a single thread handling traffic in NAT environments
                    like CTF networks, firegex manage this threads user-level in a different way.
                    The traffic is routed in the threads based on IP addresses combined with port hashing,
                    ensuring a more balanced workload and that flows will be analyzed by the same thread. ⚡️
                </Text>
            </List.Item>
            <List.Item>
                <Text size="lg">
                    <strong>TCP Handling: </strong>
                    For TCP connections, <a href="https://libtins.github.io/">libtins</a> employs a TCP follower to order packets received from the kernel. 📈
                </Text>
            </List.Item>
            <List.Item>
                <Text size="lg">
                    <strong>Regex Matching: </strong>
                    The extracted payload is processed using <a href="https://github.com/VectorCamp/vectorscan">vectorscan</a> — a fork of <a href="https://github.com/intel/hyperscan">hyperscan</a> that runs also on arm64.
                    For UDP packets, matching occurs on a per-packet basis while saving only the match context rather than the full payload. 🎯
                </Text>
            </List.Item>
        </List>
    </>
  );
};
