package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/DomySh/go-netfilter-queue"
	"github.com/Jemmic/go-pcre2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const QUEUE_BASE_NUM = 1000
const MAX_PACKET_IN_QUEUE = 100

type regex_pair struct {
	regex   string
	matcher *pcre2.Matcher
}

type regex_filters struct {
	input_whitelist  []regex_pair
	input_blacklist  []regex_pair
	output_whitelist []regex_pair
	output_blacklist []regex_pair
	regexes          []*pcre2.Regexp
}

func NewRegexFilter() *regex_filters {
	res := new(regex_filters)
	res.input_blacklist = make([]regex_pair, 0)
	res.input_whitelist = make([]regex_pair, 0)
	res.output_blacklist = make([]regex_pair, 0)
	res.output_whitelist = make([]regex_pair, 0)
	res.regexes = make([]*pcre2.Regexp, 0)
	return res
}

func (self *regex_filters) add(raw_regex string) {
	filter_type := strings.ToLower(raw_regex[0:2])

	decoded_regex, err := hex.DecodeString(raw_regex[2:])
	if err != nil {
		log.Printf("[add] Unable to decode regex '%s': %s", raw_regex, err)
		return
	}

	regex, err := pcre2.Compile(string(decoded_regex), 0)
	if err != nil {
		log.Printf("[add] Unable to compile regex '%s': %s", string(decoded_regex), err)
		return
	}
	self.regexes = append(self.regexes, regex)
	if filter_type[0] == 'i' {
		if filter_type[1] == '1' {
			self.input_whitelist = append(self.input_whitelist, regex_pair{raw_regex, regex.NewMatcher()})
		} else {
			self.input_blacklist = append(self.input_blacklist, regex_pair{raw_regex, regex.NewMatcher()})
		}
	} else {
		if filter_type[1] == '1' {
			self.output_whitelist = append(self.output_whitelist, regex_pair{raw_regex, regex.NewMatcher()})
		} else {
			self.output_blacklist = append(self.output_blacklist, regex_pair{raw_regex, regex.NewMatcher()})
		}
	}
}

func (self *regex_filters) check(data []byte, is_input bool) bool {
	if is_input {
		for _, rgx := range self.input_blacklist {
			if rgx.matcher.Match(data, 0) {
				fmt.Printf("BLOCKED %s\n", rgx.regex)
				return false
			}
		}
		for _, rgx := range self.input_whitelist {
			if !rgx.matcher.Match(data, 0) {
				fmt.Printf("BLOCKED %s\n", rgx.regex)
				return false
			}
		}
	} else {
		for _, rgx := range self.output_blacklist {
			if rgx.matcher.Match(data, 0) {
				fmt.Printf("BLOCKED %s\n", rgx.regex)
				return false
			}
		}
		for _, rgx := range self.output_whitelist {
			if !rgx.matcher.Match(data, 0) {
				fmt.Printf("BLOCKED %s\n", rgx.regex)
				return false
			}
		}
	}
	return true
}

func (self *regex_filters) clear() {
	for _, rgx := range self.input_whitelist {
		rgx.matcher.Free()
	}
	for _, rgx := range self.input_blacklist {
		rgx.matcher.Free()
	}
	for _, rgx := range self.output_whitelist {
		rgx.matcher.Free()
	}
	for _, rgx := range self.output_blacklist {
		rgx.matcher.Free()
	}
	for _, regex := range self.regexes {
		regex.Free()
	}
}

func handle_packets(packets <-chan netfilter.NFPacket, filter_table_channel chan regex_filters, is_input bool) {
	filter_table := regex_filters{}
	for true {
		filter := filter_table
		select {
		case ft := <-filter_table_channel:
			{
				filter_table = ft
			}
		case p := <-packets:
			{
				transport_layer := p.Packet.TransportLayer()
				data := transport_layer.LayerPayload()
				if len(data) > 0 {
					if filter.check(data, is_input) {
						p.SetVerdict(netfilter.NF_ACCEPT)
					} else {
						if transport_layer.LayerType() == layers.LayerTypeTCP {
							*p.Packet.ApplicationLayer().(*gopacket.Payload) = []byte{}
							transport_layer.(*layers.TCP).Payload = []byte{}
							transport_layer.(*layers.TCP).FIN = true
							transport_layer.(*layers.TCP).SYN = false
							transport_layer.(*layers.TCP).RST = false
							transport_layer.(*layers.TCP).ACK = true
							transport_layer.(*layers.TCP).SetNetworkLayerForChecksum(p.Packet.NetworkLayer())
							buffer := gopacket.NewSerializeBuffer()
							options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
							if err := gopacket.SerializePacket(buffer, options, p.Packet); err != nil {
								p.SetVerdict(netfilter.NF_DROP)
							}
							p.SetVerdictWithPacket(netfilter.NF_ACCEPT, buffer.Bytes())
						} else {
							p.SetVerdict(netfilter.NF_DROP)
						}
					}
				} else {
					p.SetVerdict(netfilter.NF_ACCEPT)
				}
			}
		}
	}
}

func isRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
}

func create_queue_seq(num int) ([]*netfilter.NFQueue, int, int) {
	var queue_list = make([]*netfilter.NFQueue, num)
	var err error
	starts := QUEUE_BASE_NUM
	for queue_list[0] == nil {
		if starts+num-1 >= 65536 {
			log.Fatalf("Netfilter queue is full!")
		}
		for i := 0; i < len(queue_list); i++ {
			queue_list[i], err = netfilter.NewNFQueue(uint16(starts+num-1-i), MAX_PACKET_IN_QUEUE, netfilter.NF_DEFAULT_PACKET_SIZE)
			if err != nil {
				for j := 0; j < i; j++ {
					queue_list[j].Close()
					queue_list[j] = nil
				}
				starts = starts + num - i
				break
			}
		}

	}
	return queue_list, starts, starts + num - 1
}

func main() {
	log.SetOutput(os.Stderr)
	if !isRoot() {
		log.Fatalf("[main] You must be root to run this program")
	}

	number_of_queues := 1

	if len(os.Args) >= 2 {
		var err error
		number_of_queues, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatalf("[main] Invalid number of queues: %s", err)
		}
	}
	var filter_channels []chan regex_filters
	// Start the queue list
	queue_list, starts_input, end_input := create_queue_seq(number_of_queues)
	for _, queue := range queue_list {
		defer queue.Close()
		ch := make(chan regex_filters)
		filter_channels = append(filter_channels, ch)
		go handle_packets(queue.GetPackets(), ch, true)
	}

	queue_list, starts_output, end_output := create_queue_seq(number_of_queues)
	for _, queue := range queue_list {
		defer queue.Close()
		ch := make(chan regex_filters)
		filter_channels = append(filter_channels, ch)
		go handle_packets(queue.GetPackets(), ch, false)
	}

	fmt.Println("QUEUE INPUT", starts_input, end_input, "OUTPUT", starts_output, end_output)

	//Reading for new configuration
	reader := bufio.NewReader(os.Stdin)
	old_filter_table := NewRegexFilter()
	for true {
		text, err := reader.ReadString('\n')
		log.Printf("[main] Regex rule updating...")
		if err != nil {
			log.Fatalf("[main] Unable to read from stdin: %s", err)
		}
		text = strings.Trim(text, "\n")
		regexes := strings.Split(text, " ")

		new_filters := NewRegexFilter()
		for _, regex := range regexes {
			regex = strings.Trim(regex, " ")
			if len(regex) < 2 {
				continue
			}
			new_filters.add(regex)
		}
		for _, ch := range filter_channels {
			ch <- *new_filters
		}
		old_filter_table.clear()
		old_filter_table = new_filters
		log.Printf("[main] Regex filter rules updated!")
	}

}
