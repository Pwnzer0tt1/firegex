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
)

const QUEUE_BASE_NUM = 1000
const MAX_PACKET_IN_QUEUE = 100

var FILTER_TABLE *regex_filters = &regex_filters{}

type regex_filters struct {
	input_whitelist  []*pcre2.Matcher
	input_blacklist  []*pcre2.Matcher
	output_whitelist []*pcre2.Matcher
	output_blacklist []*pcre2.Matcher
}

func (self regex_filters) add(raw_regex string) {
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
	if filter_type[0] == 'i' {
		if filter_type[1] == '0' {
			self.input_whitelist = append(self.input_whitelist, regex.NewMatcher())
		} else {
			self.input_blacklist = append(self.input_blacklist, regex.NewMatcher())
		}
	} else {
		if filter_type[1] == '0' {
			self.output_whitelist = append(self.output_whitelist, regex.NewMatcher())
		} else {
			self.output_blacklist = append(self.output_blacklist, regex.NewMatcher())
		}
	}
}

func (self regex_filters) check(data []byte, is_input bool) bool {
	if is_input {
		for _, matcher := range self.input_blacklist {
			if matcher.Match(data, 0) {
				return false
			}
		}
		for _, matcher := range self.input_whitelist {
			if !matcher.Match(data, 0) {
				return false
			}
		}
	} else {
		for _, matcher := range self.output_blacklist {
			if matcher.Match(data, 0) {
				return false
			}
		}
		for _, matcher := range self.output_whitelist {
			if !matcher.Match(data, 0) {
				return false
			}
		}
	}
	return true
}

func handle_packets(packets <-chan netfilter.NFPacket, is_input bool) {
	for true {
		filter := FILTER_TABLE
		p := <-packets
		log.Printf("Packet received: %s input: %t", p.Packet.TransportLayer().LayerPayload(), is_input)
		if filter.check(p.Packet.TransportLayer().LayerPayload(), is_input) {
			p.SetVerdict(netfilter.NF_ACCEPT)
		} else {
			log.Printf("Refused packet: %s", p.Packet.TransportLayer().LayerPayload())
			p.SetVerdict(netfilter.NF_DROP)
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

	// Start the queue list
	queue_list, starts_input, end_input := create_queue_seq(number_of_queues)
	for _, queue := range queue_list {
		defer queue.Close()
		go handle_packets(queue.GetPackets(), true)
	}

	queue_list, starts_output, end_output := create_queue_seq(number_of_queues)
	for _, queue := range queue_list {
		defer queue.Close()
		go handle_packets(queue.GetPackets(), false)
	}

	fmt.Println("QUEUE INPUT", starts_input, end_input, "OUTPUT", starts_output, end_output)

	//Reading for new configuration
	reader := bufio.NewReader(os.Stdin)
	for true {
		text, err := reader.ReadString('\n')
		log.Printf("[main] Regex rule updating...")
		if err != nil {
			log.Fatalf("[main] Unable to read from stdin: %s", err)
		}
		text = strings.Trim(text, "\n")
		regexes := strings.Split(text, " ")

		new_filters := regex_filters{}
		for _, regex := range regexes {
			regex = strings.Trim(regex, " ")
			if len(regex) < 2 {
				continue
			}
			new_filters.add(regex)
		}
		FILTER_TABLE = &new_filters
		log.Printf("[main] Regex filter rules updated!")
	}
}
