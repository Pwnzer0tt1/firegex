package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"

	"github.com/DomySh/go-netfilter-queue"
)

const QUEUE_BASE_NUM = 1000
const MAX_PACKET_IN_QUEUE = 100

func handle_packets(packets <-chan netfilter.NFPacket) {
	for true {
		select {
		case p := <-packets:
			//fmt.Println(p.Packet)
			p.SetVerdict(netfilter.NF_ACCEPT)
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

/*

starts = QUEUE_BASE_NUM
while True:
        if starts >= 65536:
        raise Exception("Netfilter queue is full!")
        queue_ids = list(range(starts,starts+n_threads))
        try:
        ictor.start(func_wrap, queue_ids=queue_ids)
        break
        except interceptor.UnableToBindException as e:
        starts = e.queue_id + 1
return ictor, (starts, starts+n_threads-1)

*/
func create_queue_seq(num int) ([]*netfilter.NFQueue, int, int) {
	var queue_list = make([]*netfilter.NFQueue, num)
	var err error
	starts := QUEUE_BASE_NUM
	for queue_list[0] == nil {
		if starts+num-1 >= 65536 {
			log.Fatalf("Netfilter queue is full!")
			os.Exit(1)
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
	if !isRoot() {
		log.Fatalf("[main] You must be root to run this program")
		os.Exit(1)
	}

	number_of_queues := 1

	if len(os.Args) >= 2 {
		var err error
		number_of_queues, err = strconv.Atoi(os.Args[1])
		if err != nil {
			log.Fatalf("[main] Invalid number of queues: %s", err)
			os.Exit(1)
		}
	}

	// Start the queue list
	queue_list, starts_input, end_input := create_queue_seq(number_of_queues)
	for _, queue := range queue_list {
		defer queue.Close()
		go handle_packets(queue.GetPackets())
	}

	queue_list, starts_output, end_output := create_queue_seq(number_of_queues)
	for _, queue := range queue_list {
		defer queue.Close()
		go handle_packets(queue.GetPackets())
	}

	fmt.Println("QUEUE INPUT", starts_input, end_input, "OUTPUT", starts_output, end_output)

	//Reading for new configuration
	reader := bufio.NewReader(os.Stdin)
	for true {
		text, err := reader.ReadString('\n')
		if err != nil {
			log.Fatalf("[main] Unable to read from stdin: %s", err)
			os.Exit(1)
		}
		fmt.Print(text)
	}
}
