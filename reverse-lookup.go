package main

import (
	"flag"
	"fmt"
	"reverse-lookup/internal"
)

var (
	// define flags
	tcpResolver   = flag.Bool("tcp", false, "Force resolving with tcp instead of default udp")
	dnsServer     = flag.String("dns-server", "", "DNS server used to resolve IP")
	dnsServerPort = flag.String("dns-server-port", "53", "DNS server port")
	queryType     = flag.String("query-type", "ptr", "DNS Query type ")
	iterate       = flag.Bool("all", false, "Iterate through all available query types")
)

func main() {
	flag.Parse()

	dnsResolver := internal.NewDnsResolver()
	setupResolver(dnsResolver)
	var query, err = internal.GetQueryType(*queryType)

	if len(flag.Args()) != 1 || err != nil {
		fmt.Println("Usage: reverse-lookup [flags] <IP_ADDRESS>")
		flag.PrintDefaults()
		fmt.Println("\nSupported Query types : ")
		fmt.Println(internal.GetDnsQueryTypes())
		return
	}

	target := flag.Args()[0]

	if *iterate {
		for name, query := range internal.DnsQuestions {
			fmt.Printf("Querying %s for %s records\n", target, name)
			executeQueryAndPrintResult(dnsResolver, target, query)
		}
	} else {
		executeQueryAndPrintResult(dnsResolver, target, query)
	}

}

func executeQueryAndPrintResult(dnsResolver *internal.DnsResolver, target string, query uint16) {
	answer, err := dnsResolver.ReverseLookup(target, query)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Answers : ")
	for _, name := range answer.Answer {
		fmt.Println(name.String())
	}

	fmt.Println("Name Servers : ")
	for _, name := range answer.Ns {
		fmt.Println(name.String())
	}

	fmt.Println("Extra : ")
	for _, name := range answer.Extra {
		fmt.Println(name.String())
	}
}

func setupResolver(resolver *internal.DnsResolver) {
	resolver.UseTcp = *tcpResolver
	resolver.DnsServer = *dnsServer
	resolver.DnsServerPort = *dnsServerPort

	resolver.Initialize()
}
