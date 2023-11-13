package internal

import (
	"fmt"
	"github.com/miekg/dns"
	"math/rand"
	"net"
	"os"
)

type TargetType string

type DnsResolver struct {
	UseTcp        bool
	DnsServer     string
	DnsServerPort string
	dnsClient     *dns.Client
	clientConfig  *dns.ClientConfig
}

func NewDnsResolver() *DnsResolver {
	return &DnsResolver{}
}

func (dr *DnsResolver) Initialize() {

	if dr.DnsServer == "" {
		var err error
		dr.clientConfig, err = dns.ClientConfigFromFile("/etc/resolv.conf")

		if err != nil {
			fmt.Println("There was no specified DnsServer and couldn't load backup config (/etc/resolv.conf)", err)
			os.Exit(1)
		}
	}

	dr.dnsClient = new(dns.Client)
	if dr.UseTcp {
		dr.dnsClient.Net = "tcp"
	}
}

func (dr *DnsResolver) getDnsServer() string {
	if dr.DnsServer == "" && dr.clientConfig != nil {
		var serverLen = len(dr.clientConfig.Servers)
		var randomServer = dr.clientConfig.Servers[rand.Intn(serverLen)]
		return net.JoinHostPort(randomServer, dr.clientConfig.Port)
	} else if dr.DnsServer != "" {
		return net.JoinHostPort(dr.DnsServer, dr.DnsServerPort)
	}

	return ""
}

func (dr *DnsResolver) ReverseLookup(target string, query uint16) (*dns.Msg, error) {
	reverse, err := dns.ReverseAddr(target)
	if err != nil {
		return nil, err
	}

	// Create a new DNS message
	m := new(dns.Msg)
	m.SetQuestion(reverse, query)

	// Perform the query against your local resolver
	answer, _, err := dr.dnsClient.Exchange(m, dr.getDnsServer())
	if err != nil {
		return nil, err
	}

	return answer, nil
}
