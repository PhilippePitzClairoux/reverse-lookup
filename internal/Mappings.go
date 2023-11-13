package internal

import (
	"errors"
	"github.com/miekg/dns"
	"strings"
)

func GetQueryType(query string) (uint16, error) {
	value, ok := DnsQuestions[query]
	if !ok {
		return 0, errors.New("Invalid query type was passed : " + query)
	}

	return value, nil
}

func GetDnsQueryTypes() string {
	var buffer string
	var line string
	var index = 0

	for key, _ := range DnsQuestions {
		index++
		line = strings.TrimPrefix(strings.Join([]string{line, key}, ", "), ", ")

		if index == 8 {
			buffer += "\t" + line + "\n"

			line = ""
			index = 0
		}
	}

	return buffer
}

var DnsQuestions = map[string]uint16{
	"none":       dns.TypeNone,
	"a":          dns.TypeA,
	"ns":         dns.TypeNS,
	"md":         dns.TypeMD,
	"mf":         dns.TypeMF,
	"cname":      dns.TypeCNAME,
	"soa":        dns.TypeSOA,
	"mb":         dns.TypeMB,
	"mg":         dns.TypeMG,
	"mr":         dns.TypeMR,
	"null":       dns.TypeNULL,
	"ptr":        dns.TypePTR,
	"hinfo":      dns.TypeHINFO,
	"minfo":      dns.TypeMINFO,
	"mx":         dns.TypeMX,
	"txt":        dns.TypeTXT,
	"rp":         dns.TypeRP,
	"afsdb":      dns.TypeAFSDB,
	"x25":        dns.TypeX25,
	"isdn":       dns.TypeISDN,
	"rt":         dns.TypeRT,
	"nsapptr":    dns.TypeNSAPPTR,
	"sig":        dns.TypeSIG,
	"key":        dns.TypeKEY,
	"px":         dns.TypePX,
	"gpos":       dns.TypeGPOS,
	"aaaa":       dns.TypeAAAA,
	"loc":        dns.TypeLOC,
	"nxt":        dns.TypeNXT,
	"eid":        dns.TypeEID,
	"nimloc":     dns.TypeNIMLOC,
	"srv":        dns.TypeSRV,
	"atma":       dns.TypeATMA,
	"naptr":      dns.TypeNAPTR,
	"kx":         dns.TypeKX,
	"cert":       dns.TypeCERT,
	"dname":      dns.TypeDNAME,
	"opt":        dns.TypeOPT,
	"apl":        dns.TypeAPL,
	"ds":         dns.TypeDS,
	"sshfp":      dns.TypeSSHFP,
	"ipseckey":   dns.TypeIPSECKEY,
	"rrsig":      dns.TypeRRSIG,
	"nsec":       dns.TypeNSEC,
	"dnskey":     dns.TypeDNSKEY,
	"dhcid":      dns.TypeDHCID,
	"nsec3":      dns.TypeNSEC3,
	"nsec3param": dns.TypeNSEC3PARAM,
	"tlsa":       dns.TypeTLSA,
	"smimea":     dns.TypeSMIMEA,
	"hip":        dns.TypeHIP,
	"ninfo":      dns.TypeNINFO,
	"rkey":       dns.TypeRKEY,
	"talink":     dns.TypeTALINK,
	"cds":        dns.TypeCDS,
	"cdnskey":    dns.TypeCDNSKEY,
	"openpgpkey": dns.TypeOPENPGPKEY,
	"csync":      dns.TypeCSYNC,
	"zonemd":     dns.TypeZONEMD,
	"svcb":       dns.TypeSVCB,
	"https":      dns.TypeHTTPS,
	"spf":        dns.TypeSPF,
	"uinfo":      dns.TypeUINFO,
	"uid":        dns.TypeUID,
	"gid":        dns.TypeGID,
	"unspec":     dns.TypeUNSPEC,
	"nid":        dns.TypeNID,
	"l32":        dns.TypeL32,
	"l64":        dns.TypeL64,
	"lp":         dns.TypeLP,
	"eui48":      dns.TypeEUI48,
	"eui64":      dns.TypeEUI64,
	"uri":        dns.TypeURI,
	"caa":        dns.TypeCAA,
	"avc":        dns.TypeAVC,
	"amtrelay":   dns.TypeAMTRELAY,
	"tkey":       dns.TypeTKEY,
	"tsig":       dns.TypeTSIG,
	"ixfr":       dns.TypeIXFR,
	"axfr":       dns.TypeAXFR,
	"mailb":      dns.TypeMAILB,
	"maila":      dns.TypeMAILA,
	"any":        dns.TypeANY,
	"ta":         dns.TypeTA,
	"dlv":        dns.TypeDLV,
	"reserved":   dns.TypeReserved,
}
