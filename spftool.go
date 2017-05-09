package spftool

import (
	"fmt"
	"net"
	"strings"
)

// Lookup returns a list of all SPF types and their data allowed by
// SPF on a domain. It does recursive lookups and follow includes.
func Lookup(domain string) (result []*SPF, err error) {
	count := 0
	result = []*SPF{}
	err = lookup(domain, &result, &count)
	return
}

func lookup(domain string, result *[]*SPF, count *int) error {
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return err
	}
	if *count > 10 {
		return fmt.Errorf("SPF 10 lookup limit exceeded")
	}
	*count++

	//ips := []string{}
	for _, v := range txts {
		if strings.HasPrefix(v, "v=spf1") {

			spf := parseSPF(v)
			//log.Printf("%#v", spf)
			for _, v := range spf.Include {
				lookup(v, result, count)
			}
			*result = append(*result, spf)
		}
	}
	return nil
}

// SPF is an spf record
type SPF struct {
	Include []string
	IP4     []string
	IP6     []string
	MX      []string
	A       []string
	Exists  []string
}

func parseSPF(txt string) *SPF {
	parts := strings.Split(txt, " ")

	spf := &SPF{}
	for _, v := range parts {
		t := strings.Split(v, ":")

		if len(t) < 2 {
			continue
		}

		switch t[0] {
		case "ip4":
			spf.IP4 = append(spf.IP4, t[1])
		case "ip6":
			spf.IP6 = append(spf.IP6, t[1])
		case "include":
			spf.Include = append(spf.Include, t[1])
		case "a":
			spf.Include = append(spf.A, t[1])
		case "exists":
			spf.Include = append(spf.Exists, t[1])

		}
	}
	return spf
}
