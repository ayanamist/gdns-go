package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"
)

const (
	googleDoHUrl = "https://dns.google/dns-query"
)

var (
	dnsQueryTimeoutSec uint
	ednsClientSubnet   string
	listenAddr         string
	proxy              string

	dnsQueryTimeout time.Duration

	ednsClientAddr net.IP
	ednsClientMask uint8
)

func appendEdns0Subnet(m *dns.Msg, addr net.IP, mask uint8) {
	newOpt := true
	var o *dns.OPT
	for _, v := range m.Extra {
		if v.Header().Rrtype == dns.TypeOPT {
			o = v.(*dns.OPT)
			newOpt = false
			for _, option := range o.Option {
				if option.Option() == dns.EDNS0SUBNET {
					return
				}
			}
		}
	}
	if o == nil {
		o = new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
	}
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.SourceScope = 0
	e.Address = addr
	e.SourceNetmask = mask
	if e.Address.To4() == nil {
		e.Family = 2 // IP6
	} else {
		e.Family = 1 // IP4
	}
	o.Option = append(o.Option, e)
	if newOpt {
		m.Extra = append(m.Extra, o)
	}
}

func main() {
	log.SetOutput(os.Stdout)

	flag.UintVar(&dnsQueryTimeoutSec, "t", 6, "dns query timeout in second")
	flag.StringVar(&ednsClientSubnet, "e", "", "edns client subnet")
	flag.StringVar(&listenAddr, "l", "0.0.0.0:5300", "listen address")
	flag.StringVar(&proxy, "x", "", "proxy address")
	flag.Parse()
	if proxy == "" {
		log.Fatalf("-x required")
	}
	if ednsClientSubnet != "" {
		_, ipNet, err := net.ParseCIDR(ednsClientSubnet)
		if err != nil {
			log.Fatalf("invalid edns client subnet %s: %v", ednsClientSubnet, err)
		}
		ednsClientAddr = ipNet.IP
		ones, _ := ipNet.Mask.Size()
		if ones == 0 {
			log.Fatalf("invalid edns client subnet %s: the mask is not in the canonical form--ones followed by zeros", ednsClientSubnet)
		}
		ednsClientMask = uint8(ones)
	}

	dnsQueryTimeout = time.Duration(dnsQueryTimeoutSec) * time.Second

	upstream, err := newUpstreamHTTPS(googleDoHUrl)
	if err != nil {
		log.Fatalf("unexpect newUpstreamHTTPS error: %v", err)
	}

	if err := dns.ListenAndServe(listenAddr, "udp", dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m, err := upstream.Exchange(r)
		if err != nil {
			dns.HandleFailed(w, r)
		} else {
			_ = w.WriteMsg(m)
		}
	})); err != nil {
		log.Fatalf("listen %s error: %v", listenAddr, err)
	}
}
