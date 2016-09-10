package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	GoogleDNS  = "8.8.8.8:53"
	DNSTimeout = 2 * time.Second
)

var (
	myIP *MyIP

	backupUpstream = &TcpUdpUpstream{
		NameServer: GoogleDNS,
		Network:    "udp",
		Dial: (&net.Dialer{
			Timeout: DNSTimeout,
		}).Dial,
	}
)

type MyHandler struct {
	upstreamMap map[string]Upstream
}

func appendEdns0Subnet(m *dns.Msg) {
	addr := myIP.GetIP()
	if addr.IsLoopback() {
		return
	}
	o := new(dns.OPT)
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	e := new(dns.EDNS0_SUBNET)
	e.Code = dns.EDNS0SUBNET
	e.SourceScope = 0
	e.Address = addr
	if e.Address.To4() == nil {
		e.Family = 2 // IP6
		e.SourceNetmask = net.IPv6len * 8
	} else {
		e.Family = 1 // IP4
		e.SourceNetmask = net.IPv4len * 8
	}
	o.Option = append(o.Option, e)
	m.Extra = append(m.Extra, o)
}

func (h *MyHandler) determineRoute(domain string) (u Upstream) {
	for domain != "" && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	avoidLoop := false
	if domain == GoogleDnsHttpsDomain {
		avoidLoop = true
	}
	var ok bool
	for domain != "" {
		u, ok = h.upstreamMap[domain]
		if ok {
			break
		}
		idx := strings.IndexByte(domain, '.')
		if idx < 0 {
			break
		}
		domain = domain[idx+1:]
	}
	if u == nil {
		u = h.upstreamMap[""]
	}
	if avoidLoop {
		if _, ok = u.(*GoogleHttpsUpstream); ok {
			u = backupUpstream
		}
	}
	return
}

func (h *MyHandler) ServeDNS(w dns.ResponseWriter, reqMsg *dns.Msg) {
	appendEdns0Subnet(reqMsg)
	reqMsg.Compress = true

	for i, q := range reqMsg.Question {
		up := h.determineRoute(q.Name)
		cls, ok := dns.ClassToString[q.Qclass]
		if !ok {
			cls = "UnknownClass"
		}
		typ, ok := dns.TypeToString[q.Qtype]
		if !ok {
			typ = "UnknownType"
		}

		m := reqMsg.Copy()
		m.Question = m.Question[i : i+1]
		log.Printf("%s#%d %d/%d query %v, class=%s, type=%s => %s", w.RemoteAddr(), reqMsg.Id, i+1, len(reqMsg.Question), q.Name, cls, typ, up.Name())
		respMsg, rtt, err := up.Exchange(m)
		log.Printf("%s#%d %d/%d rtt=%dms", w.RemoteAddr(), reqMsg.Id, i+1, len(reqMsg.Question), rtt/1e6)

		if err != nil {
			log.Printf("Exchange: %v", err)
		}
		if respMsg != nil {
			if err := w.WriteMsg(respMsg); err != nil {
				log.Printf("WriteMsg: %v", err)
			}
		}
	}
}

func init() {
	log.SetOutput(os.Stdout)
	myIP = &MyIP{
		Client: &http.Client{
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout: 3 * time.Second,
				}).Dial,
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       30 * time.Second,
			},
			Timeout: 30 * time.Second,
		},
	}
	myIP.SetIP(net.IP{127, 0, 0, 1})
}

func main() {
	go func() {
		oldIP := myIP.GetIP()
		for {
			if err := myIP.Refresh(); err != nil {
				log.Printf("refresh myip failed: %v", err)
			} else {
				newIP := myIP.GetIP()
				if !oldIP.Equal(newIP) {
					log.Printf("myip changed from %s to %s", oldIP, newIP)
					oldIP = newIP
				}
			}
			time.Sleep(1 * time.Second)
		}
	}()
	upstreamMap := make(map[string]Upstream)
	upstreamMap[""] = &GoogleHttpsUpstream{
		Client: &http.Client{
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout:   2 * time.Second,
					KeepAlive: 300 * time.Second,
				}).Dial,
				ResponseHeaderTimeout: 2 * time.Second,
			},
			Timeout: 2 * time.Second,
		},
	}
	server := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "udp",
		Handler: &MyHandler{
			upstreamMap: upstreamMap,
		},
		TsigSecret: nil,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Failed to setup the server: %s\n", err.Error())
	}
}
