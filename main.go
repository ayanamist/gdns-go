package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

const (
	AliDNS     = "223.5.5.5:53"
	DNSTimeout = 2 * time.Second
)

var (
	confFile = flag.String("conf", "config.json", "Specify config json path")

	myIP                *MyIP
	possibleLoopDomains = []string{GoogleDnsHttpsDomain}
	fallbackUpstream    = &TcpUdpUpstream{
		NameServer: AliDNS,
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
	if addr == nil || addr.IsLoopback() {
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
	for _, d := range possibleLoopDomains {
		if domain == d {
			avoidLoop = true
			break
		}
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
			u = fallbackUpstream
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
}

func main() {
	flag.Parse()
	config, err := GetConfigFromFile(*confFile)
	if err != nil {
		log.Fatalln(err)
	}
	myIP = new(MyIP)
	if config.MyIP == "" {
		myIP.Client = &http.Client{
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout: 3 * time.Second,
				}).Dial,
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       30 * time.Second,
			},
			Timeout: 30 * time.Second,
		}
		myIP.SetIP(net.IP{127, 0, 0, 1})
		myIP.StartTaobaoIPLoop()
	} else {
		myIP.SetIP(net.ParseIP(config.MyIP))
	}
	upstreamMap := make(map[string]Upstream)
	for k, v := range config.Mapping {
		if _, _, err := net.SplitHostPort(v); err != nil {
			if strings.Contains(err.Error(), "missing port in address") {
				v += ":53"
			} else {
				log.Fatalf("dns server %s invalid: %v", v, err)
			}
		}
		upstreamMap[k] = &TcpUdpUpstream{
			NameServer: v,
			Network:    "udp",
			Dial: (&net.Dialer{
				Timeout: DNSTimeout,
			}).Dial,
		}
	}
	if _, ok := upstreamMap[""]; !ok {
		dial := (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial
		if config.Proxy != "" {
			u, err := url.Parse(config.Proxy)
			if err != nil {
				log.Fatalf("invalid proxy url %s: %v", config.Proxy, err)
			}
			if dial, err = NewDialFromURL(u); err != nil {
				log.Fatalln(err)
			}
			domain := strings.SplitN(u.Host, ":", 2)[0]
			if net.ParseIP(domain) == nil {
				possibleLoopDomains = append(possibleLoopDomains, domain)
			}
		}
		upstreamMap[""] = &GoogleHttpsUpstream{
			Client: &http.Client{
				Transport: &http2.Transport{
					DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
						conn, err := dial(network, addr)
						if err != nil {
							return nil, err
						}
						return tls.Client(conn, cfg), nil
					},
				},
				Timeout: 2 * time.Second,
			},
		}
	}
	listenAddr := "127.0.0.1:53"
	if config.Listen != "" {
		listenAddr = config.Listen
	}
	server := &dns.Server{
		Addr: listenAddr,
		Net:  "udp",
		Handler: &MyHandler{
			upstreamMap: upstreamMap,
		},
		TsigSecret: nil,
	}
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the server: %v", err)
	}
}
