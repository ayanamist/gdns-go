package main

import (
	"crypto/tls"
	"errors"
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
	AliDNS = "223.5.5.5:53"
)

var (
	confFile = flag.String("conf", "config.json", "Specify config json path")

	myIP                *MyIP
	dnsCache            *DNSCache
	possibleLoopDomains = []string{GoogleDnsHttpsDomain}
	dnsQueryTimeoutSec  time.Duration
	fallbackUpstream    *TcpUdpUpstream
)

type MyHandler struct {
	upstreamMap map[string][]Upstream
	cache       *DNSCache
}

func appendEdns0Subnet(m *dns.Msg, addr net.IP) {
	newOpt := true
	var o *dns.OPT
	for _, v := range m.Extra {
		if v.Header().Rrtype == dns.TypeOPT {
			o = v.(*dns.OPT)
			newOpt = false
			break
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
	if e.Address.To4() == nil {
		e.Family = 2 // IP6
		e.SourceNetmask = net.IPv6len * 8
	} else {
		e.Family = 1 // IP4
		e.SourceNetmask = net.IPv4len * 8
	}
	o.Option = append(o.Option, e)
	if newOpt {
		m.Extra = append(m.Extra, o)
	}
}

func (h *MyHandler) determineRoute(domain string) (u []Upstream) {
	for domain != "" && domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	avoidLoop := false
	var ok bool
	for domain != "" {
		for _, d := range possibleLoopDomains {
			if domain == d {
				avoidLoop = true
				break
			}
		}
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
	if len(u) == 0 {
		u = h.upstreamMap[""]
	}
	if avoidLoop {
		ups := []Upstream{}
		for _, s := range u {
			if _, ok = s.(*GoogleHttpsUpstream); !ok {
				ups = append(ups, s)
			}
		}
		if len(ups) > 0 {
			u = ups
		} else {
			u = []Upstream{fallbackUpstream}
		}
	}
	return
}

func (h *MyHandler) ServeDNS(w dns.ResponseWriter, reqMsg *dns.Msg) {
	var err error
	addr := myIP.GetIP()
	if addr != nil && !addr.IsLoopback() {
		appendEdns0Subnet(reqMsg, addr)
	}

	type chanResp struct {
		m   *dns.Msg
		err error
	}
	var respMsg *dns.Msg
	allQuestions := reqMsg.Question
	for qi, q := range allQuestions {
		typ, ok := dns.TypeToString[q.Qtype]
		if !ok {
			typ = "UnknownType"
		}

		respMsg = h.cache.Get(q)
		if respMsg == nil {
			up := h.determineRoute(q.Name)

			for i, u := range up {
				m := reqMsg.Copy()
				m.Question = allQuestions[qi : qi+1]

				log.Printf("%s#%d %d/%d query %v, type=%s => %s(%d)", w.RemoteAddr(), m.Id, qi+1, len(allQuestions), q.Name, typ, u.Name(), i)
				ch := make(chan chanResp)
				go func(i int, u Upstream) {
					start := time.Now()
					respMsg, err := u.Exchange(m)
					log.Printf("%s#%d %d/%d %s(%d) rtt=%dms, err=%v", w.RemoteAddr(), m.Id, qi+1, len(allQuestions), u.Name(), i, time.Since(start)/1e6, err)
					ch <- chanResp{respMsg, err}
					close(ch)
				}(i, u)
				select {
				case resp := <-ch:
					respMsg, err = resp.m, resp.err
				case <-time.After(dnsQueryTimeoutSec):
					go func() {
						<-ch
					}()
					respMsg, err = nil, errors.New("single timeout")
				}
				if err == nil {
					break
				}
			}

			if respMsg != nil {
				h.cache.Put(q, respMsg)
			}
		} else {
			respMsg.Id = reqMsg.Id
			log.Printf("%s#%d %d/%d query %v, type=%s => cache", w.RemoteAddr(), respMsg.Id, qi+1, len(allQuestions), q.Name, typ)
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

	dnsQueryTimeoutSec = time.Duration(config.QueryTimeoutSec) * time.Second
	if dnsQueryTimeoutSec == 0 {
		dnsQueryTimeoutSec = 5 * time.Second
	}

	fallbackUpstream = &TcpUdpUpstream{
		NameServer: AliDNS,
		Network:    "udp",
		Dial: (&net.Dialer{
			Timeout: dnsQueryTimeoutSec,
		}).Dial,
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
		myIP.StartTaobaoIPLoop(func(oldIP, newIP net.IP) {
			dnsCache.Purge()
		})
	} else {
		myIP.SetIP(net.ParseIP(config.MyIP))
	}

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
	defaultGoogleUpstream := &GoogleHttpsUpstream{
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

	upstreamMap := make(map[string][]Upstream)
	for k, v := range config.Mapping {
		upstreams := []Upstream{}
		for _, v := range strings.Split(v, ",") {
			var upstream Upstream
			if v == "default" {
				upstream = defaultGoogleUpstream
			} else {
				if _, _, err := net.SplitHostPort(v); err != nil {
					if strings.Contains(err.Error(), "missing port in address") {
						v += ":53"
					} else {
						log.Fatalf("dns server %s invalid: %v", v, err)
					}
				}
				upstream = &TcpUdpUpstream{
					NameServer: v,
					Network:    "udp",
					Dial: (&net.Dialer{
						Timeout: dnsQueryTimeoutSec,
					}).Dial,
				}
			}
			upstreams = append(upstreams, upstream)
		}
		if len(upstreams) > 0 {
			upstreamMap[k] = upstreams
		}
	}
	if _, ok := upstreamMap[""]; !ok {
		upstreamMap[""] = []Upstream{defaultGoogleUpstream}
	}

	listenAddr := "127.0.0.1:53"
	if config.Listen != "" {
		listenAddr = config.Listen
	}

	cacheSize := config.CacheSize
	if cacheSize == 0 {
		cacheSize = 1000
	}
	dnsCache = NewDNSCache(cacheSize)
	server := &dns.Server{
		Addr: listenAddr,
		Net:  "udp",
		Handler: &MyHandler{
			upstreamMap: upstreamMap,
			cache:       dnsCache,
		},
		TsigSecret: nil,
	}

	log.Printf("try to listen on %s", listenAddr)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Failed to setup the server: %v", err)
	}
}
