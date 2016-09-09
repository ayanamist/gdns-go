package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

var (
	httpClient *http.Client
	myIP       *MyIP
)

type MyHandler struct {
	upstream *UpStreamDNS
}

func (h *MyHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resMsg, err := h.upstream.Query(r)
	if err != nil {
		log.Printf("query: %v", err)
	} else {
		w.WriteMsg(resMsg)
	}
}

func init() {
	log.SetOutput(os.Stdout)
	httpClient = &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		Timeout: 30 * time.Second,
	}
	myIP = &MyIP{
		ip: net.IP{127, 0, 0, 1},
	}
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
	server := &dns.Server{
		Addr: "127.0.0.1:53",
		Net:  "udp",
		Handler: &MyHandler{
			upstream: NewUpStreamDNS(),
		},
		TsigSecret: nil,
	}
	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Failed to setup the server: %s\n", err.Error())
	}
}
