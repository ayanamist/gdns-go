package main

import (
	"fmt"
	"time"

	"github.com/cloudflare/golibs/lrucache"
	"github.com/miekg/dns"
)

type DNSCache struct {
	cache *lrucache.LRUCache
}

func NewDNSCache(size uint32) *DNSCache {
	return &DNSCache{
		cache: lrucache.NewLRUCache(uint(size)),
	}
}

func msgKey(m *dns.Msg) string {
	q := m.Question[0]
	return fmt.Sprintf("%s%d%d", q.Name, q.Qclass, q.Qtype)
}

func (d *DNSCache) Put(m *dns.Msg) {
	var minTTL uint32 = 0xffffffff
	for _, rr := range m.Answer {
		ttl := rr.Header().Ttl
		if minTTL > ttl {
			minTTL = ttl
		}
	}

	d.cache.Set(msgKey(m), m, time.Now().Add(time.Duration(minTTL)*time.Second))
}

func (d *DNSCache) Get(q *dns.Msg) *dns.Msg {
	v, found := d.cache.GetNotStale(msgKey(q))
	if found {
		return v.(*dns.Msg).Copy()
	} else {
		return nil
	}
}

func (d *DNSCache) Purge() {
	d.cache.Clear()
}
