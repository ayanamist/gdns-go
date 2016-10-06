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

func questionKey(q dns.Question) string {
	return fmt.Sprintf("%s%d%d", q.Name, q.Qclass, q.Qtype)
}

func (d *DNSCache) Put(q dns.Question, m *dns.Msg) {
	var minTTL uint32 = 0xffffffff
	for _, rr := range m.Answer {
		ttl := rr.Header().Ttl
		if minTTL > ttl {
			minTTL = ttl
		}
	}

	d.cache.Set(questionKey(q), m, time.Now().Add(time.Duration(minTTL)*time.Second))
}

func (d *DNSCache) Get(q dns.Question) *dns.Msg {
	v, found := d.cache.GetNotStale(questionKey(q))
	if found {
		return v.(*dns.Msg).Copy()
	} else {
		return nil
	}
}

func (d *DNSCache) Purge() {
	d.cache.Clear()
}
