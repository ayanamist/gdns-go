package main

import (
	"sync"
	"time"

	"github.com/miekg/dns"
)

type dnsCache struct {
	m    *sync.RWMutex
	head *dnsCacheEntry
	tail *dnsCacheEntry
	c    map[dns.Question]*dnsCacheEntry
	size uint32
}

type dnsCacheEntry struct {
	q    dns.Question
	m    *dns.Msg
	t    time.Time
	prev *dnsCacheEntry
	next *dnsCacheEntry
}

func NewDNSCache(size uint32) *dnsCache {
	return &dnsCache{
		m:    new(sync.RWMutex),
		c:    make(map[dns.Question]*dnsCacheEntry, size),
		size: size,
	}
}

func (d *dnsCache) Put(q dns.Question, m *dns.Msg) {
	var minTTL uint32 = 0xffffffff
	for _, rr := range m.Answer {
		ttl := rr.Header().Ttl
		if minTTL > ttl {
			minTTL = ttl
		}
	}
	e := &dnsCacheEntry{
		q: q,
		m: m,
		t: time.Now().Add(time.Duration(minTTL) * time.Second),
	}
	d.m.Lock()
	oldEntry, ok := d.c[q]
	if ok {
		if oldEntry.prev != nil {
			oldEntry.prev.next = e
		} else {
			d.head = oldEntry.next
		}
		if oldEntry.next != nil {
			oldEntry.next.prev = e
		} else {
			d.tail = oldEntry.prev
		}
	} else {
		if d.tail == nil {
			d.head = e
			d.tail = e
		} else {
			e.prev = d.tail
			d.tail.next = e
			d.tail = e
		}
	}
	d.c[q] = e
	d.recycle()
	d.m.Unlock()
}

func (d *dnsCache) Get(q dns.Question) *dns.Msg {
	d.m.RLock()
	e, ok := d.c[q]
	if !ok {
		d.m.RUnlock()
		return nil
	}
	if e.t.Before(time.Now()) {
		d.m.RUnlock()
		d.m.Lock()
		defer d.m.Unlock()
		if e, ok := d.c[q]; ok {
			if e.t.Before(time.Now()) {
				d.delete(e)
				return nil
			}
			return e.m
		}
		return nil
	}
	d.m.RUnlock()
	return e.m
}

func (d *dnsCache) recycle() {
	if uint32(len(d.c)) < d.size {
		return
	}
	cur := d.head
	var next *dnsCacheEntry
	for cur != nil {
		next = cur.next
		if cur.t.Before(time.Now()) {
			d.delete(cur)
		}
		cur = next
	}
}

func (d *dnsCache) delete(e *dnsCacheEntry) {
	delete(d.c, e.q)
	if e.prev != nil {
		e.prev.next = e.next
		e.prev = nil
	} else {
		d.head = e.next
		if d.head != nil {
			d.head.prev = nil
		}
	}
	if e.next != nil {
		e.next.prev = e.prev
		e.next = nil
	} else {
		d.tail = e.prev
		if d.tail != nil {
			d.tail.next = nil
		}
	}
}
