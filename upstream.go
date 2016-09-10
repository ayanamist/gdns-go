package main

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Upstream interface {
	Name() string
	Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error)
}

type TcpUpstream struct {
	NameServer string
	trId       uint32
}

func (t *TcpUpstream) Name() string {
	return fmt.Sprintf("tcp://%s", t.NameServer)
}

func (t *TcpUpstream) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	start := time.Now()
	co := dns.Conn{}
	if co.Conn, err = newConn(); err != nil {
		return nil, time.Since(start), fmt.Errorf("new conn: %v", err)
	}
	defer co.Close()
	oldId := m.Id
	m.Id = uint16(atomic.AddUint32(&t.trId, 1))
	if err = co.WriteMsg(m); err != nil {
		return nil, time.Since(start), fmt.Errorf("WriteMsg: %v", err)
	}
	r, err = co.ReadMsg()
	if err != nil {
		err = fmt.Errorf("ReadMsg: %v", err)
	}
	if r != nil {
		r.Id = oldId
	}
	return r, time.Since(start), err
}

type UdpUpstream struct {
	NameServer string
	c          *dns.Client
	m          sync.Mutex
	trId       uint32
}

func (u *UdpUpstream) Name() string {
	return fmt.Sprintf("udp://%s", u.NameServer)
}

func (u *UdpUpstream) init() {
	if u.c == nil {
		u.m.Lock()
		if u.c == nil {
			u.c = &dns.Client{}
		}
		u.m.Unlock()
	}
}

func (u *UdpUpstream) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	start := time.Now()
	u.init()
	oldId := m.Id
	m.Id = uint16(atomic.AddUint32(&u.trId, 1))
	r, _, err = u.c.Exchange(m, u.NameServer)
	if r != nil {
		r.Id = oldId
	}
	rtt = time.Since(start)
	return
}

func newConn() (net.Conn, error) {
	return net.DialTimeout("tcp", GoogleDNS, 2*time.Second)
}
