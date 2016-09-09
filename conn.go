package main

import (
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	UINT16_MAX = 65535

	GoogleDNS = "8.8.8.8:53"
)

var (
	ErrTrIdNotEnough   = errors.New("transaction id not enough")
	ErrUpstreamTimeout = errors.New("upstream timeout")
	ErrUnexpectedEof   = errors.New("expected eof")
)

type UpStreamDNS struct {
}

func isDNSErr(err error) bool {
	switch err {
	case dns.ErrAlg:
		fallthrough
	case dns.ErrAuth:
		fallthrough
	case dns.ErrBuf:
		fallthrough
	case dns.ErrConnEmpty:
		fallthrough
	case dns.ErrExtendedRcode:
		fallthrough
	case dns.ErrFqdn:
		fallthrough
	case dns.ErrId:
		fallthrough
	case dns.ErrKeyAlg:
		fallthrough
	case dns.ErrKey:
		fallthrough
	case dns.ErrKeySize:
		fallthrough
	case dns.ErrNoSig:
		fallthrough
	case dns.ErrPrivKey:
		fallthrough
	case dns.ErrRcode:
		fallthrough
	case dns.ErrRdata:
		fallthrough
	case dns.ErrRRset:
		fallthrough
	case dns.ErrSecret:
		fallthrough
	case dns.ErrShortRead:
		fallthrough
	case dns.ErrSig:
		fallthrough
	case dns.ErrSoa:
		fallthrough
	case dns.ErrTime:
		fallthrough
	case dns.ErrTruncated:
		return true
	default:
		return false
	}
}

func NewUpStreamDNS() *UpStreamDNS {
	c := &UpStreamDNS{}
	return c
}

func (c *UpStreamDNS) Query(reqMsg *dns.Msg) (*dns.Msg, error) {
	co := dns.Conn{}
	var err error
	if co.Conn, err = net.DialTimeout("tcp", GoogleDNS, 2*time.Second); err != nil {
		return nil, err
	}
	defer co.Close()
	appendEdns0Subnet(reqMsg)
	reqMsg.Compress = true
	if err := co.WriteMsg(reqMsg); err != nil {
		return nil, err
	}
	return co.ReadMsg()
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
	e.Family = 1 // IP4
	e.SourceNetmask = net.IPv4len * 8
	if e.Address.To4() == nil {
		e.Family = 2 // IP6
		e.SourceNetmask = net.IPv6len * 8
	}
	o.Option = append(o.Option, e)
	m.Extra = append(m.Extra, o)
}
