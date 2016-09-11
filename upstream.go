package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Upstream interface {
	Name() string
	Exchange(m *dns.Msg) (r *dns.Msg, err error)
}

type TcpUdpUpstream struct {
	NameServer string
	Network    string
	Dial       func(network, addr string) (net.Conn, error)
	trId       uint32
}

func (t *TcpUdpUpstream) Name() string {
	return t.Network + "://" + t.NameServer
}

func (t *TcpUdpUpstream) Exchange(m *dns.Msg) (r *dns.Msg, err error) {
	co := new(dns.Conn)
	if co.Conn, err = t.Dial(t.Network, t.NameServer); err != nil {
		return nil, fmt.Errorf("Dial: %v", err)
	}
	defer co.Close()
	oldId := m.Id
	m.Id = uint16(atomic.AddUint32(&t.trId, 1))
	co.SetWriteDeadline(time.Now().Add(DNSTimeout))
	if err = co.WriteMsg(m); err != nil {
		return nil, fmt.Errorf("WriteMsg: %v", err)
	}
	co.SetReadDeadline(time.Now().Add(DNSTimeout))
	r, err = co.ReadMsg()
	if err != nil {
		err = fmt.Errorf("ReadMsg: %v", err)
	}
	if r != nil {
		r.Id = oldId
	}
	return r, err
}

const (
	GoogleDnsHttpsDomain = "dns.google.com"
	GoogleDnsHttpsUrl    = "https://" + GoogleDnsHttpsDomain + "/resolve"
)

type GoogleHttpsUpstream struct {
	Client *http.Client
}

func (g *GoogleHttpsUpstream) Name() string {
	return GoogleDnsHttpsUrl
}

func extractEdns0Subnet(m *dns.Msg) *dns.EDNS0_SUBNET {
	for _, rr := range m.Extra {
		if rrOpt, ok := rr.(*dns.OPT); ok {
			for _, opt := range rrOpt.Option {
				if e, ok := opt.(*dns.EDNS0_SUBNET); ok {
					return e
				}
			}
		}
	}
	return nil
}

type GoogleDnsHttpsQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type GoogleDnsHttpsAnswer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32
	Data string `json:"data"`
}

type GoogleDnsHttpsResponse struct {
	Status     int
	TC         bool
	RD         bool
	RA         bool
	AD         bool
	CD         bool
	Question   []GoogleDnsHttpsQuestion
	Answer     []GoogleDnsHttpsAnswer
	Authority  []GoogleDnsHttpsAnswer
	Additional []struct {
	}
	Comment string
}

func extractRRHdr(a GoogleDnsHttpsAnswer) dns.RR_Header {
	return dns.RR_Header{
		Name:   a.Name,
		Rrtype: a.Type,
		Ttl:    a.TTL,
		Class:  dns.ClassINET,
	}
}

func (g *GoogleHttpsUpstream) Exchange(m *dns.Msg) (r *dns.Msg, err error) {
	params := url.Values{
		"name": {m.Question[0].Name},
		"type": {strconv.FormatUint(uint64(m.Question[0].Qtype), 10)},
	}
	edns0Subnet := extractEdns0Subnet(m)
	if edns0Subnet != nil && edns0Subnet.Address != nil {
		params.Set("edns_client_subnet", edns0Subnet.Address.String()+"/"+strconv.Itoa(int(edns0Subnet.SourceNetmask)))
	}
	reqUrl := GoogleDnsHttpsUrl + "?" + params.Encode()
	req, err := http.NewRequest(http.MethodGet, reqUrl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status=%s", resp.Status)
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var msgResp GoogleDnsHttpsResponse
	if err := json.Unmarshal(respBytes, &msgResp); err != nil {
		return nil, err
	}
	r = new(dns.Msg)
	r.Id = m.Id
	r.MsgHdr.Response = true
	r.MsgHdr.Opcode = dns.OpcodeQuery
	r.MsgHdr.Rcode = msgResp.Status
	r.MsgHdr.Truncated = msgResp.TC
	r.MsgHdr.RecursionDesired = msgResp.RD
	r.MsgHdr.RecursionAvailable = msgResp.RA
	r.MsgHdr.CheckingDisabled = msgResp.CD
	for _, q := range msgResp.Question {
		r.Question = append(r.Question, dns.Question{q.Name, q.Type, dns.ClassINET})
	}
	for _, a := range msgResp.Answer {
		hdr := extractRRHdr(a)
		var rr dns.RR
		switch a.Type {
		case dns.TypeA:
			rr = &dns.A{
				Hdr: hdr,
				A:   net.ParseIP(a.Data),
			}
		case dns.TypeNS:
			rr = &dns.NS{
				Hdr: hdr,
				Ns:  a.Data,
			}
		case dns.TypeMD:
			rr = &dns.MD{
				Hdr: hdr,
				Md:  a.Data,
			}
		case dns.TypeMF:
			rr = &dns.MF{
				Hdr: hdr,
				Mf:  a.Data,
			}
		case dns.TypeCNAME:
			rr = &dns.CNAME{
				Hdr:    hdr,
				Target: a.Data,
			}
		case dns.TypeSOA:
		case dns.TypeMB:
			rr = &dns.MB{
				Hdr: hdr,
				Mb:  a.Data,
			}
		case dns.TypeMG:
			rr = &dns.MG{
				Hdr: hdr,
				Mg:  a.Data,
			}
		case dns.TypeMR:
			rr = &dns.MR{
				Hdr: hdr,
				Mr:  a.Data,
			}
		case dns.TypeNULL:
		case dns.TypePTR:
			rr = &dns.PTR{
				Hdr: hdr,
				Ptr: a.Data,
			}
		case dns.TypeHINFO:
		case dns.TypeMINFO:
		case dns.TypeMX:
			mx := &dns.MX{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 2 {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[0], 10, 16)
			mx.Preference = uint16(n)
			mx.Mx = parts[1]
			rr = mx
		case dns.TypeTXT:
			rr = &dns.TXT{
				Hdr: hdr,
				Txt: strings.Split(a.Data, " "),
			}
		case dns.TypeRP:
			rp := &dns.RP{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 2 {
				continue
			}
			rp.Mbox, rp.Txt = parts[0], parts[1]
			rr = rp
		case dns.TypeAAAA:
			rr = &dns.AAAA{
				Hdr:  hdr,
				AAAA: net.ParseIP(a.Data),
			}
		case dns.TypeSRV:
			srv := &dns.SRV{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 4 {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[0], 10, 16)
			srv.Priority = uint16(n)
			n, _ = strconv.ParseUint(parts[1], 10, 16)
			srv.Weight = uint16(n)
			n, _ = strconv.ParseUint(parts[2], 10, 16)
			srv.Port = uint16(n)
			srv.Target = parts[3]
			rr = srv
		case dns.TypeSPF:
			rr = &dns.SPF{
				Hdr: hdr,
				Txt: strings.Split(a.Data, " "),
			}
		case dns.TypeDS:
			ds := &dns.DS{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 4 {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[0], 10, 16)
			ds.KeyTag = uint16(n)
			n, _ = strconv.ParseUint(parts[1], 10, 8)
			ds.Algorithm = uint8(n)
			n, _ = strconv.ParseUint(parts[2], 10, 8)
			ds.DigestType = uint8(n)
			ds.Digest = parts[3]
			rr = ds
		case dns.TypeSSHFP:
			sshfp := &dns.SSHFP{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 3 {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[0], 10, 8)
			sshfp.Algorithm = uint8(n)
			n, _ = strconv.ParseUint(parts[1], 10, 8)
			sshfp.Type = uint8(n)
			sshfp.FingerPrint = parts[2]
			rr = sshfp
		case dns.TypeRRSIG:
			rrsig := &dns.RRSIG{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 9 {
				continue
			}
			var ok bool
			if rrsig.TypeCovered, ok = dns.StringToType[strings.ToUpper(parts[0])]; !ok {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[1], 10, 8)
			rrsig.Algorithm = uint8(n)
			n, _ = strconv.ParseUint(parts[2], 10, 8)
			rrsig.Labels = uint8(n)
			n, _ = strconv.ParseUint(parts[3], 10, 32)
			rrsig.OrigTtl = uint32(n)
			n, _ = strconv.ParseUint(parts[4], 10, 32)
			rrsig.Expiration = uint32(n)
			n, _ = strconv.ParseUint(parts[5], 10, 32)
			rrsig.Inception = uint32(n)
			n, _ = strconv.ParseUint(parts[6], 10, 16)
			rrsig.KeyTag = uint16(n)
			rrsig.SignerName = parts[7]
			rrsig.Signature = parts[8]
			rr = rrsig
		case dns.TypeNSEC:
			nsec := &dns.NSEC{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			nsec.NextDomain = parts[0]
			for _, d := range parts[1:] {
				if typeBit, ok := dns.StringToType[strings.ToUpper(d)]; ok {
					nsec.TypeBitMap = append(nsec.TypeBitMap, typeBit)
				}
			}
			rr = nsec
		case dns.TypeDNSKEY:
			dnskey := &dns.DNSKEY{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 4 {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[0], 10, 16)
			dnskey.Flags = uint16(n)
			n, _ = strconv.ParseUint(parts[1], 10, 8)
			dnskey.Protocol = uint8(n)
			n, _ = strconv.ParseUint(parts[2], 10, 8)
			dnskey.Algorithm = uint8(n)
			dnskey.PublicKey = parts[3]
			rr = dnskey
		case dns.TypeNSEC3:
			nsec3 := &dns.NSEC3{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 7 {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[0], 10, 8)
			nsec3.Hash = uint8(n)
			n, _ = strconv.ParseUint(parts[1], 10, 8)
			nsec3.Flags = uint8(n)
			n, _ = strconv.ParseUint(parts[2], 10, 16)
			nsec3.Iterations = uint16(n)
			n, _ = strconv.ParseUint(parts[3], 10, 8)
			nsec3.SaltLength = uint8(n)
			nsec3.Salt = parts[4]
			n, _ = strconv.ParseUint(parts[5], 10, 8)
			nsec3.HashLength = uint8(n)
			nsec3.NextDomain = parts[6]
			for _, d := range parts[7:] {
				if t, ok := dns.StringToType[strings.ToUpper(d)]; ok {
					nsec3.TypeBitMap = append(nsec3.TypeBitMap, t)
				}
			}
			rr = nsec3
		case dns.TypeNSEC3PARAM:
			nsec3param := &dns.NSEC3PARAM{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 5 {
				continue
			}
			var n uint64
			n, _ = strconv.ParseUint(parts[0], 10, 8)
			nsec3param.Hash = uint8(n)
			n, _ = strconv.ParseUint(parts[1], 10, 8)
			nsec3param.Flags = uint8(n)
			n, _ = strconv.ParseUint(parts[2], 10, 16)
			nsec3param.Iterations = uint16(n)
			n, _ = strconv.ParseUint(parts[3], 10, 8)
			nsec3param.SaltLength = uint8(n)
			nsec3param.Salt = parts[4]
			rr = nsec3param
		}
		if rr != nil {
			r.Answer = append(r.Answer, rr)
		}
	}
	for _, a := range msgResp.Authority {
		hdr := extractRRHdr(a)
		var rr dns.RR
		switch a.Type {
		case dns.TypeSOA:
			soa := &dns.SOA{
				Hdr: hdr,
			}
			parts := strings.Split(a.Data, " ")
			if len(parts) < 7 {
				continue
			}
			soa.Ns = parts[0]
			soa.Mbox = parts[1]
			var n uint64
			n, _ = strconv.ParseUint(parts[2], 10, 32)
			soa.Serial = uint32(n)
			n, _ = strconv.ParseUint(parts[3], 10, 32)
			soa.Refresh = uint32(n)
			n, _ = strconv.ParseUint(parts[4], 10, 32)
			soa.Retry = uint32(n)
			n, _ = strconv.ParseUint(parts[5], 10, 32)
			soa.Expire = uint32(n)
			n, _ = strconv.ParseUint(parts[6], 10, 32)
			soa.Minttl = uint32(n)
			rr = soa
		}
		r.Ns = append(r.Ns, rr)
	}
	err = nil
	return
}
