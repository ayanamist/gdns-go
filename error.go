package main

import "github.com/miekg/dns"

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
