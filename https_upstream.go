package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"golang.org/x/net/http/httpproxy"
)

// UpstreamHTTPS is the upstream implementation for DNS over HTTPS service
type UpstreamHTTPS struct {
	client   *http.Client
	endpoint *url.URL
}

// newUpstreamHTTPS creates a new DNS over HTTPS upstream from hostname
func newUpstreamHTTPS(endpoint string) (*UpstreamHTTPS, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	// Update TLS and HTTP client configuration
	proxyFunc := (&httpproxy.Config{
		HTTPSProxy: proxy,
	}).ProxyFunc()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: u.Hostname(),
		},
		DisableCompression: true,
		MaxIdleConns:       1,
		Proxy: func(request *http.Request) (u *url.URL, err error) {
			return proxyFunc(request.URL)
		},
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Timeout:   dnsQueryTimeout,
		Transport: transport,
	}

	return &UpstreamHTTPS{client: client, endpoint: u}, nil
}

// Exchange provides an implementation for the Upstream interface
func (u *UpstreamHTTPS) Exchange(query *dns.Msg) (*dns.Msg, error) {
	if ednsClientSubnet != "" {
		appendEdns0Subnet(query, ednsClientAddr, ednsClientMask)
	}
	queryBuf, err := query.Pack()
	if err != nil {
		return nil, errors.Wrap(err, "failed to pack DNS query")
	}

	// No content negotiation for now, use DNS wire format
	buf, backendErr := u.exchangeWireformat(queryBuf)
	if backendErr == nil {
		response := &dns.Msg{}
		if err := response.Unpack(buf); err != nil {
			return nil, errors.Wrap(err, "failed to unpack DNS response from body")
		}
		response.Id = query.Id
		return response, nil
	}

	return nil, backendErr
}

// Perform message exchange with the default UDP wireformat defined in current draft
// https://datatracker.ietf.org/doc/draft-ietf-doh-dns-over-https
func (u *UpstreamHTTPS) exchangeWireformat(msg []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", u.endpoint.String(), bytes.NewBuffer(msg))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create an HTTPS request")
	}

	req.Header.Add("Content-Type", "application/dns-message")
	req.Host = u.endpoint.Host

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to perform an HTTPS request")
	}

	// Check response status code
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status code %d", resp.StatusCode)
	}

	// Read wireformat response from the body
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read the response body")
	}

	return buf, nil
}
