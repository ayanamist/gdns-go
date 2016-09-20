package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
	ss "github.com/shadowsocks/shadowsocks-go/shadowsocks"
)

func NewDialFromURL(u *url.URL) (func(network, addr string) (net.Conn, error), error) {
	switch u.Scheme {
	case "ss":
		return newSSDial(u)
	case "socks5":
		dialer, err := proxy.FromURL(u, proxy.Direct)
		return dialer.Dial, err
	default:
		return nil, fmt.Errorf("unsupported scheme: %s", u.Scheme)
	}
}

func newSSDial(u *url.URL) (func(network, addr string) (net.Conn, error), error) {
	password, ok := u.User.Password()
	if !ok {
		return nil, errors.New("no password")
	}
	if _, err := ss.NewCipher(u.User.Username(), password); err != nil {
		return nil, err
	}
	return func(network, addr string) (net.Conn, error) {
		rawAddr, err := ss.RawAddr(addr)
		if err != nil {
			return nil, err
		}
		conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
		if err != nil {
			return nil, err
		}
		cipher, _ := ss.NewCipher(u.User.Username(), password)
		c := ss.NewConn(conn, cipher)
		if _, err = c.Write(rawAddr); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}, nil
}
