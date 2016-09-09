package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"sync"
)

const TaobaoIpURL = "http://ip.taobao.com/service/getIpInfo.php?ip=myip"

type MyIP struct {
	sync.RWMutex
	ip net.IP
}

func (m *MyIP) Refresh() error {
	resp, err := httpClient.Get(TaobaoIpURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	tbRes := struct {
		Code int `json:"code"`
		Data struct {
			IP string `json:"ip"`
		} `json:"data"`
	}{}
	if err := json.Unmarshal(respBytes, &tbRes); err != nil {
		return err
	}
	if tbRes.Data.IP == "" {
		return fmt.Errorf("unexpected result: %s", string(respBytes))
	}
	ip := net.ParseIP(tbRes.Data.IP)
	if ip == nil {
		return fmt.Errorf("unexpected ip: %s", tbRes.Data.IP)
	}
	m.SetIP(ip)
	return nil
}

func (m *MyIP) GetIP() net.IP {
	m.RLock()
	defer m.RUnlock()
	return m.ip
}

func (m *MyIP) SetIP(ip net.IP) {
	m.Lock()
	m.ip = ip
	m.Unlock()
}
