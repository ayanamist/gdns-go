package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"
)

const TaobaoIpURL = "http://ip.taobao.com/service/getIpInfo.php?ip=myip"

type MyIP struct {
	Client *http.Client
	sync.RWMutex
	ip net.IP
}

func (m *MyIP) refreshFromTaobaoIP() error {
	req, err := http.NewRequest(http.MethodGet, TaobaoIpURL, nil)
	if err != nil {
		return err
	}
	client := m.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %v", resp.Status)
	}
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
	if err := json.Unmarshal(respBytes, &tbRes); err != nil || tbRes.Data.IP == "" {
		return fmt.Errorf("unexpected result, error=%v: %s", err, string(respBytes))
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

func (m *MyIP) StartTaobaoIPLoop(cb func(oldIP, newIP net.IP)) {
	go func() {
		oldIP := m.GetIP()
		for {
			if err := m.refreshFromTaobaoIP(); err != nil {
				log.Printf("refresh myip failed: %v", err)
			} else {
				newIP := m.GetIP()
				if !oldIP.Equal(newIP) {
					log.Printf("myip changed from %s to %s", oldIP, newIP)
					if cb != nil {
						go cb(oldIP, newIP)
					}
					oldIP = newIP
				}
			}
			time.Sleep(time.Duration(60+rand.Intn(60)) * time.Second)
		}
	}()
}
