package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
)

type Config struct {
	Listen          string            `json:"listen"`
	Proxy           string            `json:"proxy"`
	MyIP            string            `json:"myip"`
	Mapping         map[string]string `json:"mapping"`
	CacheSize       *uint32           `json:"cache_size"`
	QueryTimeoutSec uint32            `json:"query_timeout_sec"`
}

func GetConfigFromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	jsonBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	var config Config
	if err := json.Unmarshal(jsonBytes, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
