#!/bin/bash

go get github.com/shadowsocks/shadowsocks-go/cmd/shadowsocks-server
$GOPATH/bin/shadowsocks-server -p 8388 -k password -m aes-128-cfb -t 60 &
SS_PID=$!

$GOPATH/bin/gdns-go -conf $(cd $(dirname ${BASH_SOURCE[0]}); pwd)/config.json | tee stdout &
PID=$!
sleep 1
dig -p 5353 @127.0.0.1 www.google.com &&\
grep -qF ' => https://dns.google.com/resolve' stdout &&\
dig -p 5353 @127.0.0.1 dns.google.com &&\
grep -qF ' => udp://8.8.8.8:53' stdout
CODE=$?
kill -9 $SS_PID
kill $PID
sleep 1
if kill -0 $PID 2>/dev/null; then
    echo "$PID is still alive"
    kill -9 $PID
    exit 1
fi
exit $CODE