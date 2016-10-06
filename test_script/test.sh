#!/bin/bash

$GOPATH/bin/gdns-go -conf $(cd $(dirname ${BASH_SOURCE[0]}); pwd)/config.json &
PID=$!
sleep 1
dig -p 5353 @127.0.0.1 www.google.com
CODE=$?
kill $PID
sleep 1
if kill -0 $PID; then
    echo "$PID is still alive"
    exit 1
fi
exit $CODE