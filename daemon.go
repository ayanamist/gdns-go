// +build !linux,!windows

package main

import "syscall"

var (
	daemonSysprocAttr *syscall.SysProcAttr = nil
)
