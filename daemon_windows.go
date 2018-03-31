package main

import "syscall"

var (
	daemonSysprocAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
)
