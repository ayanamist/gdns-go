package main

import "syscall"

var (
	daemonSysprocAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
)
