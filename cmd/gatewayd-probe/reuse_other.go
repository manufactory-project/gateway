//go:build !unix

package main

import "syscall"

func reuseAddrControl(_, _ string, _ syscall.RawConn) error {
	return nil
}
