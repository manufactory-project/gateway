// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build !unix

package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"syscall"
)

func reuseAddrControl(_, _ string, _ syscall.RawConn) error {
	return nil
}

func classifyDialError(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "reset"
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "no route") || strings.Contains(msg, "unreachable") || strings.Contains(msg, "address family not supported") {
		return "local (no route)"
	}
	return "other"
}
