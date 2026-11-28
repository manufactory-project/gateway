// SPDX-License-Identifier: AGPL-3.0-only

//go:build unix

package main

import (
	"fmt"
	"syscall"
	"testing"
)

// reserveUnlistenedTCP binds an AF_INET SOCK_STREAM socket without calling
// listen() and holds it open for the lifetime of t. Dialing the returned
// address deterministically yields ECONNREFUSED while preventing any other
// process or concurrent test from reclaiming the port.
func reserveUnlistenedTCP(t *testing.T, ip [4]byte) string {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket tcp: %v", err)
	}
	t.Cleanup(func() {
		if cErr := syscall.Close(fd); cErr != nil {
			t.Errorf("close reserved tcp fd: %v", cErr)
		}
	})
	if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: ip, Port: 0}); err != nil {
		t.Fatalf("bind reserved tcp: %v", err)
	}
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		t.Fatalf("getsockname reserved tcp: %v", err)
	}
	sa4, ok := sa.(*syscall.SockaddrInet4)
	if !ok {
		t.Fatalf("unexpected sockaddr type %T", sa)
	}
	return fmt.Sprintf("%d.%d.%d.%d:%d", sa4.Addr[0], sa4.Addr[1], sa4.Addr[2], sa4.Addr[3], sa4.Port)
}

// reserveSameIPPort holds a loopback port on both TCP (unlistened, SO_REUSEADDR)
// and UDP (SO_REUSEADDR, connected to a dummy peer so it never steals mock DNS
// replies) for the lifetime of t so no concurrent test can claim the port while
// runSameIPChecks binds the same fixed source port with SO_REUSEADDR.
func reserveSameIPPort(t *testing.T, ip [4]byte) int {
	t.Helper()
	for attempt := 0; attempt < 32; attempt++ {
		tcpFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			t.Fatalf("socket tcp: %v", err)
		}
		if err := syscall.SetsockoptInt(tcpFD, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			closeFD(t, tcpFD)
			t.Fatalf("setsockopt tcp SO_REUSEADDR: %v", err)
		}
		if err := syscall.Bind(tcpFD, &syscall.SockaddrInet4{Addr: ip, Port: 0}); err != nil {
			closeFD(t, tcpFD)
			t.Fatalf("bind tcp: %v", err)
		}
		sa, err := syscall.Getsockname(tcpFD)
		if err != nil {
			closeFD(t, tcpFD)
			t.Fatalf("getsockname tcp: %v", err)
		}
		sa4, ok := sa.(*syscall.SockaddrInet4)
		if !ok {
			closeFD(t, tcpFD)
			t.Fatalf("unexpected sockaddr type %T", sa)
		}
		port := sa4.Port

		udpFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			closeFD(t, tcpFD)
			t.Fatalf("socket udp: %v", err)
		}
		if err := syscall.SetsockoptInt(udpFD, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			closeFD(t, udpFD)
			closeFD(t, tcpFD)
			t.Fatalf("setsockopt udp SO_REUSEADDR: %v", err)
		}
		if err := syscall.Bind(udpFD, &syscall.SockaddrInet4{Addr: ip, Port: port}); err != nil {
			closeFD(t, udpFD)
			closeFD(t, tcpFD)
			continue
		}
		if err := syscall.Connect(udpFD, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 2}, Port: 1}); err != nil {
			closeFD(t, udpFD)
			closeFD(t, tcpFD)
			t.Fatalf("connect udp holder: %v", err)
		}
		t.Cleanup(func() {
			closeFD(t, udpFD)
			closeFD(t, tcpFD)
		})
		return port
	}
	t.Fatal("failed to reserve a matching TCP+UDP loopback port after 32 attempts")
	return 0
}

func closeFD(t *testing.T, fd int) {
	t.Helper()
	if err := syscall.Close(fd); err != nil {
		t.Errorf("close fd %d: %v", fd, err)
	}
}
