// SPDX-License-Identifier: AGPL-3.0-only

package admin

import (
	"context"
	"errors"
	"net"
	"syscall"
)

// peer identifies the process on the other end of an admin connection, as the
// kernel reported it at accept time (SO_PEERCRED).
type peer struct {
	uid, pid int
	err      error
}

type peerKey struct{}

// peerOf reads the connection's peer credentials. A failure is kept, not
// dropped, so the request is refused rather than served unattributed.
func peerOf(c net.Conn) peer {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peer{err: errors.New("admin: not a unix connection")}
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peer{err: err}
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return peer{err: err}
	}
	if credErr != nil {
		return peer{err: credErr}
	}
	return peer{uid: int(cred.Uid), pid: int(cred.Pid)}
}

func peerConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, peerKey{}, peerOf(c))
}
