// SPDX-License-Identifier: AGPL-3.0-only

// Package connlimit caps the connections a sandbox link may hold open at once.
package connlimit

import (
	"net"
	"sync"
)

// Limit is a connection budget shared by every listener it wraps.
type Limit struct {
	slots      chan struct{}
	onRejected func()
}

// New returns a Limit of n open connections. onRejected is called for each
// connection refused because the budget is spent.
func New(n int, onRejected func()) *Limit {
	return &Limit{slots: make(chan struct{}, n), onRejected: onRejected}
}

// Listener wraps ln so that connections over the limit are closed immediately.
func (l *Limit) Listener(ln net.Listener) net.Listener {
	return &listener{Listener: ln, limit: l}
}

type listener struct {
	net.Listener
	limit *Limit
}

func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.limit.slots <- struct{}{}:
			return &conn{Conn: c, slots: l.limit.slots}, nil
		default:
			// Counted before closing, so the peer never sees an uncounted refusal.
			l.limit.onRejected()
			if err := c.Close(); err != nil {
				continue
			}
		}
	}
}

// conn returns its slot on first Close.
type conn struct {
	net.Conn
	slots   chan struct{}
	release sync.Once
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.release.Do(func() {
		<-c.slots
	})
	return err
}
