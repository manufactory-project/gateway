// SPDX-License-Identifier: AGPL-3.0-only

// Package connlimit holds the per-link budgets that stop one sandbox from
// degrading another: a cap on concurrent connections or requests, and a token
// bucket for work a guest can request faster than the gateway should serve it.
package connlimit

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// SummaryInterval is how long refusals are batched before they are reported once.
const SummaryInterval = 10 * time.Second

// Limit is a budget of n concurrent holders (connections or requests).
type Limit struct {
	slots      chan struct{}
	onRejected func()
}

// New returns a Limit of n holders. onRejected is called for each acquisition
// refused because the budget is spent.
func New(n int, onRejected func()) *Limit {
	return &Limit{slots: make(chan struct{}, n), onRejected: onRejected}
}

// TryAcquire takes a slot, or counts a refusal and returns false when none is free.
// Every successful call must be paired with one Release.
func (l *Limit) TryAcquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		l.onRejected()
		return false
	}
}

// Release returns a slot taken by TryAcquire.
func (l *Limit) Release() {
	<-l.slots
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
		// A refusal is counted before closing, so the peer never sees an uncounted one.
		if l.limit.TryAcquire() {
			return &conn{Conn: c, limit: l.limit}, nil
		}
		if err := c.Close(); err != nil {
			continue
		}
	}
}

// conn returns its slot on first Close.
type conn struct {
	net.Conn
	limit   *Limit
	release sync.Once
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.release.Do(c.limit.Release)
	return err
}

// Drops records refused work. Each refusal is counted at once through onDrop;
// the batch is reported once, SummaryInterval after its first refusal, so a
// flood costs one summary record per interval rather than one per refusal.
type Drops struct {
	onDrop func()
	report func(n uint64)

	mu      sync.Mutex
	pending uint64
	timer   *time.Timer
}

// NewDrops returns a Drops that calls onDrop per refusal and report per batch.
func NewDrops(onDrop func(), report func(n uint64)) *Drops {
	return &Drops{onDrop: onDrop, report: report}
}

// Add records one refusal.
func (d *Drops) Add() {
	d.onDrop()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending++
	if d.pending == 1 {
		d.timer = time.AfterFunc(SummaryInterval, d.Flush)
	}
}

// Flush reports the pending batch now, if any.
func (d *Drops) Flush() {
	d.mu.Lock()
	n := d.pending
	d.pending = 0
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.mu.Unlock()
	if n > 0 {
		d.report(n)
	}
}

// Budget is a token bucket that allows perSecond events per second with a burst
// of the same size. Refused events are recorded in drops.
type Budget struct {
	lim   *rate.Limiter
	drops *Drops
}

// NewBudget returns a Budget of perSecond events per second.
func NewBudget(perSecond int, drops *Drops) *Budget {
	return &Budget{lim: rate.NewLimiter(rate.Limit(perSecond), perSecond), drops: drops}
}

// Allow reports whether one more event fits the budget, recording a drop when not.
func (b *Budget) Allow() bool {
	if b.lim.Allow() {
		return true
	}
	b.drops.Add()
	return false
}
