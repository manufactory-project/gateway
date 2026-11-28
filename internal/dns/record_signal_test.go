// SPDX-License-Identifier: AGPL-3.0-only

package dns_test

import (
	"sync"
	"time"
)

// recordSignal is an audit mirror that wakes waiters on every record written, so
// tests wait for records instead of sleeping.
type recordSignal struct {
	mu   sync.Mutex
	next chan struct{}
}

func newRecordSignal() *recordSignal {
	return &recordSignal{next: make(chan struct{})}
}

func (s *recordSignal) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.next)
	s.next = make(chan struct{})
	return len(p), nil
}

// until checks cond now and after each record, until it holds or limit passes.
func (s *recordSignal) until(limit time.Duration, cond func() bool) bool {
	timeout := time.After(limit)
	for {
		s.mu.Lock()
		next := s.next
		s.mu.Unlock()
		if cond() {
			return true
		}
		select {
		case <-next:
		case <-timeout:
			return false
		}
	}
}
