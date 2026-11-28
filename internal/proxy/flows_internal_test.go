package proxy

import (
	"testing"
)

func TestFlowRegistryRevokePropagatesReason(t *testing.T) {
	reg := NewFlowRegistry()
	af1 := reg.register(FlowInfo{
		Principal: "worker-a",
		Host:      "a.example.com",
		Port:      443,
		GrantID:   "gr_one",
	}, func() {}, nil)
	af2 := reg.register(FlowInfo{
		Principal: "worker-a",
		Host:      "b.example.com",
		Port:      443,
		GrantID:   "gr_two",
	}, func() {}, nil)

	if n := reg.RevokeByGrant("gr_one", TeardownGrantExpired); n != 1 {
		t.Fatalf("RevokeByGrant = %d, want 1", n)
	}
	if got := af1.reason(); got != TeardownGrantExpired {
		t.Fatalf("af1.reason() = %q, want %q", got, TeardownGrantExpired)
	}

	revoked := reg.RevokeWhere(func(info FlowInfo) bool {
		return info.GrantID == "gr_two"
	}, TeardownReload)
	if len(revoked) != 1 {
		t.Fatalf("RevokeWhere revoked %d flows, want 1", len(revoked))
	}
	if got := af2.reason(); got != TeardownReload {
		t.Fatalf("af2.reason() = %q, want %q", got, TeardownReload)
	}
}
