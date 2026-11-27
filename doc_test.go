package gateway_test

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestBootstrap(t *testing.T) {
	// Verifies the test harness, -race, and goleak wiring before daemon code lands.
}
