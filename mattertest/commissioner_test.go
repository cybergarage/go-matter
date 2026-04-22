package mattertest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
)

func TestCommissioner(t *testing.T) {
	t.Helper()

	scenario, err := loadLiveCommissioningScenarioFromEnv()
	if errors.Is(err, errLiveCommissioningDisabled) {
		t.Skip("live commissioner interop disabled; set MATTER_TEST_COMMISSIONER_LIVE=1 to enable")
	}
	if err != nil {
		t.Fatalf("loadLiveCommissioningScenarioFromEnv() error = %v", err)
	}

	log.EnableStdoutDebug(true)
	defer log.EnableStdoutDebug(false)

	cmr := matter.NewCommissioner()
	if err := cmr.Start(); err != nil {
		t.Fatalf("Failed to start commissioner: %v", err)
	}
	defer func() {
		if err := cmr.Stop(); err != nil {
			t.Errorf("Failed to stop commissioner: %v", err)
		}
	}()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: scenario.Name,
			run: func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()

				opts := scenario.Options()
				cme, err := cmr.Commission(ctx, scenario.PairingCode, opts...)
				if err != nil {
					t.Fatalf("Failed to commission device: %v", err)
				}
				t.Logf("Successfully commissioned device: %s", cme.String())
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}
