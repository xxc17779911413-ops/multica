package projectauth

import (
	"errors"
	"testing"
)

func TestParseRolloutPhase(t *testing.T) {
	tests := []struct {
		value string
		want  RolloutPhase
		ok    bool
	}{
		{"", RolloutOff, true},
		{"off", RolloutOff, true},
		{"shadow", RolloutShadow, true},
		{"reader", RolloutReader, true},
		{"writer", RolloutWriter, true},
		{"restricted", RolloutRestricted, true},
		{" READER ", RolloutReader, true},
		{"unknown", RolloutOff, false},
	}
	for _, tt := range tests {
		got, err := ParseRolloutPhase(tt.value)
		if (err == nil) != tt.ok || got != tt.want {
			t.Errorf("ParseRolloutPhase(%q) = (%q, %v), want (%q, ok=%v)", tt.value, got, err, tt.want, tt.ok)
		}
	}
}

func TestRolloutPhaseCapabilities(t *testing.T) {
	tests := []struct {
		phase          RolloutPhase
		shadow, reader bool
	}{
		{RolloutOff, false, false},
		{RolloutShadow, true, false},
		{RolloutReader, false, true},
		{RolloutWriter, false, true},
		{RolloutRestricted, false, true},
	}
	for _, tt := range tests {
		if tt.phase.ShadowEnabled() != tt.shadow || tt.phase.ReaderEnabled() != tt.reader {
			t.Errorf("capabilities for %q do not match expected rollout boundary", tt.phase)
		}
	}
}

func TestLegacyRolloutPhase(t *testing.T) {
	if got := LegacyRolloutPhase(false); got != RolloutOff {
		t.Fatalf("disabled legacy phase = %q", got)
	}
	if got := LegacyRolloutPhase(true); got != RolloutRestricted {
		t.Fatalf("enabled legacy phase = %q", got)
	}
}

func TestMutationBoundary(t *testing.T) {
	tests := []struct {
		phase   RolloutPhase
		enabled bool
		err     error
	}{
		{RolloutOff, false, nil},
		{RolloutShadow, false, ErrDisabled},
		{RolloutReader, true, nil},
		{RolloutWriter, true, nil},
		{RolloutRestricted, true, nil},
	}
	for _, tt := range tests {
		enabled, err := NewWithRollout(nil, tt.phase).mutationEnabled()
		if enabled != tt.enabled || !errors.Is(err, tt.err) {
			t.Errorf("phase=%s mutationEnabled() = (%v, %v), want (%v, %v)", tt.phase, enabled, err, tt.enabled, tt.err)
		}
	}

	enabled, err := (*Service)(nil).mutationEnabled()
	if enabled || err != nil {
		t.Fatalf("nil service mutationEnabled() = (%v, %v), want (false, nil)", enabled, err)
	}
}
