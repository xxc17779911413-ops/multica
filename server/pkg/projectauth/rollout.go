package projectauth

import (
	"fmt"
	"strings"
)

// RolloutPhase is the deployment-wide authorization activation boundary.
// Historical phase names remain accepted for configuration compatibility, but
// business permissions now decide whether an enabled user may mutate access.
type RolloutPhase string

const (
	RolloutOff        RolloutPhase = "off"
	RolloutShadow     RolloutPhase = "shadow"
	RolloutReader     RolloutPhase = "reader"
	RolloutWriter     RolloutPhase = "writer"
	RolloutRestricted RolloutPhase = "restricted"
)

func ParseRolloutPhase(raw string) (RolloutPhase, error) {
	phase := RolloutPhase(strings.ToLower(strings.TrimSpace(raw)))
	if phase == "" {
		phase = RolloutOff
	}
	switch phase {
	case RolloutOff, RolloutShadow, RolloutReader, RolloutWriter, RolloutRestricted:
		return phase, nil
	default:
		return RolloutOff, fmt.Errorf("invalid project permission rollout phase %q", raw)
	}
}

// LegacyRolloutPhase keeps PROJECT_PERMISSION_ENABLED backwards compatible.
// An explicit PROJECT_PERMISSION_ROLLOUT_PHASE should be preferred.
func LegacyRolloutPhase(enabled bool) RolloutPhase {
	if enabled {
		return RolloutRestricted
	}
	return RolloutOff
}

func (p RolloutPhase) ShadowEnabled() bool { return p == RolloutShadow }
func (p RolloutPhase) ReaderEnabled() bool {
	return p == RolloutReader || p == RolloutWriter || p == RolloutRestricted
}

// mutationEnabled is the package-level activation boundary. Once authorization
// is active, mutation eligibility is determined by the normal permission checks.
// 2026-09-17 coder(lq): Remove rollout-only write protection from business ACLs.
func (s *Service) mutationEnabled() (bool, error) {
	if s == nil || s.rollout == RolloutOff {
		return false, nil
	}
	if !s.Enabled() {
		return false, ErrDisabled
	}
	return true, nil
}
