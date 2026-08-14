package proxy

import "testing"

func TestClassifyOutcome(t *testing.T) {
	tests := []struct {
		outcome     string
		wantVerdict string
		wantMitm    string
	}{
		{"ok", "allow", "true"},
		{"splice (mitm:false)", "allow", "false"},
		{"block", "deny", "true"},
		{"misdirected-authority", "deny", "true"},
		{"outcall-denied", "deny", "true"},
		{"outcall-fail", "deny", "true"},
		{"raise", "deny", "true"},
		{"denied", "deny", "false"},
		// Genuinely undetermined: either an early failure ahead of the
		// connection-phase rule match, or a later one (forwarding-denied,
		// resolve-fail, connect-fail) reachable from either mitm value.
		{"no-match", "deny", "unknown"},
		{"forwarding-denied", "deny", "unknown"},
		{"auth-required", "deny", "unknown"},
		{"auth-failed", "deny", "unknown"},
		{"invalid-request", "deny", "unknown"},
		{"headers-too-large", "deny", "unknown"},
		{"empty-connection", "deny", "unknown"},
		{"client-read-timeout", "deny", "unknown"},
		{"rule-engine-error", "deny", "unknown"},
		{"resolve-fail", "deny", "unknown"},
		{"connect-fail", "deny", "unknown"},
		{"upstream-error", "deny", "unknown"},
		// An unrecognized string must still classify rather than panic —
		// the default branch is the safety net for any outcome this table
		// doesn't yet know about.
		{"some-future-outcome-not-yet-listed", "deny", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.outcome, func(t *testing.T) {
			verdict, mitm := classifyOutcome(tt.outcome)
			if verdict != tt.wantVerdict || mitm != tt.wantMitm {
				t.Errorf("classifyOutcome(%q) = (%q, %q), want (%q, %q)", tt.outcome, verdict, mitm, tt.wantVerdict, tt.wantMitm)
			}
		})
	}
}
