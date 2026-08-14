package proxy

// classifyOutcome derives the requests.total metric's verdict/mitm
// dimensions from an access-log outcome string — a coarser, query-
// friendly alternative to regex-matching the outcome vocabulary directly
// (e.g. "sum by (verdict)" instead of an outcome=~"no-match|..." allowlist
// that has to be kept in sync by hand). outcome itself remains the most
// specific label and is never replaced by this.
//
// mitm is "unknown" whenever the connection-phase mitm decision either
// hadn't been made yet (an auth/protocol failure ahead of connection-phase
// rule matching) or isn't recoverable from outcome alone: forwarding-
// denied/resolve-fail/connect-fail can each happen on either a mitm:true
// or mitm:false path, since egress denial and dial failure both occur
// after the connection-phase decision regardless of which way it went.
// Never guessed — a dashboard must not receive fabricated data.
func classifyOutcome(outcome string) (verdict, mitm string) {
	switch outcome {
	case "ok":
		return "allow", "true"
	case "splice (mitm:false)":
		return "allow", "false"
	case "block", "misdirected-authority", "outcall-denied", "outcall-fail", "raise":
		// Reachable only once a mitm:true rule's message phase is
		// already running (block/raise/outcall actions are http-only,
		// and a mitm:false rule cannot carry message-phase fields —
		// see CLAUDE.md's mitm:false invariant).
		return "deny", "true"
	case "denied":
		// A connection: {"accept": false} match — no dial, no TLS
		// termination ever attempted, so unlike the other deny outcomes
		// mitm is confidently "false" here, not "unknown".
		return "deny", "false"
	default:
		return "deny", "unknown"
	}
}
