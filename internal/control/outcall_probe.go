package control

import (
	"context"
	"fmt"

	"mitmania/internal/outcall"
	"mitmania/internal/rules"
)

// probeOutcalls performs every webhook/header.fetch action's actual
// outcall as a load-time probe: a rule carrying one is validated by
// actually exercising it on PUT /rules/{ip} — the socket exists, its
// permissions admit us, the response parses — not just by parsing its
// shape, so a broken broker is caught here instead of inside a client's
// TLS session on its first request. A no-op (returns nil unconditionally)
// when Outcall isn't configured, matching what ?validate=false does
// explicitly — there's nothing to probe with either way.
//
// The probe is an ordinary outcall: it uses the action's own CacheKey,
// so a successful probe's response is already warm in the cache by the
// time the first real request needs it, and a synthetic envelope
// (there's no real request to describe yet) built from just the rule
// file's own address — the client IP for a per-IP rule file, or the
// rules/default bucket's own key for a default-ruleset entry — either
// way just a label, not something a real broker call depends on.
func (c *Control) probeOutcalls(ctx context.Context, identity string, compiled []rules.CompiledRule) error {
	if c.Outcall == nil {
		return nil
	}
	for i, rule := range compiled {
		for j, action := range rule.Request() {
			if action.Outcall == nil {
				continue
			}
			if err := c.probeOne(ctx, identity, action); err != nil {
				return fmt.Errorf("rule %d request[%d] (%s): %w", i, j, action.Name, err)
			}
		}
	}
	return nil
}

func (c *Control) probeOne(ctx context.Context, identity string, action rules.CompiledAction) error {
	co := action.Outcall
	target := outcall.Target{Socket: co.Socket, Path: co.Path, URL: co.URL}
	req := outcall.Request{
		Version: outcall.Version,
		Action:  outcall.Action(action.Name),
		Client:  identity,
		Proto:   "http",
		HTTP:    &outcall.HTTPRequest{Method: "GET", URL: "http://" + identity + "/"},
	}
	_, err := c.Outcall.Do(ctx, co.CacheKey, target, req)
	return err
}
