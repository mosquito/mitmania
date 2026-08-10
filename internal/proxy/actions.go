package proxy

import (
	"context"

	"mitmania/internal/rules"
)

// applyRequestActions and applyResponseActions are Http1Handler's action
// registries — one per protocol direction (request/response), each owned
// by the ProtocolHandler: they dispatch a rule's already-validated
// CompiledAction list to the matching RequestInterceptor/
// ResponseInterceptor method, stopping at the first ShortCircuit verdict.
// webhook/header.fetch are the two exceptions to "pure,
// allocation-free and instantaneous" — real network calls, so they take
// ctx and an outcallContext (nil if no OutcallService is configured, in
// which case they fail closed subject to the action's own failOpen)
// instead of living as plain RequestInterceptor methods like everything
// else here.

func applyRequestActions(ctx context.Context, oc *outcallContext, ri *rules.RequestInterceptor, actions []rules.CompiledAction) rules.Verdict {
	for _, a := range actions {
		var v rules.Verdict
		switch a.Name {
		case "header.add":
			v = ri.HeaderAdd(a.Params)
		case "header.set":
			v = ri.HeaderSet(a.Params)
		case "raise":
			v = ri.Raise(a.Params)
		case "block":
			v = ri.Block(a.Params)
		case "webhook":
			v = applyWebhook(ctx, oc, a.Outcall)
		case "header.fetch":
			v = applyHeaderFetch(ctx, oc, ri, a.Outcall)
		}
		if v.ShortCircuit {
			return v
		}
	}
	return rules.Verdict{}
}

func applyResponseActions(ri *rules.ResponseInterceptor, actions []rules.CompiledAction) rules.Verdict {
	for _, a := range actions {
		var v rules.Verdict
		switch a.Name {
		case "header.add":
			v = ri.HeaderAdd(a.Params)
		case "header.set":
			v = ri.HeaderSet(a.Params)
		case "body.replace":
			v = ri.BodyReplace(a.Params)
		case "status.set":
			v = ri.StatusSet(a.Params)
		}
		if v.ShortCircuit {
			return v
		}
	}
	return rules.Verdict{}
}
