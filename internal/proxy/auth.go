package proxy

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"mitmania/internal/httperror"
	"mitmania/internal/outcall"
	"mitmania/internal/rules"
	"mitmania/internal/session"
)

// checkAuth implements the auth.http_proxy gate — called once per
// CONNECT tunnel or absolute-form connection, between the rule lookup and
// its connection-phase LookupConn, before any rule match and before any
// dial. ruleSet is what
// h.Rules.Lookup(ctx, sess.ClientKey()) already returned; req is the
// CONNECT or absolute-form request being authenticated (its
// Proxy-Authorization header, if any).
//
// checkAuth is purely a gate: it never changes which rule file governs
// the connection (mitmania is a data-plane for proxying — rule selection
// stays a pure function of source address). On failure it has already
// written the 407/403 response and logged the access record — the caller
// just returns. On success it returns the authenticated principal, empty
// when auth isn't configured/required at all — callers keep using the
// same ruleSet/lookup they already had.
func (h *Http1Handler) checkAuth(ctx context.Context, sess session.Session, ruleSet *rules.RuleSet, req *http.Request, reqURL string, treq reqTrace) (principal string, ok bool) {
	ca := ruleSet.Auth()
	if ca == nil || !ca.Required {
		return "", true
	}

	// Explicit-proxy only: Proxy-Authorization has no channel on
	// a transparent listener, so a required gate reached that way fails
	// closed rather than silently serving unauthenticated.
	if sess.Transport != session.TransportExplicit {
		httperror.WriteResponse(sess.Conn, reqURL, httperror.ForwardingDenied)
		h.logAccess(sess, req.Method, reqURL, "forwarding-denied", httperror.ForwardingDenied.Status, treq)
		return "", false
	}

	authOK, gotPrincipal := ca.Authenticate(req.Header.Get("Proxy-Authorization"))
	if !authOK && ca.Broker != nil {
		var err error
		authOK, gotPrincipal, err = h.authenticateBroker(ctx, ca, ruleSet.UUID(), sess.ClientKey().String(), req.Header.Get("Proxy-Authorization"))
		if err != nil && h.Logger != nil {
			h.Logger.Warn("auth.http_proxy: broker call failed", "client", sess.ClientKey().String(), "err", err.Error())
		}
	}

	if !authOK {
		outcome := "auth-failed"
		if req.Header.Get("Proxy-Authorization") == "" {
			outcome = "auth-required"
		}
		spec := httperror.ProxyAuthRequired(ca.Realm, ca.ChallengeSchemes())
		httperror.WriteResponse(sess.Conn, reqURL, spec)
		h.logAccess(sess, req.Method, reqURL, outcome, spec.Status, treq)
		return "", false
	}

	return gotPrincipal, true
}

// authenticateBroker delegates auth.http_proxy validation to ca.Broker's
// OutcallService (the auth broker scheme): the raw Proxy-Authorization
// scheme+value is forwarded verbatim (mitmania holds no opinion on Basic
// vs Bearer here, same spirit as header.fetch holding none about the
// broker's own auth scheme), a 2xx reply's principal is adopted, a
// non-2xx or unreachable/broken broker is a 407 either way — unlike
// webhook/header.fetch's failOpen, a login gate has no "proceed anyway"
// mode. Reuses OutcallService.Do's transport/cache/singleflight/fail-
// closed machinery wholesale, but with its own cache key: unlike webhook/
// header.fetch (deliberately request-independent), an auth
// broker's whole point is validating a specific credential, so the key
// must vary with it — a hash of it, not the raw credential, even though
// the cache itself is in-memory only like every other outcall entry.
func (h *Http1Handler) authenticateBroker(ctx context.Context, ca *rules.CompiledAuth, uuid, client, proxyAuthorization string) (ok bool, principal string, err error) {
	if h.Outcall == nil {
		return false, "", errors.New("auth.http_proxy: broker configured but no OutcallService available")
	}
	scheme, value, found := strings.Cut(proxyAuthorization, " ")
	if !found {
		return false, "", nil
	}

	target := outcall.Target{Socket: ca.Broker.Socket, Path: ca.Broker.Path, URL: ca.Broker.URL}
	targetKey := ca.Broker.URL
	if ca.Broker.Socket != "" {
		targetKey = ca.Broker.Socket + ca.Broker.Path
	}
	credSum := sha256.Sum256([]byte(scheme + ":" + value))
	cacheKey := fmt.Sprintf("auth:%s:%s:%x", uuid, targetKey, credSum[:8])

	req := outcall.Request{
		Version:    outcall.Version,
		Action:     outcall.ActionAuth,
		UUID:       uuid,
		Client:     client,
		Proto:      "http",
		Credential: &outcall.Credential{Scheme: scheme, Value: value},
	}
	resp, doErr := h.Outcall.Do(ctx, cacheKey, target, req)
	if doErr != nil {
		var denied *outcall.DeniedError
		if errors.As(doErr, &denied) {
			return false, "", nil // broker reached, said no — a 407, not a broken-broker error
		}
		return false, "", doErr // broker unreachable/broken
	}
	if resp.Principal == "" {
		return false, "", fmt.Errorf("auth.http_proxy: broker allowed but returned no principal")
	}
	return true, resp.Principal, nil
}
