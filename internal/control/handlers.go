package control

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/netip"

	"mitmania/internal/flowsink"
	"mitmania/internal/rules"
)

func (c *Control) handleCAPEM(w http.ResponseWriter, r *http.Request) {
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.CA.Cert.Raw})
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(block)
}

func (c *Control) handleCADER(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pkix-cert")
	w.Write(c.CA.Cert.Raw)
}

// statsResponse is GET /stats' body — counters and cache size, secrets
// never included by construction (there's simply no secret-carrying
// field on either flowsink.Snapshot or this struct).
type statsResponse struct {
	flowsink.Snapshot
	CacheEntries int `json:"cache_entries"`
}

func (c *Control) handleStats(w http.ResponseWriter, r *http.Request) {
	var snap flowsink.Snapshot
	if c.Flow != nil {
		snap = c.Flow.Snapshot()
	}
	n, err := c.Cache.Count(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, statsResponse{Snapshot: snap, CacheEntries: n})
}

func (c *Control) handleGetRule(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(r.PathValue("ip"))
	if err != nil {
		http.Error(w, "invalid IP: "+err.Error(), http.StatusBadRequest)
		return
	}
	raw, err := c.Store.LoadRaw(r.Context(), addr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if raw == nil {
		raw = []byte(`{"http":[]}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

// handlePutRule replaces one client's rule file, atomically. The
// body is validated (parsed + compiled) before anything is written, so an
// invalid rule file never reaches disk. There's no separate reload step:
// RuleEngine reads rules fresh from disk on every connection, so this
// takes effect immediately.
func (c *Control) handlePutRule(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		c.logAction(r, "put-rule", ip, err)
		http.Error(w, "invalid IP: "+err.Error(), http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRuleFileBytes+1))
	if err != nil {
		c.logAction(r, "put-rule", ip, err)
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > maxRuleFileBytes {
		err := fmt.Errorf("rule file too large: %d bytes (limit %d)", len(body), maxRuleFileBytes)
		c.logAction(r, "put-rule", ip, err)
		http.Error(w, "rule file too large", http.StatusRequestEntityTooLarge)
		return
	}

	// DisallowUnknownFields, not a plain Unmarshal: a misplaced field (e.g.
	// "mitm" nested inside "match" instead of alongside it) would otherwise
	// decode silently, dropping the unknown key and leaving Rule.MITM at
	// its zero value (nil -> defaults true) — silently turning a mistyped
	// mitm:false into force-MITM, the more dangerous direction to fail in.
	var rf rules.RuleFile
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rf); err != nil {
		c.logAction(r, "put-rule", ip, fmt.Errorf("invalid JSON: %w", err))
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	compiled, err := rules.Compile(rf)
	if err != nil {
		c.logAction(r, "put-rule", ip, fmt.Errorf("invalid rules: %w", err))
		http.Error(w, "invalid rules: "+err.Error(), http.StatusBadRequest)
		return
	}
	if rf.Egress != nil {
		if _, err := rules.CompileEgress(rf.Egress); err != nil {
			c.logAction(r, "put-rule", ip, fmt.Errorf("invalid egress rules: %w", err))
			http.Error(w, "invalid egress rules: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	// A malformed auth hash or unknown scheme is a load-time rejection
	// here too — same PUT-time validation every other rule-file construct
	// gets.
	if _, err := rules.CompileAuth(rf.Auth); err != nil {
		c.logAction(r, "put-rule", ip, fmt.Errorf("invalid auth config: %w", err))
		http.Error(w, "invalid auth config: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Load-time probe: a rule carrying webhook/header.fetch is
	// validated by actually performing it, so a broken broker is caught
	// here — not inside a client's TLS session on its first request.
	// ?validate=false skips it, for the bootstrap case where the broker
	// starts after the proxy.
	if r.URL.Query().Get("validate") != "false" {
		if err := c.probeOutcalls(r.Context(), ip, compiled); err != nil {
			c.logAction(r, "put-rule", ip, fmt.Errorf("outcall probe failed: %w", err))
			http.Error(w, "outcall probe failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if err := c.Store.Save(r.Context(), addr, body); err != nil {
		c.logAction(r, "put-rule", ip, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.logAction(r, "put-rule", ip, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleDeleteRule revokes one client's rule override entirely: after
// this, the client falls back to whichever rules/default bucket covers
// its address — there is no more "no file -> no match -> 511"
// case on its own, since rules/default always has an answer once it's
// been configured. Idempotent — like RuleStore.Delete, deleting an
// already-absent client's rules is not an error.
func (c *Control) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("ip")
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		c.logAction(r, "delete-rule", ip, err)
		http.Error(w, "invalid IP: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := c.Store.Delete(r.Context(), addr); err != nil {
		c.logAction(r, "delete-rule", ip, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.logAction(r, "delete-rule", ip, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleGetDefault returns the raw rules/default blob, verbatim — the
// CIDR-keyed gapless table every client without a per-IP override
// resolves against.
func (c *Control) handleGetDefault(w http.ResponseWriter, r *http.Request) {
	raw, err := c.Store.LoadRawDefault(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if raw == nil {
		raw = []byte(`{}`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

// handlePutDefault replaces the rules/default blob, atomically and only
// after it passes CompileDefaultRuleset's validation — every bucket
// compiles like an ordinary rule file, AND the v4/v6 CIDR keys together
// must cover their entire address space with no gaps (a save-time
// correctness obligation): an incomplete table is rejected with the
// specific gap named, never partially written.
func (c *Control) handlePutDefault(w http.ResponseWriter, r *http.Request) {
	const target = "default"

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRuleFileBytes+1))
	if err != nil {
		c.logAction(r, "put-default", target, err)
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > maxRuleFileBytes {
		err := fmt.Errorf("rules/default too large: %d bytes (limit %d)", len(body), maxRuleFileBytes)
		c.logAction(r, "put-default", target, err)
		http.Error(w, "rules/default too large", http.StatusRequestEntityTooLarge)
		return
	}

	compiled, canonical, err := rules.CompileDefaultRuleset(body)
	if err != nil {
		c.logAction(r, "put-default", target, fmt.Errorf("invalid default ruleset: %w", err))
		http.Error(w, "invalid default ruleset: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Same load-time probe as PUT /rules/{ip}, run over every
	// bucket — a broken broker referenced from any entry is caught here,
	// not on a client's first request that happens to fall into it.
	if r.URL.Query().Get("validate") != "false" {
		for _, bucket := range compiled.Buckets() {
			if err := c.probeOutcalls(r.Context(), bucket.Key, bucket.Rules.HTTPRules()); err != nil {
				c.logAction(r, "put-default", target, fmt.Errorf("outcall probe failed for %q: %w", bucket.Key, err))
				http.Error(w, fmt.Sprintf("outcall probe failed for %q: %s", bucket.Key, err.Error()), http.StatusBadRequest)
				return
			}
		}
	}

	// Persists the CANONICAL form (normalized keys, semantic duplicates
	// collapsed), not the raw submitted body — so GET /rules/default
	// always echoes what an entry became, not what was typed.
	if err := c.Store.SaveDefault(r.Context(), canonical); err != nil {
		c.logAction(r, "put-default", target, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.logAction(r, "put-default", target, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (c *Control) handleFlushCache(w http.ResponseWriter, r *http.Request) {
	if err := c.Cache.Flush(r.Context()); err != nil {
		c.logAction(r, "flush-cache", "", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	c.logAction(r, "flush-cache", "", nil)
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
