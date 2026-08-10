package outcall

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// freshness is the subset of RFC 9111 (HTTP Caching) the outcall broker
// cache relies on: Cache-Control's
// no-store/max-age/must-revalidate/stale-while-revalidate/stale-if-error,
// with Expires as a fallback for max-age, and — the one deliberate
// deviation — no heuristic freshness when neither is present. A response
// with neither is simply not cached, not "cached for some guessed
// duration"; the broker states freshness or gets asked again every time.
type freshness struct {
	cacheable            bool
	freshFor             time.Duration // 0 if cacheable but already stale-on-arrival (max-age=0)
	mustRevalidate       bool
	staleWhileRevalidate time.Duration
	staleIfError         time.Duration
}

// parseFreshness reads Cache-Control and Expires off resp per the rules
// above. now is passed in (rather than read via time.Now()) so callers
// can test deterministically.
func parseFreshness(header http.Header, now time.Time) freshness {
	cc := parseCacheControl(header.Get("Cache-Control"))

	if cc.noStore {
		return freshness{cacheable: false}
	}

	f := freshness{
		mustRevalidate:       cc.mustRevalidate,
		staleWhileRevalidate: cc.staleWhileRevalidate,
		staleIfError:         cc.staleIfError,
	}

	switch {
	case cc.hasMaxAge:
		f.cacheable = true
		f.freshFor = cc.maxAge
	case header.Get("Expires") != "":
		if t, err := http.ParseTime(header.Get("Expires")); err == nil {
			f.cacheable = true
			if d := t.Sub(now); d > 0 {
				f.freshFor = d
			} // else 0: already expired on arrival, still cacheable (immediately stale)
		}
	}

	return f
}

type cacheControl struct {
	noStore              bool
	mustRevalidate       bool
	hasMaxAge            bool
	maxAge               time.Duration
	staleWhileRevalidate time.Duration
	staleIfError         time.Duration
}

func parseCacheControl(value string) cacheControl {
	var cc cacheControl
	for _, dir := range strings.Split(value, ",") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		name, arg, _ := strings.Cut(dir, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		arg = strings.Trim(strings.TrimSpace(arg), `"`)

		switch name {
		case "no-store":
			cc.noStore = true
		case "must-revalidate":
			cc.mustRevalidate = true
		case "max-age":
			if n, err := strconv.Atoi(arg); err == nil {
				cc.hasMaxAge = true
				cc.maxAge = time.Duration(n) * time.Second
			}
		case "stale-while-revalidate":
			if n, err := strconv.Atoi(arg); err == nil {
				cc.staleWhileRevalidate = time.Duration(n) * time.Second
			}
		case "stale-if-error":
			if n, err := strconv.Atoi(arg); err == nil {
				cc.staleIfError = time.Duration(n) * time.Second
			}
		}
	}
	return cc
}
