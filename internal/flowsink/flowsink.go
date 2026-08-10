// Package flowsink implements mitmania's connection/request telemetry —
// a single FlowSink instance reused by every handler, feeding the
// control API's /stats.
package flowsink

import "sync/atomic"

// FlowSink records connection/request-level counters. Counters is the
// only implementation.
type FlowSink interface {
	ConnAccepted()
	ConnClosed()
	RequestServed()
}

// Counters is a plain atomic-counter FlowSink.
type Counters struct {
	connsAccepted atomic.Int64
	connsActive   atomic.Int64
	requests      atomic.Int64
}

func (c *Counters) ConnAccepted() {
	c.connsAccepted.Add(1)
	c.connsActive.Add(1)
}

func (c *Counters) ConnClosed() {
	c.connsActive.Add(-1)
}

func (c *Counters) RequestServed() {
	c.requests.Add(1)
}

// Snapshot is a point-in-time, JSON-friendly read of Counters.
type Snapshot struct {
	ConnsAccepted int64 `json:"conns_accepted"`
	ConnsActive   int64 `json:"conns_active"`
	Requests      int64 `json:"requests"`
}

func (c *Counters) Snapshot() Snapshot {
	return Snapshot{
		ConnsAccepted: c.connsAccepted.Load(),
		ConnsActive:   c.connsActive.Load(),
		Requests:      c.requests.Load(),
	}
}
