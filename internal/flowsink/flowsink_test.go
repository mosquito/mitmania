package flowsink

import "testing"

func TestCounters(t *testing.T) {
	var c Counters

	c.ConnAccepted()
	c.ConnAccepted()
	c.RequestServed()
	c.RequestServed()
	c.RequestServed()
	c.ConnClosed()

	got := c.Snapshot()
	want := Snapshot{ConnsAccepted: 2, ConnsActive: 1, Requests: 3}
	if got != want {
		t.Fatalf("Snapshot() = %+v, want %+v", got, want)
	}
}
