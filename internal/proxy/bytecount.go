package proxy

import "io"

// countingReadCloser tees Read through to n — used to measure a request
// body forwarded straight into a RoundTrip (h2's r.Body, never buffered
// whole) so its total size can be reported once the transport has drained
// it. h1's equivalent (a full request, headers+body) is already measured
// by roundtrip.go's countingWriter around req.Write, since h1's own
// Transport writes the whole request through one io.Writer.
type countingReadCloser struct {
	io.ReadCloser
	n int64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	c.n += int64(n)
	return n, err
}
