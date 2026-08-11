package session

// Acceptor is the only layer aware of transport: it fills in
// Session{Client, Dst, Conn} however its transport mode determines them.
// HTTPProxyAcceptor (explicit), RedirectAcceptor, and TProxyAcceptor
// (both Linux-only transparent modes) implement it. QUIC is a documented
// future extension point, not stubbed here.
type Acceptor interface {
	Accept() (Session, error)
	Close() error
}
