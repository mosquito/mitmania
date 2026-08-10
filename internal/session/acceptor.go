package session

// Acceptor is the only layer aware of transport: it fills in
// Session{Client, Dst, Conn} however its transport mode determines them.
// HTTPProxyAcceptor is the only implementation this pass — transparent
// (TPROXY/REDIRECT) and QUIC acceptors are a documented future extension
// point, not stubbed here.
type Acceptor interface {
	Accept() (Session, error)
	Close() error
}
