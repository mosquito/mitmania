package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"mitmania/internal/telemetry"
)

func TestTLSService_Terminate_RecordsClientHandshakeMetric(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ts.Close()
	dst := ts.Listener.Addr().String()
	const sni = "example.com"

	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer mp.Shutdown(context.Background())
	metrics, err := telemetry.NewMetrics(mp.Meter("test"))
	if err != nil {
		t.Fatalf("NewMetrics: %v", err)
	}

	factory, ca := newTestFactory(t)
	svc := &TLSService{Factory: factory, Metrics: metrics}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	tlsClient := tls.Client(clientConn, &tls.Config{
		ServerName: sni,
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})

	clientErr := make(chan error, 1)
	go func() { clientErr <- tlsClient.Handshake() }()

	result, err := svc.Terminate(context.Background(), serverConn, NewUpstreamDialer(5*time.Second, 1), dst, sni)
	if err != nil {
		t.Fatalf("Terminate: %v", err)
	}
	defer result.Client.Close()
	defer result.Upstream.Close()
	if err := <-clientErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	dur, ok := findUpstreamMetric(t, &rm, "mitmania.tls.handshake.duration")
	if !ok {
		t.Fatalf("mitmania.tls.handshake.duration not recorded")
	}
	hist := dur.Data.(metricdata.Histogram[float64])
	var sawClient bool
	for _, dp := range hist.DataPoints {
		if v, ok := dp.Attributes.Value("leg"); ok && v.AsString() == "client" {
			sawClient = true
		}
	}
	if !sawClient {
		t.Errorf("tls.handshake.duration data points = %#v, want a leg=client point", hist.DataPoints)
	}
}
