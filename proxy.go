package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Proxy struct {
	balancer *Balancer
	admin    *AdminServer
	metrics  *Metrics
	config   *Config
	conns    atomic.Int64
	tlsCfg   *tls.Config
	proxyUUID [16]byte
}

func NewProxy(b *Balancer, admin *AdminServer) *Proxy {
	p := &Proxy{
		balancer: b,
		admin:    admin,
		metrics:  NewMetrics(),
		config:   b.config,
	}
	if b.config.ProxyUUID != "" {
		p.proxyUUID, _ = ParseUUID(b.config.ProxyUUID)
	} else {
		p.proxyUUID, _ = ParseUUID("00000000-0000-0000-0000-000000000000")
	}
	return p
}

func (p *Proxy) Metrics() *Metrics {
	return p.metrics
}

func (p *Proxy) InitTLS() error {
	cert, err := tls.LoadX509KeyPair(p.config.TLSCertFile, p.config.TLSKeyFile)
	if err != nil {
		return err
	}
	p.tlsCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return nil
}

func (p *Proxy) Serve(ctx context.Context, listener net.Listener) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[Proxy] Accept error: %v", err)
				continue
			}
		}
		go p.handleRawConnection(conn)
	}
}

func (p *Proxy) handleRawConnection(conn net.Conn) {
	firstByte := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := io.ReadFull(conn, firstByte)
	conn.SetReadDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return
	}

	prepend := &PrependConn{Conn: conn, buf: firstByte}

	if firstByte[0] == 0x16 {
		p.handleTLSConnection(prepend)
	} else if firstByte[0] == 'G' || firstByte[0] == 'P' || firstByte[0] == 'D' || firstByte[0] == 'C' || firstByte[0] == 'O' {
		p.handleHTTPConnection(prepend)
	} else {
		conn.Close()
	}
}

type PrependConn struct {
	net.Conn
	buf []byte
}

func (c *PrependConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (p *Proxy) handleTLSConnection(conn net.Conn) {
	p.metrics.RecordConnection()
	defer func() {
		p.metrics.RecordClose()
		conn.Close()
	}()

	if p.tlsCfg == nil {
		return
	}

	tlsConn := tls.Server(conn, p.tlsCfg)
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()

	bufReader := bufio.NewReader(tlsConn)
	header, err := ReadVLESSHeader(bufReader)
	if err != nil {
		log.Printf("[Proxy] VLESS header error: %v", err)
		return
	}

	clientUUID := UUIDToString(header.UUID)
	log.Printf("[Proxy] Client UUID=%s target=%s", clientUUID, header.TargetAddr())

	activeAddr := p.balancer.GetActive()
	if activeAddr == "" {
		log.Printf("[Proxy] No active backend")
		return
	}

	backend := p.balancer.GetBackendByAddr(activeAddr)
	if backend == nil {
		log.Printf("[Proxy] Backend not found for %s", activeAddr)
		return
	}

	if backend.UUID == "" {
		log.Printf("[Proxy] Backend %s has no UUID configured", backend.Name)
		return
	}

	err = p.proxyToBackend(header, backend, bufReader, tlsConn)
	if err != nil {
		log.Printf("[Proxy] Backend error: %v", err)
		p.metrics.RecordFailure()
	}
}

func (p *Proxy) proxyToBackend(clientHeader *VLESSHeader, backend *Backend, clientReader *bufio.Reader, clientConn net.Conn) error {
	cfg := &RealityConfig{
		Addr:        backend.Addr(),
		SNI:         backend.SNI,
		PubKey:      backend.RealityPubKey,
		ShortID:     backend.RealityShortID,
		SpiderX:     backend.RealitySpiderX,
		Fingerprint: backend.Fingerprint,
		Flow:        backend.Flow,
	}

	backendUUID, err := ParseUUID(backend.UUID)
	if err != nil {
		return err
	}

	backendConn, err := DialReality(cfg)
	if err != nil {
		return err
	}
	defer backendConn.Close()

	bw := NewFlushWriter(backendConn)
	header := &VLESSHeader{
		Version: 0x00,
		UUID:    backendUUID,
		Addon:   clientHeader.Addon,
		Cmd:     clientHeader.Cmd,
		Port:    clientHeader.Port,
		Atyp:    clientHeader.Atyp,
		Addr:    clientHeader.Addr,
	}
	if err := WriteVLESSHeader(bw, header); err != nil {
		return err
	}
	bw.Flush()

	log.Printf("[Proxy] Connected to backend %s (%s) for target %s", backend.Name, backend.Addr(), clientHeader.TargetAddr())

	visionBackend := NewVisionConn(backendConn)

	var wg sync.WaitGroup
	wg.Add(2)

	var clientToBackend, backendToClient int64

	go func() {
		defer wg.Done()
		n, _ := io.Copy(visionBackend, clientReader)
		atomic.AddInt64(&clientToBackend, n)
		backendConn.Close()
	}()

	go func() {
		defer wg.Done()
		n, _ := io.Copy(clientConn, visionBackend)
		atomic.AddInt64(&backendToClient, n)
		clientConn.Close()
	}()

	wg.Wait()
	log.Printf("[Proxy] Relay done: client→backend=%d bytes, backend→client=%d bytes, target=%s", clientToBackend, backendToClient, clientHeader.TargetAddr())
	return nil
}

func (p *Proxy) handleHTTPConnection(conn net.Conn) {
	defer conn.Close()

	bufReader := bufio.NewReader(conn)
	req, err := http.ReadRequest(bufReader)
	if err != nil {
		return
	}

	if strings.HasPrefix(req.URL.Path, "/sub/") {
		p.admin.ServeSubscriptionHTTP(conn, req)
		return
	}

	w := &httpResponseWriter{conn: conn}
	http.Error(w, "Not Found", 404)
}

type httpResponseWriter struct {
	conn net.Conn
}

func (w *httpResponseWriter) Header() http.Header         { return http.Header{} }
func (w *httpResponseWriter) Write(b []byte) (int, error)  { return w.conn.Write(b) }
func (w *httpResponseWriter) WriteHeader(statusCode int)   {}
