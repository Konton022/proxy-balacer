package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
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
		log.Printf("[Proxy] TLS handshake error: %v", err)
		return
	}
	defer tlsConn.Close()
	log.Printf("[Proxy] TLS handshake OK from %s (state=%d version=%x)", tlsConn.RemoteAddr(), tlsConn.ConnectionState().HandshakeComplete, tlsConn.ConnectionState().Version)

	bufReader := bufio.NewReader(tlsConn)

	peek, _ := bufReader.Peek(64)
	log.Printf("[Proxy] Client data after TLS (%d bytes peek):\n%s", len(peek), hex.Dump(peek))

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

	debugBackend := &DebugConn{Conn: backendConn, direction: "BACKEND"}

	bw := NewFlushWriter(debugBackend)

	flowAddon := encodeFlowAddon(backend.Flow)

	header := &VLESSHeader{
		Version: 0x00,
		UUID:    backendUUID,
		Addon:   flowAddon,
		Cmd:     clientHeader.Cmd,
		Port:    clientHeader.Port,
		Atyp:    clientHeader.Atyp,
		Addr:    clientHeader.Addr,
	}

	log.Printf("[Proxy] Backend VLESS: uuid=%s addon=%d bytes cmd=%d atyp=%d port=%d addr=%x flow=%s",
		backend.UUID, len(flowAddon), header.Cmd, header.Atyp, header.Port, header.Addr, backend.Flow)

	// Test target override
	if p.config.TestTarget != "" {
		log.Printf("[Proxy] TEST MODE: overriding target %s with %s", clientHeader.TargetAddr(), p.config.TestTarget)
		host, portStr, _ := net.SplitHostPort(p.config.TestTarget)
		port := uint16(0)
		fmt.Sscanf(portStr, "%d", &port)
		header.Port = port
		if ip := net.ParseIP(host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				header.Atyp = VLESS_ATYP_IPV4
				header.Addr = []byte(ip4)
			} else {
				header.Atyp = VLESS_ATYP_IPV6
				header.Addr = []byte(ip)
			}
		} else {
			header.Atyp = VLESS_ATYP_DOMAIN
			header.Addr = []byte(host)
		}
	}

	// Log exact VLESS header bytes for debugging
	{
		var hdrBuf [64]byte
		hdrN := 0
		hdrBuf[hdrN] = header.Version; hdrN++
		copy(hdrBuf[hdrN:hdrN+16], header.UUID[:]); hdrN += 16
		hdrBuf[hdrN] = byte(len(header.Addon)); hdrN++
		if len(header.Addon) > 0 {
			copy(hdrBuf[hdrN:hdrN+len(header.Addon)], header.Addon)
			hdrN += len(header.Addon)
		}
		hdrBuf[hdrN] = header.Cmd; hdrN++
		hdrBuf[hdrN] = byte(header.Port >> 8); hdrN++
		hdrBuf[hdrN] = byte(header.Port); hdrN++
		hdrBuf[hdrN] = header.Atyp; hdrN++
		hdrBuf[hdrN] = byte(len(header.Addr)); hdrN++
		copy(hdrBuf[hdrN:hdrN+len(header.Addr)], header.Addr)
		hdrN += len(header.Addr)
		log.Printf("[Proxy] VLESS header wire bytes (%d):\n%s", hdrN, hex.Dump(hdrBuf[:hdrN]))
	}

	if err := WriteVLESSHeader(bw, header); err != nil {
		return err
	}
	bw.Flush()

	log.Printf("[Proxy] Connected to backend %s (%s) for target %s", backend.Name, backend.Addr(), clientHeader.TargetAddr())

	responseConn := &vlessResponseConn{Conn: debugBackend}

	debugClient := &DebugConn{Conn: clientConn, direction: "CLIENT"}

	var wg sync.WaitGroup
	wg.Add(2)

	var clientToBackend, backendToClient int64

	backendHasVision := strings.Contains(backend.Flow, "xtls-rprx-vision")

	if backendHasVision {
		log.Printf("[Proxy] Backend %s uses Vision relay (flow=%s)", backend.Name, backend.Flow)
		go func() {
			defer wg.Done()
			defer debugBackend.Close()
			relay := NewVisionRelay(clientReader, debugBackend, "C2B", p.proxyUUID, backendUUID)
			n, err := relay.Relay()
			atomic.AddInt64(&clientToBackend, n)
			if err != nil {
				log.Printf("[Proxy] C2B error: %v (wrote %d)", err, n)
			}
		}()

		go func() {
			defer wg.Done()
			defer debugClient.Close()
			relay := NewVisionRelay(responseConn, debugClient, "B2C", backendUUID, p.proxyUUID)
			n, err := relay.Relay()
			atomic.AddInt64(&backendToClient, n)
			if err != nil {
				log.Printf("[Proxy] B2C error: %v (wrote %d)", err, n)
			}
		}()
	} else {
		log.Printf("[Proxy] Backend %s has no Vision — using VisionReader(C2B)+VisionWriter(B2C)", backend.Name)
		go func() {
			defer wg.Done()
			defer debugBackend.Close()
			vr := NewVisionReader(clientReader, "C2B", p.proxyUUID)
			n, err := io.Copy(debugBackend, vr)
			atomic.StoreInt64(&clientToBackend, n)
			if err != nil {
				log.Printf("[Proxy] C2B no-vision error: %v (wrote %d)", err, n)
			}
		}()

		go func() {
			defer wg.Done()
			defer debugClient.Close()
			vw := NewVisionWriter(debugClient, "B2C", p.proxyUUID)
			n, err := io.Copy(vw, responseConn)
			atomic.StoreInt64(&backendToClient, n)
			if err != nil {
				log.Printf("[Proxy] B2C no-vision error: %v (wrote %d)", err, n)
			}
		}()
	}

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
