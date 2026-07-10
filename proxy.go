package main

import (
	"bufio"
	"context"
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
}

func NewProxy(b *Balancer, admin *AdminServer) *Proxy {
	return &Proxy{
		balancer: b,
		admin:    admin,
		metrics:  NewMetrics(),
		config:   b.config,
	}
}

func (p *Proxy) Metrics() *Metrics {
	return p.metrics
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
		go p.handleConnection(conn)
	}
}

func (p *Proxy) routeBySNI(sni string) string {
	be := p.balancer.BackendForSNI(sni)
	if be != nil && p.balancer.IsUp(be.Addr()) {
		return be.Addr()
	}
	return p.balancer.GetActive()
}

func (p *Proxy) handleConnection(clientConn net.Conn) {
	p.metrics.RecordConnection()
	defer func() {
		p.metrics.RecordClose()
		clientConn.Close()
	}()

	bufReader := bufio.NewReader(clientConn)

	peek, err := bufReader.Peek(4)
	if err != nil {
		return
	}

	if string(peek) == "GET " || string(peek) == "POST" {
		req, err := http.ReadRequest(bufReader)
		if err != nil {
			return
		}
		if strings.HasPrefix(req.URL.Path, "/sub/") {
			p.admin.ServeSubscriptionHTTP(clientConn, req)
			return
		}
		return
	}

	peek512, err := bufReader.Peek(512)
	var backendAddr string
	if err == nil && peek512[0] == 0x16 {
		sni, err := extractSNI(peek512)
		if err == nil && sni != "" {
			backendAddr = p.routeBySNI(sni)
			if backendAddr != "" {
				log.Printf("[Proxy] SNI=%s -> %s", sni, backendAddr)
			}
		}
	}

	if backendAddr == "" {
		backendAddr = p.balancer.GetActive()
	}
	if backendAddr == "" {
		return
	}

	backendConn := p.dialWithRetry(backendAddr)
	if backendConn == nil {
		p.metrics.RecordFailure()
		return
	}
	defer backendConn.Close()

	p.proxyBuffers(clientConn, backendConn, bufReader)
}

func (p *Proxy) dialWithRetry(addr string) net.Conn {
	timeout := p.config.HealthCheckTimeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}

	retries := p.config.RetryCount
	if retries <= 0 {
		retries = 2
	}

	delay := p.config.RetryDelay
	if delay == 0 {
		delay = 500 * time.Millisecond
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err == nil {
		return conn
	}

	for i := 0; i < retries; i++ {
		p.metrics.RecordRetry()
		time.Sleep(delay)
		conn, err = net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			return conn
		}
	}

	return nil
}

func (p *Proxy) proxyBuffers(clientConn net.Conn, backendConn net.Conn, clientBuf *bufio.Reader) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(backendConn, clientBuf)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, backendConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}
