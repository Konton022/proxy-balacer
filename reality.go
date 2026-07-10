package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

type RealityConfig struct {
	Addr       string
	SNI        string
	PubKey     string
	ShortID    string
	SpiderX    string
	Fingerprint string
	Flow       string
}

func base64ToBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

func buildClientHelloID(fp string) utls.ClientHelloID {
	switch strings.ToLower(fp) {
	case "chrome":
		return utls.HelloChrome_Auto
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloIOS_Auto
	case "edge":
		return utls.HelloEdge_Auto
	case "random", "randomized":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

type realityExtension struct {
	shortID  [8]byte
	pubKey   [32]byte
	spiderX  string
}

func (e *realityExtension) Len() int {
	return 8 + 32 + 2 + len(e.spiderX)
}

func (e *realityExtension) Serialize() []byte {
	buf := make([]byte, 0, e.Len())
	buf = append(buf, e.shortID[:]...)
	buf = append(buf, e.pubKey[:]...)
	spiderXLen := len(e.spiderX)
	buf = append(buf, byte(spiderXLen>>8), byte(spiderXLen))
	buf = append(buf, []byte(e.spiderX)...)
	return buf
}

func DialReality(cfg *RealityConfig) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", cfg.Addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.Addr, err)
	}

	pubKeyBytes, err := base64ToBytes(cfg.PubKey)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("decode pubkey: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		conn.Close()
		return nil, fmt.Errorf("invalid pubkey length: %d", len(pubKeyBytes))
	}

	var pubKey [32]byte
	copy(pubKey[:], pubKeyBytes)

	var shortID [8]byte
	if cfg.ShortID != "" {
		sidBytes, err := base64ToBytes(cfg.ShortID)
		if err == nil {
			copy(shortID[:], sidBytes[:min(len(sidBytes), 8)])
		}
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}

	helloID := buildClientHelloID(cfg.Fingerprint)

	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         cfg.SNI,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, helloID)

	spec := utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			utls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{ServerName: cfg.SNI},
			&utls.UtlsExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateOnceAsClient},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SupportedVersionsExtension{Versions: []uint16{
				utls.GREASE_PLACEHOLDER,
				utls.VersionTLS13,
				utls.VersionTLS12,
			}},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{
				{Group: utls.X25519, Data: make([]byte, 32)},
			}},
			&utls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&utls.SCTExtension{},
			&utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle},
		},
	}

	_ = ecdsaKey

	if err := uconn.ApplyPreset(&spec); err != nil {
		conn.Close()
		return nil, fmt.Errorf("apply preset: %w", err)
	}

	if err := uconn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	log.Printf("[Reality] Connected to %s (SNI=%s)", cfg.Addr, cfg.SNI)
	return uconn.Conn, nil
}

func ProxyToBackend(clientHeader *VLESSHeader, clientReader io.Reader, clientWriter io.Writer, backend *Backend, proxyUUID string) error {
	cfg := &RealityConfig{
		Addr:       backend.Addr(),
		SNI:        backend.SNI,
		PubKey:     backend.RealityPubKey,
		ShortID:    backend.RealityShortID,
		SpiderX:    backend.RealitySpiderX,
		Fingerprint: backend.Fingerprint,
		Flow:       backend.Flow,
	}

	backendUUID, err := ParseUUID(backend.UUID)
	if err != nil {
		return fmt.Errorf("parse backend uuid: %w", err)
	}

	backendConn, err := DialReality(cfg)
	if err != nil {
		return fmt.Errorf("dial reality: %w", err)
	}
	defer backendConn.Close()

	bw := NewFlushWriter(backendConn)
	header := &VLESSHeader{
		Version: 0x00,
		UUID:    backendUUID,
		Cmd:     clientHeader.Cmd,
		Port:    clientHeader.Port,
		Atyp:    clientHeader.Atyp,
		Addr:    clientHeader.Addr,
	}
	if err := WriteVLESSHeader(bw, header); err != nil {
		return fmt.Errorf("write vless header: %w", err)
	}
	bw.Flush()

	done := make(chan struct{}, 2)

	go func() {
		io.Copy(backendConn, clientReader)
		if tc, ok := backendConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		io.Copy(clientWriter, backendConn)
		if tc, ok := clientWriter.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()

	<-done
	return nil
}

type FlushWriter struct {
	w   io.Writer
	buf []byte
}

func NewFlushWriter(w io.Writer) *FlushWriter {
	return &FlushWriter{w: w}
}

func (fw *FlushWriter) Write(p []byte) (n int, err error) {
	fw.buf = append(fw.buf, p...)
	return len(p), nil
}

func (fw *FlushWriter) Flush() error {
	_, err := fw.w.Write(fw.buf)
	fw.buf = fw.buf[:0]
	return err
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
