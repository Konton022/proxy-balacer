package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <addr> <sni> <target-host:port> [uuid] [pubkey] [shortid] [flow] [spiderx]\n", os.Args[0])
		os.Exit(1)
	}

	addr := os.Args[1]
	sni := os.Args[2]
	target := os.Args[3]

	uuid := "b5e3a7c1-8f2d-4e6a-9b0c-1d3e5f7a9b2c"
	pubkey := ""
	shortid := ""
	flow := "xtls-rprx-vision"
	spiderx := ""

	if len(os.Args) > 4 { uuid = os.Args[4] }
	if len(os.Args) > 5 { pubkey = os.Args[5] }
	if len(os.Args) > 6 { shortid = os.Args[6] }
	if len(os.Args) > 7 { flow = os.Args[7] }
	if len(os.Args) > 8 { spiderx = os.Args[8] }

	log.Printf("=== VLESS Backend Probe ===")
	log.Printf("Backend: %s (SNI=%s)", addr, sni)
	log.Printf("Target: %s", target)
	log.Printf("UUID: %s Flow: %s", uuid, flow)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		log.Fatalf("TCP dial failed: %v", err)
	}
	log.Printf("TCP connected")

	pubKeyBytes, _ := base64Decode(pubkey)

	var shortID [8]byte
	if shortid != "" {
		sidBytes, err := hex.DecodeString(shortid)
		if err != nil {
			sidBytes, _ = base64Decode(shortid)
		}
		copy(shortID[:], sidBytes[:min(len(sidBytes), 8)])
	}

	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_ = ecdsaKey

	uconn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}, utls.HelloChrome_Auto)

	extensions := []utls.TLSExtension{
		&utls.SNIExtension{ServerName: sni},
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
	}

	if len(pubKeyBytes) == 32 {
		spiderXBytes := []byte(spiderx)
		spiderXLen := len(spiderXBytes)
		realityData := make([]byte, 0, 8+32+2+spiderXLen)
		realityData = append(realityData, shortID[:]...)
		realityData = append(realityData, pubKeyBytes...)
		realityData = append(realityData, byte(spiderXLen>>8), byte(spiderXLen))
		realityData = append(realityData, spiderXBytes...)
		extensions = append(extensions, &utls.GenericExtension{Id: 0xff00, Data: realityData})
		log.Printf("Reality extension: shortID=%x pubkey=%x spiderX=%q", shortID, pubKeyBytes, spiderx)
	} else {
		log.Printf("WARNING: pubkey not 32 bytes (%d), skipping Reality extension", len(pubKeyBytes))
	}

	spec := utls.ClientHelloSpec{
		CipherSuites: []uint16{
			utls.GREASE_PLACEHOLDER,
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_AES_256_GCM_SHA384,
			utls.TLS_CHACHA20_POLY1305_SHA256,
			utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []byte{0},
		Extensions:         extensions,
	}

	if err := uconn.ApplyPreset(&spec); err != nil {
		log.Fatalf("ApplyPreset: %v", err)
	}

	if err := uconn.Handshake(); err != nil {
		log.Fatalf("TLS handshake: %v", err)
	}
	log.Printf("TLS handshake OK")

	parsedUUID, _ := parseUUID(uuid)
	flowAddon := encodeFlowAddon(flow)

	host, portStr, _ := splitHostPort(target)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// Build wire bytes
	var hdrBuf [128]byte
	n := 0
	hdrBuf[n] = 0x00; n++
	copy(hdrBuf[n:n+16], parsedUUID[:]); n += 16
	hdrBuf[n] = byte(len(flowAddon)); n++
	copy(hdrBuf[n:n+len(flowAddon)], flowAddon); n += len(flowAddon)
	hdrBuf[n] = 0x01; n++
	binary.BigEndian.PutUint16(hdrBuf[n:n+2], port); n += 2
	hdrBuf[n] = 0x02; n++
	hdrBuf[n] = byte(len(host)); n++
	copy(hdrBuf[n:n+len(host)], []byte(host)); n += len(host)

	log.Printf("VLESS request (%d bytes):\n%s", n, hex.Dump(hdrBuf[:n]))

	uconn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := uconn.Write(hdrBuf[:n]); err != nil {
		log.Fatalf("Write VLESS header: %v", err)
	}
	log.Printf("VLESS header sent!")

	if flow == "xtls-rprx-vision" {
		httpPayload := []byte("GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n")
		padSize := 0
		if len(httpPayload) > 0 {
			pad := len(httpPayload) % 64
			if pad != 0 {
				padSize = 64 - pad
			}
		}

		var visionFrame []byte
		visionFrame = append(visionFrame, parsedUUID[:]...)
		visionFrame = append(visionFrame, 0x01)
		var clBuf [2]byte
		binary.BigEndian.PutUint16(clBuf[:], uint16(len(httpPayload)))
		visionFrame = append(visionFrame, clBuf[:]...)
		var plBuf [2]byte
		binary.BigEndian.PutUint16(plBuf[:], uint16(padSize))
		visionFrame = append(visionFrame, plBuf[:]...)
		visionFrame = append(visionFrame, httpPayload...)
		visionFrame = append(visionFrame, make([]byte, padSize)...)

		log.Printf("Vision frame (%d bytes, content=%d pad=%d):\n%s", len(visionFrame), len(httpPayload), padSize, hex.Dump(visionFrame))
		uconn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := uconn.Write(visionFrame); err != nil {
			log.Fatalf("Write Vision frame: %v", err)
		}
		log.Printf("Vision frame sent! Waiting for response...")
	} else {
		httpPayload := "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
		log.Printf("Sending raw HTTP request (%d bytes)", len(httpPayload))
		uconn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := uconn.Write([]byte(httpPayload)); err != nil {
			log.Printf("Write HTTP request: %v", err)
		}
	}

	uconn.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp := make([]byte, 8192)
	for i := 0; i < 5; i++ {
		rn, err := uconn.Read(resp)
		if err != nil {
			log.Printf("Read %d: %v", i+1, err)
			break
		}
		log.Printf("Data read %d (%d bytes):\n%s", i+1, rn, hex.Dump(resp[:rn]))
	}

	log.Printf("=== Done ===")
}

func parseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	for i := 0; i < 16; i++ {
		fmt.Sscanf(s[i*2:i*2+2], "%02x", &uuid[i])
	}
	return uuid, nil
}

func encodeFlowAddon(flow string) []byte {
	if flow == "" { return nil }
	return append([]byte{0x0a, byte(len(flow))}, []byte(flow)...)
}

func base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2: s += "=="
	case 3: s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

func splitHostPort(addr string) (string, string, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "0", nil
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
