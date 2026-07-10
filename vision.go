package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

const (
	visionContentType = 0x17
	visionTLSVersion  = 0x0303
	visionMaxPayload  = 16384
)

type VisionConn struct {
	reader    io.Reader
	writer    net.Conn
	readBuf   []byte
	readPos   int
	direction string
}

func NewVisionConn(r io.Reader, w net.Conn, direction string) *VisionConn {
	return &VisionConn{reader: r, writer: w, direction: direction}
}

func (vc *VisionConn) Read(p []byte) (int, error) {
	if vc.readPos < len(vc.readBuf) {
		n := copy(p, vc.readBuf[vc.readPos:])
		vc.readPos += n
		return n, nil
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(vc.reader, header); err != nil {
		return 0, fmt.Errorf("[%s] read vision header: %w", vc.direction, err)
	}

	length := binary.BigEndian.Uint16(header[3:5])
	if length == 0 {
		return 0, io.ErrUnexpectedEOF
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(vc.reader, payload); err != nil {
		return 0, fmt.Errorf("[%s] read vision payload: %w", vc.direction, err)
	}

	log.Printf("[%s] vision read: ct=0x%02x len=%d first_16=%x", vc.direction, header[0], length, payload[:min(len(payload), 16)])

	vc.readBuf = payload
	vc.readPos = 0

	n := copy(p, payload)
	vc.readPos = n
	return n, nil
}

func (vc *VisionConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > visionMaxPayload {
			chunkSize = visionMaxPayload
		}

		buf := make([]byte, 5+chunkSize)
		buf[0] = visionContentType
		binary.BigEndian.PutUint16(buf[1:3], visionTLSVersion)
		binary.BigEndian.PutUint16(buf[3:5], uint16(chunkSize))
		copy(buf[5:], p[:chunkSize])

		if _, err := vc.writer.Write(buf); err != nil {
			return total, err
		}

		total += chunkSize
		p = p[chunkSize:]
	}
	return total, nil
}

type vlessResponseConn struct {
	net.Conn
	once   sync.Once
	header []byte
	err    error
}

func (c *vlessResponseConn) Read(p []byte) (int, error) {
	c.once.Do(func() {
		h := make([]byte, 2)
		if _, err := io.ReadFull(c.Conn, h); err != nil {
			c.err = err
			return
		}
		addonLen := int(h[1])
		if addonLen > 0 {
			addon := make([]byte, addonLen)
			if _, err := io.ReadFull(c.Conn, addon); err != nil {
				c.err = err
				return
			}
			h = append(h, addon...)
		}
		c.header = h
		log.Printf("[Proxy] Backend VLESS response header (%d bytes): %x", len(h), h)
	})
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(p)
}
