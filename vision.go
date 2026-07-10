package main

import (
	"encoding/binary"
	"io"
	"net"
)

const (
	visionContentType = 0x17
	visionTLSVersion  = 0x0303
	visionMaxPayload  = 16384
)

type VisionConn struct {
	net.Conn
	readBuf []byte
	readPos int
}

func NewVisionConn(conn net.Conn) *VisionConn {
	return &VisionConn{Conn: conn}
}

func (vc *VisionConn) Read(p []byte) (int, error) {
	if vc.readPos < len(vc.readBuf) {
		n := copy(p, vc.readBuf[vc.readPos:])
		vc.readPos += n
		return n, nil
	}

	header := make([]byte, 5)
	if _, err := io.ReadFull(vc.Conn, header); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint16(header[3:5])
	if length == 0 {
		return 0, io.ErrUnexpectedEOF
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(vc.Conn, payload); err != nil {
		return 0, err
	}

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

		if _, err := vc.Conn.Write(buf); err != nil {
			return total, err
		}

		total += chunkSize
		p = p[chunkSize:]
	}
	return total, nil
}
