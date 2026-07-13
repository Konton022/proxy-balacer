package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type DebugConn struct {
	net.Conn
	direction string
}

func (dc *DebugConn) Read(p []byte) (int, error) {
	n, err := dc.Conn.Read(p)
	if n > 0 {
		log.Printf("[DEBUG %s] READ %d bytes:\n%s", dc.direction, n, hex.Dump(p[:n]))
	}
	return n, err
}

func (dc *DebugConn) Write(p []byte) (int, error) {
	log.Printf("[DEBUG %s] WRITE %d bytes:\n%s", dc.direction, len(p), hex.Dump(p))
	return dc.Conn.Write(p)
}

func (dc *DebugConn) Close() error {
	log.Printf("[DEBUG %s] CLOSE", dc.direction)
	return dc.Conn.Close()
}

func (dc *DebugConn) SetDeadline(t time.Time) error {
	return dc.Conn.SetDeadline(t)
}

func (dc *DebugConn) SetReadDeadline(t time.Time) error {
	return dc.Conn.SetReadDeadline(t)
}

func (dc *DebugConn) SetWriteDeadline(t time.Time) error {
	return dc.Conn.SetWriteDeadline(t)
}

const (
	visionHeaderSize           = 21 // UUID(16) + command(1) + content_len(2) + padding_len(2)
	visionSubsequentHeaderSize = 5  // command(1) + content_len(2) + padding_len(2) — no UUID after first frame
	visionMaxContent           = 16384
)

type VisionReader struct {
	reader    io.Reader
	uuid      [16]byte
	rawMode   bool
	isFirst   bool
	buf       []byte
	bufPos    int
	direction string
}

func NewVisionReader(r io.Reader, direction string, uuid [16]byte) *VisionReader {
	return &VisionReader{reader: r, uuid: uuid, direction: direction, isFirst: true}
}

func (vr *VisionReader) Read(p []byte) (int, error) {
	if vr.bufPos < len(vr.buf) {
		n := copy(p, vr.buf[vr.bufPos:])
		vr.bufPos += n
		return n, nil
	}

	if vr.rawMode {
		return vr.reader.Read(p)
	}

	var header []byte
	var command byte
	var contentLen, paddingLen uint16

	if vr.isFirst {
		header = make([]byte, visionHeaderSize)
		if _, err := io.ReadFull(vr.reader, header); err != nil {
			return 0, fmt.Errorf("[%s] read vision header (first): %w", vr.direction, err)
		}
		var frameUUID [16]byte
		copy(frameUUID[:], header[0:16])
		if frameUUID != vr.uuid {
			return 0, fmt.Errorf("[%s] vision UUID mismatch: got %x want %x", vr.direction, frameUUID, vr.uuid)
		}
		command = header[16]
		contentLen = binary.BigEndian.Uint16(header[17:19])
		paddingLen = binary.BigEndian.Uint16(header[19:21])
		vr.isFirst = false
		log.Printf("[%s] vision frame FIRST: cmd=%d content_len=%d padding_len=%d uuid=%x", vr.direction, command, contentLen, paddingLen, frameUUID)
	} else {
		header = make([]byte, visionSubsequentHeaderSize)
		if _, err := io.ReadFull(vr.reader, header); err != nil {
			return 0, fmt.Errorf("[%s] read vision header (subsequent): %w", vr.direction, err)
		}
		command = header[0]
		contentLen = binary.BigEndian.Uint16(header[1:3])
		paddingLen = binary.BigEndian.Uint16(header[3:5])
		log.Printf("[%s] vision frame NEXT: cmd=%d content_len=%d padding_len=%d", vr.direction, command, contentLen, paddingLen)
	}

	content := make([]byte, contentLen)
	if contentLen > 0 {
		if _, err := io.ReadFull(vr.reader, content); err != nil {
			return 0, fmt.Errorf("[%s] read vision content: %w", vr.direction, err)
		}
	}

	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		if _, err := io.ReadFull(vr.reader, padding); err != nil {
			return 0, fmt.Errorf("[%s] read vision padding: %w", vr.direction, err)
		}
	}

	if command == 0x01 || command == 0x02 {
		vr.rawMode = true
		log.Printf("[%s] vision: switching to raw mode (cmd=%d)", vr.direction, command)
	}

	vr.buf = content
	vr.bufPos = 0
	n := copy(p, content)
	vr.bufPos = n
	return n, nil
}

type VisionWriter struct {
	writer    net.Conn
	uuid      [16]byte
	rawMode   bool
	isFirst   bool
	direction string
	frameNum  int
}

func NewVisionWriter(w net.Conn, direction string, uuid [16]byte) *VisionWriter {
	return &VisionWriter{writer: w, uuid: uuid, direction: direction, isFirst: true}
}

func xtlsPadding(contentLen int) int {
	if contentLen <= 0 {
		return 0
	}
	pad := contentLen % 64
	if pad == 0 {
		return 0
	}
	return 64 - pad
}

func (vw *VisionWriter) Write(p []byte) (int, error) {
	if vw.rawMode {
		return vw.writer.Write(p)
	}

	total := 0

	if vw.isFirst {
		chunkSize := len(p)
		if chunkSize > visionMaxContent {
			chunkSize = visionMaxContent
		}

		command := byte(0x01)
		paddingSize := xtlsPadding(chunkSize)
		vw.frameNum++

		frameSize := visionHeaderSize + chunkSize + paddingSize
		frame := make([]byte, frameSize)
		copy(frame[0:16], vw.uuid[:])
		frame[16] = command
		binary.BigEndian.PutUint16(frame[17:19], uint16(chunkSize))
		binary.BigEndian.PutUint16(frame[19:21], uint16(paddingSize))
		copy(frame[21:21+chunkSize], p[:chunkSize])

		log.Printf("[%s] vision write FIRST #%d: cmd=%d content_len=%d padding_len=%d total=%d uuid=%x",
			vw.direction, vw.frameNum, command, chunkSize, paddingSize, frameSize, vw.uuid)

		if _, err := vw.writer.Write(frame); err != nil {
			return total, err
		}
		vw.isFirst = false
		total += chunkSize
		p = p[chunkSize:]
	}

	vw.rawMode = true

	if len(p) > 0 {
		n, err := vw.writer.Write(p)
		total += n
		return total, err
	}
	return total, nil
}

type VisionRelay struct {
	reader    io.Reader
	writer    net.Conn
	srcUUID   [16]byte
	dstUUID   [16]byte
	direction string
}

func NewVisionRelay(r io.Reader, w net.Conn, direction string, srcUUID, dstUUID [16]byte) *VisionRelay {
	return &VisionRelay{reader: r, writer: w, direction: direction, srcUUID: srcUUID, dstUUID: dstUUID}
}

func (vr *VisionRelay) Relay() (int64, error) {
	isFirst := true
	rawMode := false
	var total int64

	for {
		if rawMode {
			n, err := io.Copy(vr.writer, vr.reader)
			total += n
			return total, err
		}

		var headerSize int
		if isFirst {
			headerSize = visionHeaderSize
		} else {
			headerSize = visionSubsequentHeaderSize
		}

		header := make([]byte, headerSize)
		if _, err := io.ReadFull(vr.reader, header); err != nil {
			return total, fmt.Errorf("[%s] read vision header: %w", vr.direction, err)
		}

		var cmd byte
		var cl, pl uint16

		if isFirst {
			var frameUUID [16]byte
			copy(frameUUID[:], header[0:16])
			log.Printf("[%s] relay FIRST: src_uuid=%x dst_uuid=%x", vr.direction, frameUUID, vr.dstUUID)
			copy(header[0:16], vr.dstUUID[:])
			cmd = header[16]
			cl = binary.BigEndian.Uint16(header[17:19])
			pl = binary.BigEndian.Uint16(header[19:21])
			isFirst = false
		} else {
			cmd = header[0]
			cl = binary.BigEndian.Uint16(header[1:3])
			pl = binary.BigEndian.Uint16(header[3:5])
		}

		log.Printf("[%s] relay frame: cmd=%d content_len=%d padding_len=%d", vr.direction, cmd, cl, pl)

		payloadSize := int(cl) + int(pl)
		payload := make([]byte, payloadSize)
		if payloadSize > 0 {
			if _, err := io.ReadFull(vr.reader, payload); err != nil {
				return total, fmt.Errorf("[%s] read vision payload: %w", vr.direction, err)
			}
		}

		frame := make([]byte, headerSize+payloadSize)
		copy(frame, header)
		copy(frame[headerSize:], payload)

		if _, err := vr.writer.Write(frame); err != nil {
			return total, fmt.Errorf("[%s] write vision frame: %w", vr.direction, err)
		}

		total += int64(cl)

		if cmd == 0x01 || cmd == 0x02 {
			rawMode = true
			log.Printf("[%s] relay: switching to raw mode (cmd=%d)", vr.direction, cmd)
		}
	}
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
			log.Printf("[Proxy] Backend response read error: %v", err)
			c.err = err
			return
		}
		addonLen := int(h[1])
		if addonLen > 0 {
			addon := make([]byte, addonLen)
			if _, err := io.ReadFull(c.Conn, addon); err != nil {
				log.Printf("[Proxy] Backend response addon read error: %v", err)
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
