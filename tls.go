package main

import (
	"encoding/binary"
	"fmt"
)

func extractSNI(data []byte) (string, error) {
	if len(data) < 5 {
		return "", fmt.Errorf("too short for TLS record")
	}
	if data[0] != 0x16 {
		return "", fmt.Errorf("not a TLS handshake")
	}

	pos := 5
	if len(data) < pos+4 {
		return "", fmt.Errorf("too short for handshake header")
	}
	if data[pos] != 0x01 {
		return "", fmt.Errorf("not a ClientHello")
	}
	pos++

	_ = int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
	pos += 3

	if len(data) < pos+2+32 {
		return "", fmt.Errorf("too short for version+random")
	}
	pos += 2 + 32

	if len(data) < pos+1 {
		return "", fmt.Errorf("too short for session id length")
	}
	sidLen := int(data[pos])
	pos += 1 + sidLen

	if len(data) < pos+2 {
		return "", fmt.Errorf("too short for cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + csLen

	if len(data) < pos+1 {
		return "", fmt.Errorf("too short for compression methods length")
	}
	cmLen := int(data[pos])
	pos += 1 + cmLen

	if len(data) < pos+2 {
		return "", fmt.Errorf("too short for extensions length")
	}
	extLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2

	end := pos + extLen
	if end > len(data) {
		end = len(data)
	}

	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos:])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4

		if extType == 0x0000 && extDataLen > 5 && pos+extDataLen <= end {
			if data[pos] == 0x00 {
				nameLen := int(binary.BigEndian.Uint16(data[pos+3:]))
				if nameLen > 0 && pos+5+nameLen <= end {
					return string(data[pos+5 : pos+5+nameLen]), nil
				}
			}
		}
		pos += extDataLen
	}

	return "", fmt.Errorf("SNI not found")
}
