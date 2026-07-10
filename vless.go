package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	VLESS_CMD_TCP byte = 0x01
	VLESS_CMD_UDP byte = 0x02

	VLESS_ATYP_IPV4   byte = 0x01
	VLESS_ATYP_DOMAIN byte = 0x02
	VLESS_ATYP_IPV6   byte = 0x04
)

type VLESSHeader struct {
	Version byte
	UUID    [16]byte
	Addon   []byte
	Cmd     byte
	Port    uint16
	Atyp    byte
	Addr    []byte
}

func ParseUUID(s string) ([16]byte, error) {
	var uuid [16]byte
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return uuid, fmt.Errorf("invalid UUID length: %d", len(s))
	}
	for i := 0; i < 16; i++ {
		_, err := fmt.Sscanf(s[i*2:i*2+2], "%02x", &uuid[i])
		if err != nil {
			return uuid, fmt.Errorf("invalid UUID byte %d: %v", i, err)
		}
	}
	return uuid, nil
}

func UUIDToString(uuid [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}

func ReadVLESSHeader(r io.Reader) (*VLESSHeader, error) {
	h := &VLESSHeader{}

	if err := binary.Read(r, binary.BigEndian, &h.Version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if h.Version != 0x00 {
		return nil, fmt.Errorf("unsupported VLESS version: %d", h.Version)
	}

	if err := binary.Read(r, binary.BigEndian, &h.UUID); err != nil {
		return nil, fmt.Errorf("read uuid: %w", err)
	}

	var addonLen byte
	if err := binary.Read(r, binary.BigEndian, &addonLen); err != nil {
		return nil, fmt.Errorf("read addon len: %w", err)
	}
	if addonLen > 0 {
		h.Addon = make([]byte, addonLen)
		if _, err := io.ReadFull(r, h.Addon); err != nil {
			return nil, fmt.Errorf("read addon: %w", err)
		}
	}

	if err := binary.Read(r, binary.BigEndian, &h.Cmd); err != nil {
		return nil, fmt.Errorf("read cmd: %w", err)
	}

	if err := binary.Read(r, binary.BigEndian, &h.Port); err != nil {
		return nil, fmt.Errorf("read port: %w", err)
	}

	if err := binary.Read(r, binary.BigEndian, &h.Atyp); err != nil {
		return nil, fmt.Errorf("read atyp: %w", err)
	}

	switch h.Atyp {
	case VLESS_ATYP_IPV4:
		h.Addr = make([]byte, 4)
		if _, err := io.ReadFull(r, h.Addr); err != nil {
			return nil, fmt.Errorf("read ipv4: %w", err)
		}
	case VLESS_ATYP_IPV6:
		h.Addr = make([]byte, 16)
		if _, err := io.ReadFull(r, h.Addr); err != nil {
			return nil, fmt.Errorf("read ipv6: %w", err)
		}
	case VLESS_ATYP_DOMAIN:
		var domainLen byte
		if err := binary.Read(r, binary.BigEndian, &domainLen); err != nil {
			return nil, fmt.Errorf("read domain len: %w", err)
		}
		h.Addr = make([]byte, domainLen)
		if _, err := io.ReadFull(r, h.Addr); err != nil {
			return nil, fmt.Errorf("read domain: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown atyp: %d", h.Atyp)
	}

	return h, nil
}

func WriteVLESSHeader(w io.Writer, h *VLESSHeader) error {
	binary.Write(w, binary.BigEndian, h.Version)
	binary.Write(w, binary.BigEndian, h.UUID)
	addonLen := byte(len(h.Addon))
	binary.Write(w, binary.BigEndian, addonLen)
	if len(h.Addon) > 0 {
		binary.Write(w, binary.BigEndian, h.Addon)
	}
	binary.Write(w, binary.BigEndian, h.Cmd)
	binary.Write(w, binary.BigEndian, h.Port)
	binary.Write(w, binary.BigEndian, h.Atyp)

	switch h.Atyp {
	case VLESS_ATYP_IPV4, VLESS_ATYP_IPV6:
		binary.Write(w, binary.BigEndian, h.Addr)
	case VLESS_ATYP_DOMAIN:
		binary.Write(w, binary.BigEndian, byte(len(h.Addr)))
		binary.Write(w, binary.BigEndian, h.Addr)
	}
	return nil
}

func (h *VLESSHeader) TargetAddr() string {
	switch h.Atyp {
	case VLESS_ATYP_IPV4:
		return fmt.Sprintf("%d.%d.%d.%d:%d", h.Addr[0], h.Addr[1], h.Addr[2], h.Addr[3], h.Port)
	case VLESS_ATYP_IPV6:
		ip := net.IP(h.Addr)
		return fmt.Sprintf("[%s]:%d", ip.String(), h.Port)
	case VLESS_ATYP_DOMAIN:
		return fmt.Sprintf("%s:%d", string(h.Addr), h.Port)
	}
	return ""
}
