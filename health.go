package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type HealthChecker struct {
	mu       sync.RWMutex
	statuses map[string]bool
	timeout  time.Duration
}

func NewHealthChecker(timeout time.Duration) *HealthChecker {
	return &HealthChecker{
		statuses: make(map[string]bool),
		timeout:  timeout,
	}
}

func (h *HealthChecker) Check(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, h.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (h *HealthChecker) SetStatus(addr string, up bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statuses[addr] = up
}

func (h *HealthChecker) IsUp(addr string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	status, ok := h.statuses[addr]
	return ok && status
}

func (h *HealthChecker) Start(addrs []string, interval time.Duration, onStatusChange func(addr string, up bool)) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			for _, addr := range addrs {
				up := h.Check(addr)
				h.mu.RLock()
				prevUp := h.statuses[addr]
				h.mu.RUnlock()

				if prevUp != up {
					h.SetStatus(addr, up)
					status := "UP"
					if !up {
						status = "DOWN"
					}
					log.Printf("[Health] %s is %s", addr, status)
					if onStatusChange != nil {
						onStatusChange(addr, up)
					}
				}
			}
		}
	}()

	for _, addr := range addrs {
		up := h.Check(addr)
		h.SetStatus(addr, up)
		fmt.Printf("[Health] Initial %s -> %v\n", addr, up)
	}
}
