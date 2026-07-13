package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"sync"
	"time"
)

type HealthChecker struct {
	mu            sync.RWMutex
	statuses      map[string]bool
	pings         map[string]int64
	timeout       time.Duration
	observatoryOK bool
}

func NewHealthChecker(timeout time.Duration) *HealthChecker {
	return &HealthChecker{
		statuses: make(map[string]bool),
		pings:    make(map[string]int64),
		timeout:  timeout,
	}
}

func (h *HealthChecker) Check(addr string) (bool, int64) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, h.timeout)
	if err != nil {
		return false, 0
	}
	latency := time.Since(start).Milliseconds()
	conn.Close()
	return true, latency
}

func (h *HealthChecker) SetStatus(addr string, up bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.statuses[addr] = up
}

func (h *HealthChecker) SetPing(addr string, pingMs int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.pings[addr] = pingMs
}

func (h *HealthChecker) SetObservatoryOK(ok bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.observatoryOK = ok
}

func (h *HealthChecker) IsObservatoryOK() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.observatoryOK
}

func (h *HealthChecker) IsUp(addr string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	status, ok := h.statuses[addr]
	return ok && status
}

func (h *HealthChecker) GetPing(addr string) int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.pings[addr]
}

func (h *HealthChecker) BestUp(addrs []string) string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	type candidate struct {
		addr string
		ping int64
	}
	var candidates []candidate
	for _, addr := range addrs {
		if up, ok := h.statuses[addr]; ok && up {
			ping := h.pings[addr]
			if ping == 0 {
				ping = 9999
			}
			candidates = append(candidates, candidate{addr, ping})
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].ping < candidates[j].ping
	})
	return candidates[0].addr
}

func (h *HealthChecker) Start(addrs []string, interval time.Duration, onStatusChange func(addr string, up bool)) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			for _, addr := range addrs {
				up, ping := h.Check(addr)
				h.mu.RLock()
				prevUp := h.statuses[addr]
				obsOK := h.observatoryOK
				h.mu.RUnlock()

				h.SetPing(addr, ping)

				if up {
					log.Printf("[Health] %s UP (%dms)", addr, ping)
				}

				if obsOK {
					continue
				}

				if prevUp != up {
					h.SetStatus(addr, up)
					status := "UP"
					if !up {
						status = "DOWN"
						log.Printf("[Health] %s is %s", addr, status)
					}
					if onStatusChange != nil {
						onStatusChange(addr, up)
					}
				}
			}
		}
	}()

	for _, addr := range addrs {
		up, ping := h.Check(addr)
		h.SetStatus(addr, up)
		h.SetPing(addr, ping)
		fmt.Printf("[Health] Initial %s -> %v (%dms)\n", addr, up, ping)
	}
}
