package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type Metrics struct {
	TotalConnections   atomic.Int64
	ActiveConnections  atomic.Int64
	FailedConnections  atomic.Int64
	RetriedConnections atomic.Int64
	FailoverCount      atomic.Int64
	FailbackCount      atomic.Int64

	LastFailover  time.Time
	LastFailback  time.Time
	StartTime     time.Time

	mu             sync.Mutex
	recentConns    []time.Time
	recentFails    []time.Time
}

func NewMetrics() *Metrics {
	return &Metrics{
		StartTime:   time.Now(),
		recentConns: make([]time.Time, 0, 100),
		recentFails: make([]time.Time, 0, 100),
	}
}

func (m *Metrics) RecordConnection() {
	m.TotalConnections.Add(1)
	m.ActiveConnections.Add(1)
	m.mu.Lock()
	m.recentConns = append(m.recentConns, time.Now())
	if len(m.recentConns) > 100 {
		m.recentConns = m.recentConns[1:]
	}
	m.mu.Unlock()
}

func (m *Metrics) RecordClose() {
	m.ActiveConnections.Add(-1)
}

func (m *Metrics) RecordFailure() {
	m.FailedConnections.Add(1)
	m.mu.Lock()
	m.recentFails = append(m.recentFails, time.Now())
	if len(m.recentFails) > 100 {
		m.recentFails = m.recentFails[1:]
	}
	m.mu.Unlock()
}

func (m *Metrics) RecordRetry() {
	m.RetriedConnections.Add(1)
}

func (m *Metrics) RecordFailover() {
	m.FailoverCount.Add(1)
	m.mu.Lock()
	m.LastFailover = time.Now()
	m.mu.Unlock()
}

func (m *Metrics) RecordFailback() {
	m.FailbackCount.Add(1)
	m.mu.Lock()
	m.LastFailback = time.Now()
	m.mu.Unlock()
}

func (m *Metrics) ConnsPerMinute() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-1 * time.Minute)
	count := 0
	for _, t := range m.recentConns {
		if t.After(cutoff) {
			count++
		}
	}
	return float64(count)
}

func (m *Metrics) Snapshot() map[string]interface{} {
	return map[string]interface{}{
		"total_connections":   m.TotalConnections.Load(),
		"active_connections":  m.ActiveConnections.Load(),
		"failed_connections":  m.FailedConnections.Load(),
		"retried_connections": m.RetriedConnections.Load(),
		"failover_count":      m.FailoverCount.Load(),
		"failback_count":      m.FailbackCount.Load(),
		"last_failover":       m.LastFailover.Format(time.RFC3339),
		"last_failback":       m.LastFailback.Format(time.RFC3339),
		"uptime":              time.Since(m.StartTime).Truncate(time.Second).String(),
		"conns_per_minute":    int(m.ConnsPerMinute()),
	}
}
