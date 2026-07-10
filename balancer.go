package main

import (
	"context"
	"log"
	"sync"
	"time"

	"gorm.io/gorm"
)

type Balancer struct {
	config      *Config
	db          *gorm.DB
	health      *HealthChecker
	mu          sync.RWMutex
	currentAddr string
	backends    []Backend
	metrics     *Metrics

	manualMode    bool
	manualAddr    string
}

func NewBalancer(db *gorm.DB, cfg *Config) *Balancer {
	b := &Balancer{
		config:  cfg,
		db:      db,
		health:  NewHealthChecker(cfg.HealthCheckTimeout),
		metrics: NewMetrics(),
	}

	b.loadBackends()
	return b
}

func (b *Balancer) loadBackends() {
	var backends []Backend
	b.db.Where("enabled = ?", true).Order("`primary` DESC, id ASC").Find(&backends)

	b.mu.Lock()
	b.backends = backends
	b.mu.Unlock()

	log.Printf("[Balancer] Loaded %d backends from database", len(backends))
}

func (b *Balancer) Reload() {
	b.loadBackends()
}

func (b *Balancer) checkSubscriptions() {
	b.mu.RLock()
	backends := make([]Backend, len(b.backends))
	copy(backends, b.backends)
	b.mu.RUnlock()

	for _, be := range backends {
		if be.SubURL == "" {
			continue
		}
		prevUp := b.health.IsUp(be.Addr())
		_, err := FetchSubscriptionURL(be.SubURL)
		if err != nil {
			if prevUp {
				log.Printf("[Health] %s subscription DOWN: %v", be.Name, err)
			}
			b.health.SetStatus(be.Addr(), false)
			if be.Addr() == b.GetActive() {
				b.failover()
			}
		} else if !prevUp {
			log.Printf("[Health] %s subscription UP", be.Name)
			b.health.SetStatus(be.Addr(), true)
			if b.config.Failback && !b.manualMode {
				b.tryFailback()
			}
		}
	}
}

func (b *Balancer) Start(ctx context.Context) {
	onChange := func(addr string, up bool) {
		if b.manualMode {
			return
		}
		if up && b.config.Failback {
			b.tryFailback()
		}
		if !up && addr == b.GetActive() {
			b.failover()
		}
	}

	b.mu.RLock()
	var tcpAddrs []string
	for _, be := range b.backends {
		tcpAddrs = append(tcpAddrs, be.Addr())
	}
	b.mu.RUnlock()

	b.health.Start(tcpAddrs, b.config.HealthCheckInterval, onChange)

	b.checkSubscriptions()
	b.selectInitial()
	log.Printf("[Balancer] Initial active server: %s (manual=%v)", b.GetActive(), b.manualMode)

	go func() {
		time.Sleep(b.config.HealthCheckInterval)
		b.checkSubscriptions()
		ticker := time.NewTicker(b.config.HealthCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				b.Reload()
				b.checkSubscriptions()
				if !b.manualMode {
					b.selectBest()
				}
			}
		}
	}()
}

func (b *Balancer) GetActive() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.currentAddr
}

func (b *Balancer) IsManual() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.manualMode
}

func (b *Balancer) GetManualAddr() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.manualAddr
}

func (b *Balancer) SetManual(addr string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if addr == "" {
		b.manualMode = false
		b.manualAddr = ""
		log.Printf("[Balancer] Switched to AUTO mode")
		b.selectBestUnlocked()
		return
	}

	b.manualMode = true
	b.manualAddr = addr
	b.currentAddr = addr
	log.Printf("[Balancer] Manual switch to %s", addr)
}

func (b *Balancer) GetAllAddrPing() map[string]int64 {
	b.mu.RLock()
	backends := make([]Backend, len(b.backends))
	copy(backends, b.backends)
	b.mu.RUnlock()

	result := make(map[string]int64)
	for _, be := range backends {
		result[be.Addr()] = b.health.GetPing(be.Addr())
	}
	return result
}

func (b *Balancer) selectInitial() {
	b.mu.Lock()
	defer b.mu.Unlock()

	best := b.health.BestUp(b.allAddrsUnlocked())
	if best != "" {
		b.currentAddr = best
		return
	}

	addrs := b.allAddrsUnlocked()
	if len(addrs) > 0 {
		b.currentAddr = addrs[0]
	}
}

func (b *Balancer) selectBest() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.selectBestUnlocked()
}

func (b *Balancer) selectBestUnlocked() {
	if b.manualMode {
		return
	}
	best := b.health.BestUp(b.allAddrsUnlocked())
	if best != "" && best != b.currentAddr {
		log.Printf("[Balancer] Best server changed: %s -> %s (ping-based)", b.currentAddr, best)
		b.currentAddr = best
	}
}

func (b *Balancer) allAddrsUnlocked() []string {
	var addrs []string
	for _, be := range b.backends {
		addrs = append(addrs, be.Addr())
	}
	return addrs
}

func (b *Balancer) failover() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.manualMode {
		return
	}

	best := b.health.BestUp(b.allAddrsUnlocked())
	if best != "" && best != b.currentAddr {
		log.Printf("[Balancer] Failover: switching from %s to %s", b.currentAddr, best)
		b.currentAddr = best
		b.metrics.RecordFailover()
		return
	}
	log.Printf("[Balancer] No healthy backends to failover to")
}

func (b *Balancer) BackendForSNI(sni string) *Backend {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for i := range b.backends {
		if b.backends[i].SNI == sni {
			return &b.backends[i]
		}
	}
	return nil
}

func (b *Balancer) IsUp(addr string) bool {
	return b.health.IsUp(addr)
}

func (b *Balancer) GetBackendByAddr(addr string) *Backend {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for i := range b.backends {
		if b.backends[i].Addr() == addr {
			return &b.backends[i]
		}
	}
	return nil
}

func (b *Balancer) GetPing(addr string) int64 {
	return b.health.GetPing(addr)
}

func (b *Balancer) tryFailback() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.config.Failback || b.manualMode {
		return
	}

	for _, be := range b.backends {
		addr := be.Addr()
		if be.Primary && addr != b.currentAddr && b.health.IsUp(addr) {
			if _, err := FetchSubscriptionURL(be.SubURL); err != nil {
				log.Printf("[Balancer] Failback skipped for %s: subscription DOWN", addr)
				continue
			}
			log.Printf("[Balancer] Failback: switching back to primary %s", addr)
			b.currentAddr = addr
			b.metrics.RecordFailback()
			return
		}
	}
}
