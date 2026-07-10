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
			if b.config.Failback {
				b.tryFailback()
			}
		}
	}
}

func (b *Balancer) Start(ctx context.Context) {
	onChange := func(addr string, up bool) {
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
	log.Printf("[Balancer] Initial active server: %s", b.GetActive())

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
			}
		}
	}()
}

func (b *Balancer) GetActive() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.currentAddr
}

func (b *Balancer) selectInitial() {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for _, be := range b.backends {
		if b.health.IsUp(be.Addr()) {
			b.currentAddr = be.Addr()
			return
		}
	}

	if len(b.backends) > 0 {
		b.currentAddr = b.backends[0].Addr()
	}
}

func (b *Balancer) failover() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, be := range b.backends {
		addr := be.Addr()
		if addr != b.currentAddr && b.health.IsUp(addr) {
			log.Printf("[Balancer] Failover: switching from %s to %s", b.currentAddr, addr)
			b.currentAddr = addr
			b.metrics.RecordFailover()
			return
		}
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

func (b *Balancer) tryFailback() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.config.Failback {
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
