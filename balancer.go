package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	lastSyncedAddr string
	lastSyncTime   time.Time
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
		_, err := FetchSubscriptionURL(be.SubURL)
		if err != nil {
			if b.health.IsUp(be.Addr()) {
				log.Printf("[Health] %s subscription DOWN: %v", be.Name, err)
			}
			b.health.SetStatus(be.Addr(), false)
			if be.Addr() == b.GetActive() {
				b.failover()
			}
		}
	}
}

func (b *Balancer) Start(ctx context.Context) {
	obsWatcher := NewObservatoryWatcher(b.health)
	obsWatcher.OnStatusChange(func(addr string, up bool) {
		if b.manualMode {
			return
		}
		if !up && addr == b.GetActive() {
			b.failover()
		}
	})
	obsWatcher.Start()

	onChange := func(addr string, up bool) {
		if b.manualMode {
			return
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
		b.syncXrayLocked(b.currentAddr)
		return
	}

	b.manualMode = true
	b.manualAddr = addr
	b.currentAddr = addr
	log.Printf("[Balancer] Manual switch to %s", addr)
	b.syncXrayLocked(addr)
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
		b.syncXrayLocked(best)
		return
	}

	addrs := b.allAddrsUnlocked()
	if len(addrs) > 0 {
		b.currentAddr = addrs[0]
		b.syncXrayLocked(addrs[0])
	}
}

func (b *Balancer) selectBest() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.selectBestUnlocked()
	b.syncXrayLocked(b.currentAddr)
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
		b.syncXrayLocked(best)
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
			b.syncXrayLocked(addr)
			return
		}
	}
}

const xrayConfigPath = "/opt/proxy-balancer/xray-config.json"

func (b *Balancer) syncXrayLocked(addr string) {
	if addr == b.lastSyncedAddr && time.Since(b.lastSyncTime) < 30*time.Second {
		return
	}
	b.lastSyncedAddr = addr
	b.lastSyncTime = time.Now()

	data, err := os.ReadFile(xrayConfigPath)
	if err != nil {
		log.Printf("[Balancer] Failed to read xray config: %v", err)
		return
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Printf("[Balancer] Failed to parse xray config: %v", err)
		return
	}

	routing, ok := cfg["routing"].(map[string]interface{})
	if !ok {
		return
	}

	rules, ok := routing["rules"].([]interface{})
	if !ok {
		return
	}

	var newRules []interface{}
	for _, r := range rules {
		rule, ok := r.(map[string]interface{})
		if !ok {
			newRules = append(newRules, r)
			continue
		}
		obTag, _ := rule["outboundTag"].(string)
		_, hasBalancer := rule["balancerTag"]
		if strings.HasPrefix(obTag, "proxy-") || hasBalancer {
			continue
		}
		newRules = append(newRules, r)
	}

	if addr != "" {
		outboundTag := b.findOutboundTag(addr, cfg)
		if outboundTag == "" {
			log.Printf("[Balancer] Could not find xray outbound for address %s", addr)
			routing["rules"] = newRules
		} else {
			log.Printf("[Balancer] Xray routing forced to %s (outbound: %s)", addr, outboundTag)
			manualRule := map[string]interface{}{
				"inboundTag":  []interface{}{"vless-in", "vless-ws-in"},
				"outboundTag": outboundTag,
			}
			routing["rules"] = append([]interface{}{manualRule}, newRules...)
		}
	} else {
		log.Printf("[Balancer] Xray routing returned to AUTO")
		routing["rules"] = newRules
	}

	newData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return
	}

	if err := os.WriteFile(xrayConfigPath, newData, 0644); err != nil {
		log.Printf("[Balancer] Failed to write xray config: %v", err)
		return
	}

	cmd := exec.Command("systemctl", "restart", "proxy-balancer")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[Balancer] Failed to restart xray: %v %s", err, string(output))
	} else {
		log.Printf("[Balancer] Xray restarted successfully")
	}
}

func (b *Balancer) findOutboundTag(addr string, cfg map[string]interface{}) string {
	outbounds, ok := cfg["outbounds"].([]interface{})
	if !ok {
		return ""
	}
	for _, o := range outbounds {
		ob, ok := o.(map[string]interface{})
		if !ok {
			continue
		}
		tag, _ := ob["tag"].(string)
		if !strings.HasPrefix(tag, "proxy-") {
			continue
		}
		settings, ok := ob["settings"].(map[string]interface{})
		if !ok {
			continue
		}
		vnext, ok := settings["vnext"].([]interface{})
		if !ok {
			continue
		}
		for _, v := range vnext {
			vn, ok := v.(map[string]interface{})
			if !ok {
				continue
			}
			vnAddr, _ := vn["address"].(string)
			vnPort := 0
			switch p := vn["port"].(type) {
			case float64:
				vnPort = int(p)
			case string:
				vnPort, _ = strconv.Atoi(p)
			}
			candidate := fmt.Sprintf("%s:%d", vnAddr, vnPort)
			if candidate == addr {
				return tag
			}
		}
	}
	return ""
}
