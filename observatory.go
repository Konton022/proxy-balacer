package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var observatoryRe = regexp.MustCompile(`app/observatory: the outbound (proxy-\S+) is (alive|dead)`)

type ObservatoryWatcher struct {
	health         *HealthChecker
	tagToAddr      map[string]string
	stopCh         chan struct{}
	onStatusChange func(addr string, up bool)
	mu             sync.RWMutex
}

func NewObservatoryWatcher(health *HealthChecker) *ObservatoryWatcher {
	return &ObservatoryWatcher{
		health:    health,
		tagToAddr: make(map[string]string),
		stopCh:    make(chan struct{}),
	}
}

func (w *ObservatoryWatcher) OnStatusChange(fn func(addr string, up bool)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.onStatusChange = fn
}

func (w *ObservatoryWatcher) loadTagMap() {
	data, err := os.ReadFile(xrayConfigPath)
	if err != nil {
		return
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return
	}

	outbounds, ok := cfg["outbounds"].([]interface{})
	if !ok {
		return
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
		if len(vnext) == 0 {
			continue
		}
		vn, ok := vnext[0].(map[string]interface{})
		if !ok {
			continue
		}
		addr, _ := vn["address"].(string)
		port := 0
		switch p := vn["port"].(type) {
		case float64:
			port = int(p)
		case string:
			port, _ = strconv.Atoi(p)
		}
		if addr != "" && port > 0 {
			w.tagToAddr[tag] = addr + ":" + strconv.Itoa(port)
		}
	}
	log.Printf("[Observatory] Loaded tag map: %v", w.tagToAddr)
}

func (w *ObservatoryWatcher) notifyChange(addr string, alive bool) {
	w.mu.RLock()
	fn := w.onStatusChange
	w.mu.RUnlock()
	if fn != nil {
		go fn(addr, alive)
	}
}

func (w *ObservatoryWatcher) Start() {
	w.loadTagMap()

	w.scanLog()

	w.health.SetObservatoryOK(true)
	log.Printf("[Observatory] Observatory mode active, TCP health checks will not override status")

	go w.startTail()
}

func (w *ObservatoryWatcher) startTail() {
	logFile := "/var/log/xray/error.log"

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var offset int64
	if info, err := os.Stat(logFile); err == nil {
		offset = info.Size()
	}

	for {
		select {
		case <-w.stopCh:
			return
		case <-ticker.C:
			w.readNewLines(logFile, &offset)
		}
	}
}

func (w *ObservatoryWatcher) readNewLines(logFile string, offset *int64) {
	f, err := os.Open(logFile)
	if err != nil {
		return
	}
	defer f.Close()

	f.Seek(*offset, 0)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := observatoryRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		tag := m[1]
		alive := m[2] == "alive"

		addr, ok := w.tagToAddr[tag]
		if !ok {
			continue
		}

		prevUp := w.health.IsUp(addr)
		if prevUp != alive {
			if alive {
				log.Printf("[Observatory] %s (%s) -> UP", tag, addr)
			} else {
				log.Printf("[Observatory] %s (%s) -> DOWN", tag, addr)
			}
			w.health.SetStatus(addr, alive)
			w.notifyChange(addr, alive)
		}
	}
	if pos, err := f.Seek(0, 1); err == nil {
		*offset = pos
	}
}

func (w *ObservatoryWatcher) scanLog() {
	data, err := os.ReadFile("/var/log/xray/error.log")
	if err != nil {
		return
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		m := observatoryRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		tag := m[1]
		alive := m[2] == "alive"
		addr, ok := w.tagToAddr[tag]
		if !ok {
			continue
		}
		w.health.SetStatus(addr, alive)
	}
}
