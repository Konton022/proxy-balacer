package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	configPath := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	db, err := gorm.Open(sqlite.Open(cfg.DBPath), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	if err := AutoMigrate(db); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	seedBackendsFromConfig(db, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	balancer := NewBalancer(db, cfg)
	go balancer.Start(ctx)

	if cfg.ProxyUUID == "" {
		cfg.ProxyUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
		log.Printf("[Config] Using default proxy UUID: %s (set proxy_uuid in config.yaml)", cfg.ProxyUUID)
	} else {
		log.Printf("[Config] Proxy UUID: %s", cfg.ProxyUUID)
	}

	var (
		admin       *AdminServer
		adminServer *http.Server
	)

	if cfg.AdminEnabled {
		admin = NewAdminServer(db, cfg, balancer)
		adminServer = &http.Server{
			Addr:         cfg.AdminAddr(),
			Handler:      http.HandlerFunc(admin.router),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		go func() {
			log.Printf("[Admin] Starting admin panel on %s", cfg.AdminAddr())
			if err := adminServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[Admin] Server error: %v", err)
			}
		}()
	}

	proxy := NewProxy(balancer, admin)
	if admin != nil {
		admin.SetProxy(proxy)
	}

	if cfg.TLSEnabled && cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		if err := proxy.InitTLS(); err != nil {
			log.Printf("[Proxy] TLS init failed: %v (falling back to self-signed)", err)
			certFile := cfg.DBPath + ".crt"
			keyFile := cfg.DBPath + ".key"
			if err := ensureSelfSignedCert(certFile, keyFile); err != nil {
				log.Fatalf("Self-signed cert failed: %v", err)
			}
			cfg.TLSCertFile = certFile
			cfg.TLSKeyFile = keyFile
			proxy.InitTLS()
		} else {
			log.Printf("[Proxy] TLS enabled with cert: %s", cfg.TLSCertFile)
		}
	} else {
		certFile := cfg.DBPath + ".crt"
		keyFile := cfg.DBPath + ".key"
		if err := ensureSelfSignedCert(certFile, keyFile); err != nil {
			log.Fatalf("Self-signed cert failed: %v", err)
		}
		cfg.TLSCertFile = certFile
		cfg.TLSKeyFile = keyFile
		proxy.InitTLS()
		log.Printf("[Proxy] TLS enabled with self-signed cert")
	}
	proxyListener, err := net.Listen("tcp", cfg.Addr())
	if err != nil {
		log.Fatalf("Proxy listen failed: %v", err)
	}

	var proxyWg sync.WaitGroup
	proxyWg.Add(1)
	go func() {
		defer proxyWg.Done()
		log.Printf("[Proxy] Listening on %s", cfg.Addr())
		proxy.Serve(ctx, proxyListener)
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit
	log.Printf("Received signal %v, shutting down gracefully...", sig)

	cancel()

	if adminServer != nil {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := adminServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("[Admin] Shutdown error: %v", err)
		}
	}

	proxyListener.Close()
	proxyWg.Wait()

	log.Println("Shutdown complete")
}

func seedBackendsFromConfig(db *gorm.DB, cfg *Config) {
	var count int64
	db.Model(&Backend{}).Count(&count)
	if count > 0 {
		return
	}

	for _, cb := range cfg.Backends {
		backend := Backend{
			Name:    cb.Name,
			SubURL:  cb.SubURL,
			Primary: cb.Primary,
			Enabled: true,
		}

		if configs, err := FetchSubscriptionURL(cb.SubURL); err == nil && len(configs) > 0 {
			host, port, sni, err := ParseBackendFromSubscription(cb.SubURL, configs)
			if err == nil {
				backend.Host = host
				backend.Port = port
				backend.SNI = sni
			}
			uuid, realitySNI, pbk, sid, spx, fp, flow := extractRealityParams(configs[0])
			backend.UUID = uuid
			backend.RealityPubKey = pbk
			backend.RealityShortID = sid
			backend.RealitySpiderX = spx
			backend.Fingerprint = fp
			backend.Flow = flow
			if realitySNI != "" {
				backend.SNI = realitySNI
			}
			backend.LastFetch = time.Now()
		}

		if err := db.Create(&backend).Error; err != nil {
			log.Printf("[Config] Failed to seed backend %s: %v", cb.Name, err)
		} else {
			log.Printf("[Config] Seeded backend: %s (%s:%d)", cb.Name, backend.Host, backend.Port)

			if configs, err := FetchSubscriptionURL(cb.SubURL); err == nil {
				for _, link := range configs {
					cfg := ParseConfigLinkFull(link, backend.ID)
					db.Create(&cfg)
				}
				log.Printf("[Config] Imported %d configs for %s", len(configs), cb.Name)
			}
		}
	}
}
