package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type ConfigBackend struct {
	Name    string `yaml:"name"`
	SubURL  string `yaml:"sub_url"`
	Primary bool   `yaml:"primary"`
}

type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	ListenPort int    `yaml:"listen_port"`
	PublicHost string `yaml:"public_host"`

	Backends []ConfigBackend `yaml:"backends"`

	HealthCheckInterval time.Duration `yaml:"health_check_interval"`
	HealthCheckTimeout  time.Duration `yaml:"health_check_timeout"`
	Failback            bool          `yaml:"failback"`
	RetryCount          int           `yaml:"retry_count"`
	RetryDelay          time.Duration `yaml:"retry_delay"`

	AdminEnabled  bool   `yaml:"admin_enabled"`
	AdminListen   string `yaml:"admin_listen"`
	AdminPort     int    `yaml:"admin_port"`
	AdminUser     string `yaml:"admin_user"`
	AdminPassword string `yaml:"admin_password"`
	AdminSecret   string `yaml:"admin_secret"`
	DBPath        string `yaml:"db_path"`

	TLSEnabled  bool   `yaml:"tls_enabled"`
	TLSDomain   string `yaml:"tls_domain"`
	TLSEmail    string `yaml:"tls_email"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	TLSCertFile string `yaml:"tls_cert_file"`

	ProxyUUID string `yaml:"proxy_uuid"`

	RawRelay bool `yaml:"raw_relay"`

	TestTarget string `yaml:"test_target"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		ListenAddr:          "0.0.0.0",
		ListenPort:          443,
		HealthCheckInterval: 10 * time.Second,
		HealthCheckTimeout:  3 * time.Second,
		Failback:            true,
		RetryCount:          2,
		RetryDelay:          500 * time.Millisecond,
		AdminEnabled:        true,
		AdminListen:         "0.0.0.0",
		AdminPort:           8080,
		AdminUser:           "admin",
		AdminPassword:       "admin",
		AdminSecret:         "change-me",
		DBPath:              "balancer.db",
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	if cfg.AdminSecret == "change-me-to-random-string" || cfg.AdminSecret == "change-me" {
		secretPath := cfg.DBPath + ".secret"
		if existing, err := os.ReadFile(secretPath); err == nil {
			cfg.AdminSecret = string(existing)
		} else {
			b := make([]byte, 32)
			rand.Read(b)
			cfg.AdminSecret = hex.EncodeToString(b)
			os.WriteFile(secretPath, []byte(cfg.AdminSecret), 0600)
			fmt.Printf("[Config] Generated admin secret: %s\n", secretPath)
		}
	}

	return cfg, nil
}

func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.ListenAddr, c.ListenPort)
}

func (c *Config) AdminAddr() string {
	return fmt.Sprintf("%s:%d", c.AdminListen, c.AdminPort)
}

func (b *ConfigBackend) Addr() string {
	return b.SubURL
}
