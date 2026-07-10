package main

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

type Backend struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Name      string `json:"name"`
	SubURL    string `json:"sub_url"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	SNI       string `json:"sni"`
	Primary   bool   `json:"primary"`
	Enabled   bool   `gorm:"default:true" json:"enabled"`
	LastFetch time.Time `json:"last_fetch"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (b *Backend) Addr() string {
	return fmt.Sprintf("%s:%d", b.Host, b.Port)
}

type SubConfig struct {
	ID             uint   `gorm:"primaryKey" json:"id"`
	BackendID      uint   `json:"backend_id"`
	Remark         string `json:"remark"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	Settings       string `gorm:"type:text" json:"settings"`
	StreamSettings string `gorm:"type:text" json:"stream_settings"`
	RawLink        string `gorm:"type:text" json:"raw_link"`
	CreatedAt      time.Time
	UpdatedAt      time.Time

	Backend Backend `gorm:"foreignKey:BackendID" json:"backend,omitempty"`
}

type Client struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Enabled   bool   `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Subscription struct {
	ID        uint   `gorm:"primaryKey" json:"id"`
	ClientID  uint   `json:"client_id"`
	Name      string `json:"name"`
	Token     string `gorm:"uniqueIndex;size:64" json:"token"`
	Enabled   bool   `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time
	UpdatedAt time.Time

	Client  Client     `gorm:"foreignKey:ClientID" json:"client,omitempty"`
	Configs []SubConfig `gorm:"many2many:subscription_configs;" json:"configs,omitempty"`
}

type Session struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Token     string    `gorm:"uniqueIndex;size:64" json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&Backend{}, &SubConfig{}, &Client{}, &Subscription{}, &Session{})
}
