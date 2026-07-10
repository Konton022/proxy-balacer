# Proxy Balancer

Go-based TCP proxy load balancer for 3x-ui proxy servers with health checking, failover, and admin panel.

## Project Structure

```
/opt/proxy-balancer/
├── main.go                 # Entry point: config, DB, starts balancer, proxy, admin
├── config.go               # Config struct, LoadConfig(), YAML parsing
├── config.yaml             # Runtime config (backends, admin creds, TLS paths)
├── balancer.go             # Balancer: backend selection, failover/failback logic
├── proxy.go                # TCP proxy: SNI routing, connection handling, retry
├── health.go               # HealthChecker: TCP dial + subscription endpoint checks
├── admin.go                # Admin web panel: auth, CRUD for backends/clients/subs, QR, subscription endpoints
├── models.go               # GORM models: Backend, SubConfig, Client, Subscription, Session
├── subscription.go         # Generate vmess/vless/trojan subscription links
├── subscription_fetch.go   # Fetch + parse subscription URLs from backends
├── xui.go                  # 3x-ui panel API client (XUIClient)
├── tls.go                  # TLS ClientHello SNI extraction
├── metrics.go              # Connection metrics (atomic counters, per-minute stats)
├── templates/              # Go HTML templates (embed via //go:embed)
│   ├── layout.html         # Base layout with sidebar nav
│   ├── dashboard.html      # Dashboard: stats, backend status, metrics
│   ├── backends.html       # Backend management
│   ├── clients.html        # Client management
│   ├── subscriptions.html  # Subscription management + QR modal
│   └── login.html          # Login page
├── static/                 # Static assets (currently empty)
├── go.mod                  # Module: proxy-balancer, Go 1.22.5
├── go.sum
├── Makefile                # build, install, restart, stop, status, logs
├── balancer.db             # SQLite database
├── balancer.db.secret      # Auto-generated admin secret
├── server.crt              # TLS cert (Let's Encrypt)
├── server.key              # TLS key
└── proxy-balancer          # Compiled binary
```

## Dependencies

- Go 1.22.5
- `gorm.io/gorm` v1.25.7 — ORM
- `gorm.io/driver/sqlite` v1.5.6 — SQLite driver
- `gopkg.in/yaml.v3` — YAML config parsing
- `github.com/skip2/go-qrcode` — QR code generation

## Data Models

- **Backend** — proxy server (name, sub_url, host, port, sni, primary, enabled)
- **SubConfig** — individual proxy config from subscription (remark, protocol, host, port, settings, raw_link)
- **Client** — end user (name, email, enabled)
- **Subscription** — client subscription with token, linked to Configs via many2many
- **Session** — admin auth sessions

## Key Logic

- `filterActiveConfigs()` — returns only configs from the currently active backend (not all healthy)
- `Balancer.failover()` — switches to next healthy backend when active goes down
- `Balancer.tryFailback()` — returns to primary backend when it recovers
- `extractSNI()` — parses TLS ClientHello for SNI-based routing
- `ParseConfigLinkFull()` — converts raw subscription link to SubConfig model

## Running

```bash
# Build
go build -o proxy-balancer .

# Run
./proxy-balancer -config config.yaml

# Or via systemd
systemctl restart proxy-balancer
```

## Config (config.yaml)

- `listen_addr` / `listen_port` — proxy listener (default 8443)
- `admin_enabled` / `admin_port` — admin panel (default 8080)
- `tls_enabled` + cert/key paths — TLS termination
- `health_check_interval` / `health_check_timeout` — health check timing
- `failback` — auto-return to primary backend
- `backends[]` — initial backend list (seeded to DB on first run)

## API Endpoints (Admin)

- `GET /` — dashboard
- `GET/POST /backends` — list/add backends
- `POST /backends/:id/refetch` — re-fetch subscription
- `POST /backends/:id/toggle` — enable/disable
- `DELETE /backends/:id` — delete
- `GET/POST /clients` — list/add clients
- `DELETE /clients/:id` — delete
- `GET/POST /subscriptions` — list/add subscriptions
- `DELETE /subscriptions/:id` — delete
- `GET /sub/:token` — subscription endpoint (filtered by active backend)
- `GET /sub/:token/qr` — QR code image

## Architecture

```
                         ┌─────────────────────────┐
                         │      Client Device       │
                         │  (v2ray, sing-box, etc.) │
                         └────────────┬────────────┘
                                      │ TLS (SNI routing)
                                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   proxy-balancer (:8443)                    │
│                                                             │
│  1. Accept TCP connection                                   │
│  2. Peek first bytes:                                       │
│     - "GET "/"POST" → subscription endpoint (/sub/:token)  │
│     - 0x16 (TLS) → extract SNI → route to matching backend │
│  3. Otherwise → route to active backend                     │
│  4. Proxy bidirectional TCP stream                          │
│                                                             │
│  Health checking (TCP dial + subscription fetch):           │
│  - If active backend DOWN → failover to next healthy        │
│  - If primary recovers + failback=true → switch back        │
│                                                             │
│  Admin panel (:8080) — web UI for management                │
└────────────┬────────────────────────────────┬───────────────┘
             │                                │
             ▼                                ▼
┌────────────────────┐              ┌────────────────────┐
│   Backend: Germany │              │    Backend: USA    │
│   3x-ui panel      │              │    3x-ui panel     │
│   :29327           │              │    :53130          │
│   (primary)        │              │    (secondary)     │
└────────────────────┘              └────────────────────┘
```

### Flow

1. **Client** connects to proxy-balancer with a subscription URL (`https://proxy:8443/sub/:token`)
2. **Subscription endpoint** returns proxy configs (vmess/vless/trojan) rewritten to point to the balancer's public host, filtered to only the **active backend**
3. **Client** connects to proxy-balancer using one of the returned configs
4. **Proxy** extracts SNI from TLS ClientHello, routes to matching backend (or active backend)
5. **Health checker** monitors backends via TCP dial; if active goes down → failover; if primary recovers → failback

### TLS Termination

- TLS is **NOT terminated** by the balancer — it passes through to the backend
- The balancer only reads the TLS ClientHello to extract SNI for routing
- Certs on the balancer (`server.crt`/`server.key`) are for the admin panel HTTPS, not for proxy traffic
- Actual TLS termination happens on the 3x-ui backends

## Deployment

### Systemd Service

- Service file: `/etc/systemd/system/proxy-balancer.service`
- Working dir: `/opt/proxy-balancer/`
- Starts with: `proxy-balancer -config /opt/proxy-balancer/config.yaml`
- Enabled on boot

### TLS Certificates (Let's Encrypt)

- Domain: `proxy-balancer.duckdns.org`
- Cert path: `/etc/letsencrypt/live/proxy-balancer.duckdns.org/fullchain.pem`
- Key path: `/etc/letsencrypt/live/proxy-balancer.duckdns.org/privkey.pem`
- Used by admin panel (port 8080) — the proxy port (8443) uses backend TLS passthrough

### Database

- SQLite at `/opt/proxy-balancer/balancer.db`
- Secret file at `/opt/proxy-balancer/balancer.db.secret` (auto-generated admin secret)
- Backends are seeded from `config.yaml` on first run only (if DB is empty)

## Typical Tasks

| Task | Files to modify |
|------|-----------------|
| Add new backend | Admin panel or `config.yaml` + restart |
| Change health check timing | `config.yaml` → `health_check_interval` / `health_check_timeout` |
| Add/edit client subscriptions | Admin panel → Subscriptions page |
| Change admin password | `config.yaml` → `admin_user` / `admin_password` |
| Modify failover behavior | `config.yaml` → `failback` flag; `balancer.go` |
| Change proxy port | `config.yaml` → `listen_port` |
| Update TLS certs | Replace cert/key files, restart |
| Add support for new protocol | `subscription.go` (link generation), `subscription_fetch.go` (parsing) |
| Modify UI | `templates/*.html` (embedded, rebuild required) |
| Debug connection issues | `journalctl -u proxy-balancer -f` |

## Notes

- Templates are embedded via `//go:embed templates/*` — rebuild required after template changes
- DB is SQLite at `balancer.db`
- Auth via session cookie (30 day expiry)
- CSRF protection on all POST requests
- Subscription endpoint returns configs only from the active backend (for failover)
- The `primary` flag is internal only — used for failback logic, NOT visible to clients in subscriptions
