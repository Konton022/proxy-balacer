# Proxy Balancer

TCP proxy load balancer for 3x-ui servers with health checking, failover, and admin panel.

## Features

- **Load Balancing** — route traffic across multiple 3x-ui backends
- **Health Checking** — TCP dial + subscription endpoint monitoring
- **Failover** — automatic switching when backend goes down
- **Failback** — return to primary when it recovers
- **SNI Routing** — route by TLS Server Name Indication
- **Subscription Management** — generate and manage client subscriptions
- **Admin Panel** — web UI for managing backends, clients, subscriptions
- **QR Codes** — share subscription QR codes with copy/download/share

## Architecture

```
Client → proxy-balancer:8443 → 3x-ui backend (Germany/USA/etc.)
              ↑
         Health checks
         Failover logic
```

The balancer sits in front of your 3x-ui panels. Clients connect to the balancer, which routes to the active backend. When a backend fails, traffic automatically shifts to a healthy one.

**Note:** TLS is not terminated by the balancer — it passes through to the backend. The balancer only reads the TLS ClientHello for SNI routing.

## Install

```bash
# Clone
git clone https://github.com/yourusername/proxy-balancer.git
cd proxy-balancer

# Build
go build -o proxy-balancer .

# Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your backends and settings

# Run
./proxy-balancer -config config.yaml
```

## Systemd Service

```bash
# Copy binary
cp proxy-balancer /usr/local/bin/

# Create service
cat > /etc/systemd/system/proxy-balancer.service << 'EOF'
[Unit]
Description=Proxy Balancer for 3x-ui failover
After=network.target

[Service]
ExecStart=/usr/local/bin/proxy-balancer -config /opt/proxy-balancer/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
systemctl daemon-reload
systemctl enable --now proxy-balancer
```

## Configuration

Copy `config.yaml.example` to `config.yaml` and configure:

```yaml
listen_port: 8443              # Proxy port
public_host: "your-domain.com" # Public hostname for subscriptions

backends:
  - name: "germany"
    sub_url: "https://panel1.com:2096/sub-client-link/TOKEN"
    primary: true
  - name: "usa"
    sub_url: "https://panel2.com:2096/sub-client-link/TOKEN"
    primary: false

admin_port: 8080               # Admin panel port
admin_user: "admin"            # Change this!
admin_password: "your-pass"    # Change this!
```

### TLS

The proxy port (8443) uses **passthrough TLS** — certificates live on your 3x-ui backends, not here.

The admin panel (8080) needs its own TLS cert if exposed publicly. Use Let's Encrypt:

```yaml
tls_enabled: true
tls_cert_file: "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
tls_key_file: "/etc/letsencrypt/live/your-domain.com/privkey.pem"
```

## Usage

1. **Add backends** — via admin panel or config file (first run seeds to DB)
2. **Create clients** — Admin → Clients → Add
3. **Create subscriptions** — Admin → Subscriptions → Create (select client + configs)
4. **Share subscription URL** — give the URL or QR code to the client
5. **Client imports** — paste URL or scan QR in v2ray/sing-box/etc.

## Admin Panel

Open `https://your-domain:8080` in browser.

- **Dashboard** — overview of backends, clients, subscriptions, metrics
- **Backends** — add/remove/toggle/refetch 3x-ui servers
- **Clients** — manage end users
- **Subscriptions** — create subscriptions with selected configs, share QR codes

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard |
| GET/POST | `/backends` | List / add backends |
| POST | `/backends/:id/refetch` | Re-fetch subscription |
| POST | `/backends/:id/toggle` | Enable/disable |
| DELETE | `/backends/:id` | Delete backend |
| GET/POST | `/clients` | List / add clients |
| DELETE | `/clients/:id` | Delete client |
| GET/POST | `/subscriptions` | List / add subscriptions |
| DELETE | `/subscriptions/:id` | Delete subscription |
| GET | `/sub/:token` | Subscription endpoint (returns proxy configs) |
| GET | `/sub/:token/qr` | QR code image |

## Development

```bash
# Build
go build -o proxy-balancer .

# Run
./proxy-balancer -config config.yaml

# View logs
journalctl -u proxy-balancer -f
```

## Dependencies

- Go 1.22.5+
- SQLite (via mattn/go-sqlite3, requires CGO)
- [gorm.io/gorm](https://gorm.io) — ORM
- [github.com/skip2/go-qrcode](https://github.com/skip2/go-qrcode) — QR generation

## License

MIT
