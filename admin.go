package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skip2/go-qrcode"
	"gorm.io/gorm"
)

//go:embed templates/*
var templateFS embed.FS

type AdminServer struct {
	db       *gorm.DB
	config   *Config
	balancer *Balancer
	proxy    *Proxy

	tmpl *template.Template

	csrfMu     sync.Mutex
	csrfTokens map[string]time.Time
}

func NewAdminServer(db *gorm.DB, cfg *Config, b *Balancer) *AdminServer {
	return &AdminServer{
		db:     db,
		config: cfg,
		balancer: b,
		tmpl:   template.Must(template.New("").Funcs(template.FuncMap{
			"add": func(a, b int) int { return a + b },
		}).ParseFS(templateFS, "templates/*.html")),
		csrfTokens: make(map[string]time.Time),
	}
}

func (a *AdminServer) SetProxy(p *Proxy) {
	a.proxy = p
}

func ensureSelfSignedCert(certFile, keyFile string) error {
	if _, err := os.Stat(certFile); err == nil {
		_, err := os.Stat(keyFile)
		if err == nil {
			return nil
		}
	}

	os.MkdirAll(filepath.Dir(certFile), 0755)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "Proxy Balancer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		DNSNames:     []string{"localhost", "proxy-balancer"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create cert: %v", err)
	}

	certOut, _ := os.Create(certFile)
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyOut, _ := os.Create(keyFile)
	defer keyOut.Close()
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	log.Printf("[Admin] Generated self-signed cert: %s, %s", certFile, keyFile)
	return nil
}

func (a *AdminServer) generateCSRF() string {
	token := make([]byte, 32)
	rand.Read(token)
	tokenStr := hex.EncodeToString(token)

	a.csrfMu.Lock()
	a.csrfTokens[tokenStr] = time.Now().Add(30 * time.Minute)
	a.csrfMu.Unlock()

	return tokenStr
}

func (a *AdminServer) validateCSRF(r *http.Request) bool {
	token := r.FormValue("csrf_token")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
		return false
	}

	a.csrfMu.Lock()
	defer a.csrfMu.Unlock()

	expires, ok := a.csrfTokens[token]
	if !ok {
		return false
	}
	delete(a.csrfTokens, token)
	return time.Now().Before(expires)
}

func (a *AdminServer) cleanupCSRF() {
	a.csrfMu.Lock()
	defer a.csrfMu.Unlock()
	now := time.Now()
	for token, expires := range a.csrfTokens {
		if now.After(expires) {
			delete(a.csrfTokens, token)
		}
	}
}

func (a *AdminServer) router(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	method := r.Method

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if path == "/login" && method == "GET" {
		a.handleLoginPage(w, r)
		return
	}
	if path == "/login" && method == "POST" {
		a.handleLogin(w, r)
		return
	}
	if path == "/logout" && method == "GET" {
		a.handleLogout(w, r)
		return
	}

	if strings.HasPrefix(path, "/sub/") && strings.HasSuffix(path, "/qr") && method == "GET" {
		a.subscriptionQR(w, r)
		return
	}
	if strings.HasPrefix(path, "/sub/") && method == "GET" {
		a.subscriptionEndpoint(w, r)
		return
	}

	if !a.isAuthenticated(r) {
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/login")
			http.Error(w, "", 401)
			return
		}
		http.Redirect(w, r, "/login", 302)
		return
	}

	if method == "POST" && !a.validateCSRF(r) {
		http.Error(w, "Invalid CSRF token", 403)
		return
	}

	a.cleanupCSRF()

	switch {
	case path == "/" && method == "GET":
		a.dashboard(w, r)
	case path == "/backends" && method == "GET":
		a.backendsPage(w, r)
	case path == "/backends" && method == "POST":
		a.addBackend(w, r)
	case strings.HasPrefix(path, "/backends/") && strings.HasSuffix(path, "/refetch") && method == "POST":
		a.refetchBackend(w, r, path)
	case strings.HasPrefix(path, "/backends/") && strings.HasSuffix(path, "/toggle") && method == "POST":
		a.toggleBackend(w, r, path)
	case strings.HasPrefix(path, "/backends/") && method == "DELETE":
		a.deleteBackend(w, r, path)
	case path == "/active-server" && method == "POST":
		a.setActiveServer(w, r)
	case path == "/clients" && method == "GET":
		a.clientsPage(w, r)
	case path == "/clients" && method == "POST":
		a.addClient(w, r)
	case strings.HasPrefix(path, "/clients/") && method == "DELETE":
		a.deleteClient(w, r, path)
	case path == "/subscriptions" && method == "GET":
		a.subscriptionsPage(w, r)
	case path == "/subscriptions" && method == "POST":
		a.addSubscription(w, r)
	case strings.HasPrefix(path, "/subscriptions/") && method == "DELETE":
		a.deleteSubscription(w, r, path)
	default:
		http.NotFound(w, r)
	}
}

type ginH map[string]interface{}

func (a *AdminServer) render(w http.ResponseWriter, data ginH, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := a.tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		log.Printf("[Admin] Template error: %v", err)
	}
}

func (a *AdminServer) renderContent(w http.ResponseWriter, contentTmpl string, data ginH, status int) {
	data["csrf_token"] = a.generateCSRF()
	var buf strings.Builder
	if err := a.tmpl.ExecuteTemplate(&buf, contentTmpl, data); err != nil {
		log.Printf("[Admin] Content template error: %v", err)
		http.Error(w, "Template error", 500)
		return
	}
	data["Content"] = template.HTML(buf.String())
	a.render(w, data, status)
}

func (a *AdminServer) createSession() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)
	a.db.Create(&Session{Token: token, ExpiresAt: time.Now().Add(30 * 24 * time.Hour)})
	return token
}

func (a *AdminServer) deleteSession(token string) {
	a.db.Where("token = ?", token).Delete(&Session{})
}

func (a *AdminServer) getSessionToken(r *http.Request) string {
	c, err := r.Cookie("session")
	if err != nil {
		return ""
	}
	return c.Value
}

func (a *AdminServer) isAuthenticated(r *http.Request) bool {
	token := a.getSessionToken(r)
	if token == "" {
		return false
	}
	var s Session
	if err := a.db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&s).Error; err != nil {
		return false
	}
	return true
}

func (a *AdminServer) cleanupSessions() {
	a.db.Where("expires_at <= ?", time.Now()).Delete(&Session{})
}

func extractID(path, prefix string) string {
	p := strings.TrimPrefix(path, prefix)
	p = strings.TrimSuffix(p, "/refetch")
	p = strings.TrimSuffix(p, "/toggle")
	return strings.TrimSuffix(p, "/")
}

func (a *AdminServer) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if a.isAuthenticated(r) {
		http.Redirect(w, r, "/", 302)
		return
	}
	a.renderContent(w, "login_content", ginH{"hide_sidebar": true}, 200)
}

func (a *AdminServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == a.config.AdminUser && password == a.config.AdminPassword {
		token := a.createSession()
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Path:     "/",
			MaxAge:   86400 * 30,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", 302)
		return
	}
	a.renderContent(w, "login_content", ginH{"hide_sidebar": true, "error": "Invalid credentials"}, 200)
}

func (a *AdminServer) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := a.getSessionToken(r)
	a.deleteSession(token)
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", 302)
}

func (a *AdminServer) dashboard(w http.ResponseWriter, r *http.Request) {
	var backendCount, clientCount, subCount, configCount int64
	a.db.Model(&Backend{}).Count(&backendCount)
	a.db.Model(&Client{}).Count(&clientCount)
	a.db.Model(&Subscription{}).Count(&subCount)
	a.db.Model(&SubConfig{}).Count(&configCount)

	type BackendStatus struct {
		Name    string
		Addr    string
		Primary bool
		Up      bool
		Ping    int64
		Configs int
	}
	var backends []BackendStatus
	var dbBackends []Backend
	a.db.Order("`primary` DESC, id ASC").Find(&dbBackends)
	for _, be := range dbBackends {
		var cfgCount int64
		a.db.Model(&SubConfig{}).Where("backend_id = ?", be.ID).Count(&cfgCount)
		backends = append(backends, BackendStatus{
			Name:    be.Name,
			Addr:    be.Addr(),
			Primary: be.Primary,
			Up:      a.balancer.IsUp(be.Addr()),
			Ping:    a.balancer.GetPing(be.Addr()),
			Configs: int(cfgCount),
		})
	}

	activeServer := ""
	isManual := false
	if a.balancer != nil {
		activeServer = a.balancer.GetActive()
		isManual = a.balancer.IsManual()
	}

	var metrics map[string]interface{}
	if a.proxy != nil {
		metrics = a.proxy.Metrics().Snapshot()
	}

	var clients []Client
	a.db.Order("id desc").Find(&clients)

	type SubWithInfo struct {
		Subscription
		ClientName  string
		ConfigCount int
	}
	var subs []SubWithInfo
	var dbSubs []Subscription
	a.db.Preload("Client").Order("id desc").Find(&dbSubs)
	for _, s := range dbSubs {
		var count int64
		a.db.Model(&SubConfig{}).Joins("JOIN subscription_configs ON subscription_configs.sub_config_id = sub_configs.id").Where("subscription_configs.subscription_id = ?", s.ID).Count(&count)
		subs = append(subs, SubWithInfo{
			Subscription: s,
			ClientName:   s.Client.Name,
			ConfigCount:  int(count),
		})
	}

	a.renderContent(w, "dashboard_content", ginH{
		"active":        "dashboard",
		"backend_count": backendCount,
		"client_count":  clientCount,
		"sub_count":     subCount,
		"config_count":  configCount,
		"active_server": activeServer,
		"is_manual":     isManual,
		"metrics":       metrics,
		"backends":      backends,
		"clients":       clients,
		"subscriptions": subs,
	}, 200)
}

func (a *AdminServer) backendsPage(w http.ResponseWriter, r *http.Request) {
	var backends []Backend
	a.db.Order("`primary` DESC, id ASC").Find(&backends)

	type BackendWithCount struct {
		Backend
		ConfigCount int
	}
	var backendData []BackendWithCount
	for _, be := range backends {
		var count int64
		a.db.Model(&SubConfig{}).Where("backend_id = ?", be.ID).Count(&count)
		backendData = append(backendData, BackendWithCount{be, int(count)})
	}

	activeServer := ""
	if a.balancer != nil {
		activeServer = a.balancer.GetActive()
	}

	a.renderContent(w, "backends_content", ginH{
		"active":        "backends",
		"backends":      backendData,
		"active_server": activeServer,
	}, 200)
}

func (a *AdminServer) addBackend(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	subURL := r.FormValue("sub_url")
	if name == "" || subURL == "" {
		http.Error(w, "Name and Subscription URL required", 400)
		return
	}

	configs, err := FetchSubscriptionURL(subURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch subscription: %v", err), 400)
		return
	}
	if len(configs) == 0 {
		http.Error(w, "No configs found in subscription", 400)
		return
	}

	host, port, sni, err := ParseBackendFromSubscription(subURL, configs)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to parse server info from subscription: %v", err), 400)
		return
	}

	uuid, realitySNI, pbk, sid, spx, fp, flow := extractRealityParams(configs[0])

	backend := Backend{
		Name:            name,
		SubURL:          subURL,
		Host:            host,
		Port:            port,
		SNI:             sni,
		Primary:         r.FormValue("primary") == "on",
		Enabled:         true,
		LastFetch:       time.Now(),
		UUID:            uuid,
		RealityPubKey:   pbk,
		RealityShortID:  sid,
		RealitySpiderX:  spx,
		Fingerprint:     fp,
		Flow:            flow,
	}
	if realitySNI != "" {
		backend.SNI = realitySNI
	}

	if err := a.db.Create(&backend).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed to save: %v", err), 400)
		return
	}

	imported := 0
	for _, link := range configs {
		cfg := ParseConfigLinkFull(link, backend.ID)
		if err := a.db.Create(&cfg).Error; err == nil {
			imported++
		}
	}

	a.balancer.Reload()
	log.Printf("[Admin] Added backend %s (%s:%d) with %d configs", backend.Name, backend.Host, backend.Port, imported)
	http.Redirect(w, r, "/backends", 302)
}

func (a *AdminServer) refetchBackend(w http.ResponseWriter, r *http.Request, path string) {
	id := extractID(path, "/backends/")

	var backend Backend
	if err := a.db.First(&backend, id).Error; err != nil {
		http.Error(w, "Backend not found", 404)
		return
	}

	configs, err := FetchSubscriptionURL(backend.SubURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch: %v", err), 400)
		return
	}

	host, port, sni, err := ParseBackendFromSubscription(backend.SubURL, configs)
	if err == nil {
		uuid, realitySNI, pbk, sid, spx, fp, flow := extractRealityParams(configs[0])
		updates := map[string]interface{}{
			"host":       host,
			"port":       port,
			"last_fetch": time.Now(),
			"uuid":       uuid,
			"reality_pub_key":  pbk,
			"reality_short_id": sid,
			"reality_spider_x": spx,
			"fingerprint":      fp,
			"flow":             flow,
		}
		if realitySNI != "" {
			updates["sni"] = realitySNI
		} else {
			updates["sni"] = sni
		}
		a.db.Model(&backend).Updates(updates)
	} else {
		a.db.Model(&backend).Update("last_fetch", time.Now())
	}

	a.db.Where("backend_id = ?", backend.ID).Delete(&SubConfig{})
	imported := 0
	for _, link := range configs {
		cfg := ParseConfigLinkFull(link, backend.ID)
		if err := a.db.Create(&cfg).Error; err == nil {
			imported++
		}
	}

	a.balancer.Reload()
	log.Printf("[Admin] Refetched %s: %d configs", backend.Name, imported)
	http.Redirect(w, r, "/backends", 302)
}

func (a *AdminServer) toggleBackend(w http.ResponseWriter, r *http.Request, path string) {
	id := extractID(path, "/backends/")
	var backend Backend
	if err := a.db.First(&backend, id).Error; err != nil {
		http.Error(w, "Not found", 404)
		return
	}
	a.db.Model(&backend).Update("enabled", !backend.Enabled)
	a.balancer.Reload()
	log.Printf("[Admin] Toggled backend %s: enabled=%v", backend.Name, !backend.Enabled)
	w.WriteHeader(200)
}

func (a *AdminServer) deleteBackend(w http.ResponseWriter, r *http.Request, path string) {
	id := extractID(path, "/backends/")
	a.db.Where("backend_id = ?", id).Delete(&SubConfig{})
	a.db.Delete(&Backend{}, id)
	a.balancer.Reload()
	w.WriteHeader(200)
}

func (a *AdminServer) setActiveServer(w http.ResponseWriter, r *http.Request) {
	addr := r.FormValue("addr")
	a.balancer.SetManual(addr)
	http.Redirect(w, r, "/", 302)
}

func (a *AdminServer) clientsPage(w http.ResponseWriter, r *http.Request) {
	var clients []Client
	a.db.Order("id desc").Find(&clients)
	a.renderContent(w, "clients_content", ginH{"active": "clients", "clients": clients}, 200)
}

func (a *AdminServer) addClient(w http.ResponseWriter, r *http.Request) {
	client := Client{
		Name:  r.FormValue("name"),
		Email: r.FormValue("email"),
	}
	if err := a.db.Create(&client).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed: %v", err), 400)
		return
	}
	log.Printf("[Admin] Added client: %s", client.Name)
	http.Redirect(w, r, "/clients", 302)
}

func (a *AdminServer) deleteClient(w http.ResponseWriter, r *http.Request, path string) {
	id := extractID(path, "/clients/")
	a.db.Where("client_id = ?", id).Delete(&Subscription{})
	a.db.Delete(&Client{}, id)
	w.WriteHeader(200)
}

func (a *AdminServer) subscriptionsPage(w http.ResponseWriter, r *http.Request) {
	var subs []Subscription
	a.db.Preload("Client").Preload("Configs").Order("id desc").Find(&subs)

	var clients []Client
	a.db.Order("name asc").Find(&clients)

	var configs []SubConfig
	a.db.Order("remark asc").Find(&configs)

	proxyAddr := fmt.Sprintf("%s:%d", a.config.ListenAddr, a.config.ListenPort)
	if a.config.PublicHost != "" {
		proxyAddr = fmt.Sprintf("%s:%d", a.config.PublicHost, a.config.ListenPort)
	} else {
		host := r.Host
		if idx := strings.Index(host, ":"); idx > 0 {
			host = host[:idx]
		} else if host == "" {
			host = "localhost"
		}
		proxyAddr = fmt.Sprintf("%s:%d", host, a.config.ListenPort)
	}

	a.renderContent(w, "subscriptions_content", ginH{
		"active":        "subscriptions",
		"subscriptions": subs,
		"clients":       clients,
		"configs":       configs,
		"balancer_addr": proxyAddr,
	}, 200)
}

func (a *AdminServer) addSubscription(w http.ResponseWriter, r *http.Request) {
	clientID, _ := strconv.ParseUint(r.FormValue("client_id"), 10, 64)
	name := r.FormValue("name")

	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	sub := Subscription{
		ClientID: uint(clientID),
		Name:     name,
		Token:    token,
		Enabled:  true,
	}

	if err := a.db.Create(&sub).Error; err != nil {
		http.Error(w, fmt.Sprintf("Failed: %v", err), 400)
		return
	}

	r.ParseForm()
	for _, idStr := range r.Form["config_ids"] {
		id, err := strconv.ParseUint(idStr, 10, 64)
		if err != nil {
			continue
		}
		a.db.Exec("INSERT INTO subscription_configs (subscription_id, sub_config_id) VALUES (?, ?)", sub.ID, id)
	}

	log.Printf("[Admin] Created subscription: %s", name)
	http.Redirect(w, r, "/subscriptions", 302)
}

func (a *AdminServer) deleteSubscription(w http.ResponseWriter, r *http.Request, path string) {
	id := extractID(path, "/subscriptions/")
	a.db.Exec("DELETE FROM subscription_configs WHERE subscription_id = ?", id)
	a.db.Delete(&Subscription{}, id)
	w.WriteHeader(200)
}

func (a *AdminServer) filterActiveConfigs(configs []SubConfig) []SubConfig {
	activeAddr := a.balancer.GetActive()
	if activeAddr == "" {
		return configs
	}

	var activeBackend Backend
	if err := a.db.Where("enabled = ? AND host || ':' || port = ?", true, activeAddr).First(&activeBackend).Error; err != nil {
		return configs
	}

	var filtered []SubConfig
	for _, cfg := range configs {
		if cfg.BackendID == activeBackend.ID {
			filtered = append(filtered, cfg)
		}
	}
	if len(filtered) == 0 {
		return configs
	}
	return filtered
}

func (a *AdminServer) subscriptionEndpoint(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	token = strings.TrimSuffix(token, ".txt")

	var sub Subscription
	if err := a.db.Where("token = ? AND enabled = ?", token, true).First(&sub).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	balancerHost := a.config.PublicHost
	if balancerHost == "" {
		balancerHost = a.config.ListenAddr
		if balancerHost == "0.0.0.0" {
			balancerHost = r.Host
			if idx := strings.Index(balancerHost, ":"); idx > 0 {
				balancerHost = balancerHost[:idx]
			}
		}
	}

	proxyUUID := a.config.ProxyUUID
	if proxyUUID == "" {
		proxyUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	}

	link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=tcp&flow=xtls-rprx-vision#Balancer",
		proxyUUID, balancerHost, a.config.ListenPort, balancerHost)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", 0, 0, 0, 0))
	io.WriteString(w, link)
}

func (a *AdminServer) ServeSubscriptionHTTP(conn net.Conn, req *http.Request) {
	defer conn.Close()

	token := strings.TrimPrefix(req.URL.Path, "/sub/")
	token = strings.TrimSuffix(token, ".txt")

	var sub Subscription
	if err := a.db.Where("token = ? AND enabled = ?", token, true).First(&sub).Error; err != nil {
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	balancerHost := a.config.PublicHost
	if balancerHost == "" {
		balancerHost = req.Host
		if idx := strings.Index(balancerHost, ":"); idx > 0 {
			balancerHost = balancerHost[:idx]
		}
	}

	proxyUUID := a.config.ProxyUUID
	if proxyUUID == "" {
		proxyUUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	}

	link := fmt.Sprintf("vless://%s@%s:%d?encryption=none&security=tls&sni=%s&type=tcp&flow=xtls-rprx-vision#Balancer",
		proxyUUID, balancerHost, a.config.ListenPort, balancerHost)

	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store, must-revalidate\r\nContent-Length: %d\r\nSubscription-Userinfo: upload=0; download=0; total=0; expire=0\r\n\r\n%s", len(link), link)
	conn.Write([]byte(resp))
}

func (a *AdminServer) subscriptionQR(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/sub/")
	token = strings.TrimSuffix(token, "/qr")
	token = strings.TrimSuffix(token, ".png")

	var sub Subscription
	if err := a.db.Where("token = ? AND enabled = ?", token, true).First(&sub).Error; err != nil {
		http.NotFound(w, r)
		return
	}

	subURL := fmt.Sprintf("http://%s/sub/%s", r.Host, token)
	if a.config.PublicHost != "" {
		subURL = fmt.Sprintf("https://%s/sub/%s", a.config.PublicHost, token)
	}

	qr, err := qrcode.New(subURL, qrcode.Medium)
	if err != nil {
		http.Error(w, "Failed to generate QR", 500)
		return
	}

	png, err := qr.PNG(256)
	if err != nil {
		http.Error(w, "Failed to encode QR", 500)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}
