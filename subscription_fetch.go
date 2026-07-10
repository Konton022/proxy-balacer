package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func ParseBackendFromSubscription(subURL string, configs []string) (host string, port int, sni string, err error) {
	for _, link := range configs {
		host, port, sni = extractServerInfo(link)
		if host != "" && port > 0 {
			return host, port, sni, nil
		}
	}
	return "", 0, "", fmt.Errorf("no valid config found in subscription")
}

func extractServerInfo(link string) (host string, port int, sni string) {
	if strings.HasPrefix(link, "vmess://") {
		data := strings.TrimPrefix(link, "vmess://")
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return "", 0, ""
		}
		var v struct {
			Add  string `json:"add"`
			Port string `json:"port"`
			PS   string `json:"ps"`
			Host string `json:"host"`
			TLS  string `json:"tls"`
		}
		if err := json.Unmarshal(decoded, &v); err != nil {
			return "", 0, ""
		}
		port, _ = strconv.Atoi(v.Port)
		sni = v.Host
		if sni == "" && v.TLS == "tls" {
			sni = v.Add
		}
		return v.Add, port, sni
	}

	for _, prefix := range []string{"vless://", "trojan://", "ss://"} {
		if strings.HasPrefix(link, prefix) {
			rest := strings.TrimPrefix(link, prefix)
			if idx := strings.Index(rest, "@"); idx >= 0 {
				hostPort := rest[idx+1:]
				if qIdx := strings.Index(hostPort, "?"); qIdx >= 0 {
					hostPort = hostPort[:qIdx]
				}
				if hIdx := strings.Index(hostPort, ":"); hIdx >= 0 {
					host = hostPort[:hIdx]
					portStr := hostPort[hIdx+1:]
					port, _ = strconv.Atoi(portStr)
				}

				u, _ := url.Parse(link)
				q := u.Query()
				sni = q.Get("host")
				if sni == "" {
					sni = q.Get("sni")
				}
				if sni == "" && q.Get("security") == "tls" {
					sni = host
				}

				return host, port, sni
			}
		}
	}
	return "", 0, ""
}

func ParseConfigLink(link string) (remark, protocol, raw string) {
	raw = link
	if strings.HasPrefix(link, "vmess://") {
		protocol = "vmess"
		data := strings.TrimPrefix(link, "vmess://")
		if d, err := base64.StdEncoding.DecodeString(data); err == nil {
			var v struct {
				PS string `json:"ps"`
			}
			if json.Unmarshal(d, &v) == nil {
				remark = v.PS
			}
		}
	} else if strings.HasPrefix(link, "vless://") {
		protocol = "vless"
		if p := strings.Index(link, "#"); p > 0 {
			remark = link[p+1:]
		}
	} else if strings.HasPrefix(link, "trojan://") {
		protocol = "trojan"
		if p := strings.Index(link, "#"); p > 0 {
			remark = link[p+1:]
		}
	} else if strings.HasPrefix(link, "ss://") {
		protocol = "shadowsocks"
		if p := strings.Index(link, "#"); p > 0 {
			remark = link[p+1:]
		}
	}
	if remark == "" {
		remark = protocol
	}
	return
}

func extractRealityParams(link string) (uuid, sni, pbk, sid, spx, fp, flow string) {
	uuid, _, _ = ParseConfigLink(link)
	host, _, _ := extractServerInfo(link)

	if strings.HasPrefix(link, "vmess://") {
		data := strings.TrimPrefix(link, "vmess://")
		if d, err := base64.StdEncoding.DecodeString(data); err == nil {
			var v map[string]interface{}
			if json.Unmarshal(d, &v) == nil {
				sni, _ = v["host"].(string)
				fp, _ = v["fp"].(string)
				flow, _ = v["flow"].(string)
			}
		}
		return
	}

	u, err := url.Parse(link)
	if err != nil {
		return
	}
	q := u.Query()
	sni = q.Get("sni")
	if sni == "" {
		sni = q.Get("host")
	}
	if sni == "" && q.Get("security") == "reality" {
		sni = host
	}
	pbk = q.Get("pbk")
	sid = q.Get("sid")
	spx = q.Get("spx")
	fp = q.Get("fp")
	flow = q.Get("flow")
	return
}

func ParseConfigLinkFull(link string, backendID uint) SubConfig {
	remark, protocol, raw := ParseConfigLink(link)
	host, port, _ := extractServerInfo(link)

	settings := ""
	streamSettings := ""
	if strings.HasPrefix(link, "vmess://") {
		data := strings.TrimPrefix(link, "vmess://")
		if d, err := base64.StdEncoding.DecodeString(data); err == nil {
			var vmess map[string]interface{}
			if json.Unmarshal(d, &vmess) == nil {
				delete(vmess, "ps")
				delete(vmess, "add")
				delete(vmess, "port")
				if b, err := json.Marshal(vmess); err == nil {
					settings = string(b)
				}
				ss := map[string]interface{}{
					"network": vmess["net"],
					"security": vmess["tls"],
					"type":     vmess["type"],
				}
				if vmess["net"] == "ws" {
					ws := map[string]interface{}{
						"path": vmess["path"],
						"headers": map[string]interface{}{
							"Host": vmess["host"],
						},
					}
					ss["wsSettings"] = ws
				}
				if b, err := json.Marshal(ss); err == nil {
					streamSettings = string(b)
				}
			}
		}
	}

	return SubConfig{
		BackendID:      backendID,
		Remark:         remark,
		Host:           host,
		Port:           port,
		Protocol:       protocol,
		Settings:       settings,
		StreamSettings: streamSettings,
		RawLink:        raw,
	}
}

func FetchSubscriptionURL(rawURL string) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response failed: %w", err)
	}

	content := strings.TrimSpace(string(body))
	if content == "" {
		return nil, fmt.Errorf("empty response")
	}

	var decoded string

	if strings.HasPrefix(content, "vmess://") || strings.HasPrefix(content, "vless://") ||
		strings.HasPrefix(content, "trojan://") || strings.HasPrefix(content, "ss://") {
		decoded = content
	} else {
		d, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			d2, err2 := base64.RawStdEncoding.DecodeString(content)
			if err2 != nil {
				return nil, fmt.Errorf("failed to decode base64: %v", err)
			}
			decoded = string(d2)
		} else {
			decoded = string(d)
		}
	}

	lines := strings.Split(strings.TrimSpace(decoded), "\n")
	var configs []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			configs = append(configs, line)
		}
	}

	return configs, nil
}
