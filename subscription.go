package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type SubSettings struct {
	V    string `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port string `json:"port"`
	ID   string `json:"id"`
	AID  string `json:"aid"`
	SCY  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
}

type SubStreamSettings struct {
	Network  string `json:"network"`
	Security string `json:"security"`
	Type     string `json:"type"`
	WSPath   string `json:"wsPath"`
	WSHost   string `json:"wsHost"`
}

func parseSettings(raw json.RawMessage) (map[string]interface{}, error) {
	var settings map[string]interface{}
	if err := json.Unmarshal(raw, &settings); err != nil {
		return nil, err
	}
	return settings, nil
}

func parseStreamSettings(raw json.RawMessage) (SubStreamSettings, error) {
	var s SubStreamSettings
	if raw == nil || string(raw) == "null" {
		return s, nil
	}

	var rawMap map[string]interface{}
	if err := json.Unmarshal(raw, &rawMap); err != nil {
		return s, err
	}

	if net, ok := rawMap["network"]; ok {
		s.Network = fmt.Sprintf("%v", net)
	}
	if sec, ok := rawMap["security"]; ok {
		s.Security = fmt.Sprintf("%v", sec)
	}
	if t, ok := rawMap["type"]; ok {
		s.Type = fmt.Sprintf("%v", t)
	}

	if ws, ok := rawMap["wsSettings"].(map[string]interface{}); ok {
		if p, ok := ws["path"]; ok {
			s.WSPath = fmt.Sprintf("%v", p)
		}
		if h, ok := ws["headers"].(map[string]interface{}); ok {
			if host, ok := h["Host"]; ok {
				s.WSHost = fmt.Sprintf("%v", host)
			}
		}
	}

	if tcp, ok := rawMap["tcpSettings"].(map[string]interface{}); ok {
		if h, ok := tcp["header"].(map[string]interface{}); ok {
			if t, ok := h["type"]; ok {
				s.Type = fmt.Sprintf("%v", t)
			}
		}
	}

	return s, nil
}

func extractClients(settings map[string]interface{}) []map[string]interface{} {
	clientsRaw, ok := settings["clients"]
	if !ok {
		return nil
	}

	clientsArr, ok := clientsRaw.([]interface{})
	if !ok {
		return nil
	}

	var clients []map[string]interface{}
	for _, c := range clientsArr {
		if clientMap, ok := c.(map[string]interface{}); ok {
			clients = append(clients, clientMap)
		}
	}
	return clients
}

func generateVMessLink(cfg *SubConfig, balancerHost string, balancerPort int, stream SubStreamSettings, note string) string {
	var settings map[string]interface{}
	json.Unmarshal([]byte(cfg.Settings), &settings)
	clients := extractClients(settings)
	if len(clients) == 0 {
		return ""
	}

	client := clients[0]
	id, _ := client["id"].(string)
	aid := "0"
	if a, ok := client["alterId"]; ok {
		aid = fmt.Sprintf("%v", a)
	}

	sub := SubSettings{
		V:    "2",
		PS:   note,
		Add:  balancerHost,
		Port: fmt.Sprintf("%d", balancerPort),
		ID:   id,
		AID:  aid,
		SCY:  "auto",
		Net:  stream.Network,
		Type: stream.Type,
		Host: stream.WSHost,
		Path: stream.WSPath,
		TLS:  stream.Security,
	}

	if sub.Net == "" {
		sub.Net = "tcp"
	}

	data, _ := json.Marshal(sub)
	return "vmess://" + base64.StdEncoding.EncodeToString(data)
}

func generateVLESSSLink(cfg *SubConfig, balancerHost string, balancerPort int, stream SubStreamSettings, note string) string {
	var settings map[string]interface{}
	json.Unmarshal([]byte(cfg.Settings), &settings)
	clients := extractClients(settings)
	if len(clients) == 0 {
		return ""
	}

	client := clients[0]
	id, _ := client["id"].(string)

	u, _ := url.Parse(fmt.Sprintf("vless://%s@%s:%d", id, balancerHost, balancerPort))

	params := url.Values{}
	params.Set("type", stream.Network)
	if stream.Network == "" {
		params.Set("type", "tcp")
	}
	params.Set("security", stream.Security)
	params.Set("encryption", "none")

	if stream.Network == "ws" {
		params.Set("path", stream.WSPath)
		params.Set("host", stream.WSHost)
	}

	u.RawQuery = params.Encode()
	u.Fragment = note

	return u.String()
}

func generateTrojanLink(cfg *SubConfig, balancerHost string, balancerPort int, stream SubStreamSettings, note string) string {
	var settings map[string]interface{}
	json.Unmarshal([]byte(cfg.Settings), &settings)
	clients := extractClients(settings)
	if len(clients) == 0 {
		return ""
	}

	client := clients[0]
	password, _ := client["password"].(string)

	u, _ := url.Parse(fmt.Sprintf("trojan://%s@%s:%d", password, balancerHost, balancerPort))

	params := url.Values{}
	params.Set("security", stream.Security)
	params.Set("type", stream.Network)

	u.RawQuery = params.Encode()
	u.Fragment = note

	return u.String()
}

func rewriteRawLink(rawLink string, newHost string, newPort int) string {
	portStr := fmt.Sprintf("%d", newPort)

	if strings.HasPrefix(rawLink, "vmess://") {
		data := strings.TrimPrefix(rawLink, "vmess://")
		decoded, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return rawLink
		}
		var vmess SubSettings
		if err := json.Unmarshal(decoded, &vmess); err != nil {
			return rawLink
		}
		vmess.Add = newHost
		vmess.Port = portStr
		encoded, _ := json.Marshal(vmess)
		return "vmess://" + base64.StdEncoding.EncodeToString(encoded)
	}

	if strings.HasPrefix(rawLink, "vless://") || strings.HasPrefix(rawLink, "trojan://") || strings.HasPrefix(rawLink, "ss://") {
		re := regexp.MustCompile(`@[^:]+:\d+`)
		result := re.ReplaceAllString(rawLink, "@"+newHost+":"+portStr)

		if strings.Contains(rawLink, "#") {
			before, after := result[:strings.LastIndex(result, "#")], result[strings.LastIndex(result, "#"):]
			return before + after
		}
		return result
	}

	return rawLink
}

func extractHostFromLink(link string) string {
	host, _, _ := extractServerInfo(link)
	return host
}

func GenerateSubscription(configs []SubConfig, balancerHost string, balancerPort int) string {
	var links []string

	seen := make(map[string]bool)

	for _, cfg := range configs {
		if cfg.RawLink != "" {
			link := rewriteRawLink(cfg.RawLink, balancerHost, balancerPort)
			if link != "" && !seen[link] {
				seen[link] = true
				links = append(links, link)
			}
			continue
		}

		note := cfg.Remark
		stream, _ := parseStreamSettings(json.RawMessage(cfg.StreamSettings))
		var link string

		switch cfg.Protocol {
		case "vmess":
			link = generateVMessLink(&cfg, balancerHost, balancerPort, stream, note)
		case "vless":
			link = generateVLESSSLink(&cfg, balancerHost, balancerPort, stream, note)
		case "trojan":
			link = generateTrojanLink(&cfg, balancerHost, balancerPort, stream, note)
		}

		if link != "" && !seen[link] {
			seen[link] = true
			links = append(links, link)
		}
	}

	if len(links) == 0 {
		return ""
	}

	return base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
}


