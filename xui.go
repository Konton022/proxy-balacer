package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type XUIClient struct {
	baseURL  string
	client   *http.Client
	cookies  []*http.Cookie
}

func NewXUIClient(baseURL string) *XUIClient {
	jar, _ := cookiejar.New(nil)
	return &XUIClient{
		baseURL: baseURL,
		client: &http.Client{
			Jar:     jar,
			Timeout: 10 * time.Second,
		},
	}
}

type XUIResponse struct {
	Success bool            `json:"success"`
	Msg     string          `json:"msg"`
	Obj     json.RawMessage `json:"obj"`
}

type XUIInbound struct {
	ID             int             `json:"id"`
	Remark         string          `json:"remark"`
	Port           int             `json:"port"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings json.RawMessage `json:"streamSettings"`
}

func (x *XUIClient) Login(username, password string) error {
	data := url.Values{
		"username": {username},
		"password": {password},
	}

	req, err := http.NewRequest("POST", x.baseURL+"/login", strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := x.client.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result XUIResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("login parse failed: %w", err)
	}

	if !result.Success {
		return fmt.Errorf("login failed: %s", result.Msg)
	}

	x.cookies = resp.Cookies()
	return nil
}

func (x *XUIClient) ListInbounds() ([]XUIInbound, error) {
	req, err := http.NewRequest("GET", x.baseURL+"/panel/api/inbounds/list", nil)
	if err != nil {
		return nil, err
	}
	for _, c := range x.cookies {
		req.AddCookie(c)
	}

	resp, err := x.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list inbounds failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Success bool          `json:"success"`
		Obj     []XUIInbound  `json:"obj"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("list inbounds parse failed: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("list inbounds failed")
	}

	return result.Obj, nil
}

func (x *XUIClient) GetInbound(id int) (*XUIInbound, error) {
	req, err := http.NewRequest("GET", x.baseURL+fmt.Sprintf("/panel/api/inbounds/get/%d", id), nil)
	if err != nil {
		return nil, err
	}
	for _, c := range x.cookies {
		req.AddCookie(c)
	}

	resp, err := x.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get inbound failed: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var result struct {
		Success bool        `json:"success"`
		Obj     XUIInbound  `json:"obj"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("get inbound parse failed: %w", err)
	}

	if !result.Success {
		return nil, fmt.Errorf("get inbound failed")
	}

	return &result.Obj, nil
}
