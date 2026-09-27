// Package sender chứa HTTP client nói chuyện với manager API và vòng lặp gửi
// event từ queue lên server.
package sender

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"siem-agent/core"
)

// ErrUnauthorized: token hết hạn/sai -> cần enroll lại.
var ErrUnauthorized = errors.New("unauthorized")

// AgentInfo mô tả agent khi enroll/heartbeat.
type AgentInfo struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Version  string `json:"version"`
}

// Client là HTTP client dùng chung cho sender, heartbeat và response poller.
type Client struct {
	baseURL       string
	enrollmentKey string
	info          AgentInfo
	tokenPath     string
	http          *http.Client

	mu    sync.Mutex
	token string
}

// NewClient tạo client; caFile khác rỗng -> chỉ tin chứng chỉ do CA nội bộ này ký (TLS >= 1.2).
func NewClient(baseURL, enrollmentKey string, info AgentInfo, stateDir string, timeout time.Duration, caFile string) (*Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("không đọc được CA '%s': %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("file CA '%s' không hợp lệ", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	c := &Client{
		baseURL:       strings.TrimRight(baseURL, "/"),
		enrollmentKey: enrollmentKey,
		info:          info,
		tokenPath:     filepath.Join(stateDir, "agent.token"),
		http:          &http.Client{Timeout: timeout, Transport: transport},
	}
	if raw, err := os.ReadFile(c.tokenPath); err == nil {
		c.token = strings.TrimSpace(string(raw))
	}
	return c, nil
}

// Enroll đăng ký agent với manager bằng enrollment key, nhận token riêng cho agent.
func (c *Client) Enroll(ctx context.Context) error {
	var resp struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/agents/enroll", c.info, &resp, map[string]string{
		"X-Enrollment-Key": c.enrollmentKey,
	}, false); err != nil {
		return fmt.Errorf("enroll thất bại: %w", err)
	}
	c.mu.Lock()
	c.token = resp.Token
	c.mu.Unlock()
	_ = os.WriteFile(c.tokenPath, []byte(resp.Token), 0o600)
	return nil
}

// EnsureEnrolled enroll nếu chưa có token.
func (c *Client) EnsureEnrolled(ctx context.Context) error {
	c.mu.Lock()
	has := c.token != ""
	c.mu.Unlock()
	if has {
		return nil
	}
	return c.Enroll(ctx)
}

// Call gọi API có xác thực; tự enroll lại 1 lần nếu bị 401.
func (c *Client) Call(ctx context.Context, method, path string, body, out interface{}) error {
	if err := c.EnsureEnrolled(ctx); err != nil {
		return err
	}
	err := c.do(ctx, method, path, body, out, nil, true)
	if errors.Is(err, ErrUnauthorized) {
		if err := c.Enroll(ctx); err != nil {
			return err
		}
		err = c.do(ctx, method, path, body, out, nil, true)
	}
	return err
}

func (c *Client) SendEvents(ctx context.Context, events []core.Event) error {
	return c.Call(ctx, http.MethodPost, "/api/v1/events", events, nil)
}

func (c *Client) Heartbeat(ctx context.Context) error {
	return c.Call(ctx, http.MethodPost, "/api/v1/agents/heartbeat", c.info, nil)
}

func (c *Client) PollActions(ctx context.Context) ([]core.Action, error) {
	var actions []core.Action
	err := c.Call(ctx, http.MethodGet, "/api/v1/agents/actions", nil, &actions)
	return actions, err
}

func (c *Client) ReportAction(ctx context.Context, id string, res core.ActionResult) error {
	return c.Call(ctx, http.MethodPost, "/api/v1/actions/"+id+"/result", res, nil)
}

// ServerHost trả về hostname của manager (dùng để whitelist khi cô lập máy).
func (c *Client) ServerHost() string {
	u := strings.TrimPrefix(strings.TrimPrefix(c.baseURL, "http://"), "https://")
	if i := strings.IndexAny(u, ":/"); i >= 0 {
		u = u[:i]
	}
	return u
}

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}, headers map[string]string, auth bool) error {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("không serialize được body: %w", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Agent-ID", c.info.AgentID)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if auth {
		c.mu.Lock()
		req.Header.Set("Authorization", "Bearer "+c.token)
		c.mu.Unlock()
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("lỗi HTTP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("server trả về %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
