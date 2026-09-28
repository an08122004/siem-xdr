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
	"net"
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

// ErrEnrollConflict: manager từ chối cấp token vì agent_id đã được enroll mà agent không chứng minh
// được danh tính (mất token, trùng agent_id với máy khác, hoặc bị thu hồi). Cần analyst bấm
// "Cho enroll lại" trên console.
var ErrEnrollConflict = errors.New("agent_id đã được enroll trên manager; cần analyst cho phép enroll lại")

// enrollCooldown: sau khi bị từ chối, không thử enroll lại ngay (tránh dội request và audit event).
const enrollCooldown = time.Minute

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

	dialer        *net.Dialer
	mu            sync.Mutex
	token         string
	enrollBlocked time.Time // tới thời điểm này không thử enroll lại
	pins          []string  // IP manager đã ghim (máy đang bị cô lập, DNS bị chặn)
}

// NewClient tạo client; caFile khác rỗng -> chỉ tin chứng chỉ do CA nội bộ này ký (TLS >= 1.2).
func NewClient(baseURL, enrollmentKey string, info AgentInfo, stateDir string, timeout time.Duration, caFile string) (*Client, error) {
	c := &Client{dialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = c.dial
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
	c.baseURL = strings.TrimRight(baseURL, "/")
	c.enrollmentKey = enrollmentKey
	c.info = info
	c.tokenPath = filepath.Join(stateDir, "agent.token")
	c.http = &http.Client{Timeout: timeout, Transport: transport}
	if raw, err := os.ReadFile(c.tokenPath); err == nil {
		c.token = strings.TrimSpace(string(raw))
	}
	return c, nil
}

// PinServerIPs: khi máy bị cô lập, DNS bị chặn -> kết nối thẳng tới các IP manager này.
// TLS vẫn xác thực chứng chỉ theo tên host trong URL (chỉ đổi địa chỉ quay số). ips rỗng = bỏ ghim.
func (c *Client) PinServerIPs(ips []string) {
	c.mu.Lock()
	c.pins = append([]string(nil), ips...)
	c.mu.Unlock()
	c.http.CloseIdleConnections()
}

func (c *Client) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c.mu.Lock()
	pins := c.pins
	c.mu.Unlock()
	host, port, err := net.SplitHostPort(addr)
	if err != nil || len(pins) == 0 || !strings.EqualFold(host, c.ServerHost()) {
		return c.dialer.DialContext(ctx, network, addr)
	}
	var lastErr error
	for _, ip := range pins {
		conn, err := c.dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// Enroll đăng ký agent với manager bằng enrollment key, nhận token ngẫu nhiên riêng cho agent.
//
// Nếu đã có token (kể cả token kiểu cũ), agent gửi kèm để chứng minh danh tính: manager chỉ cấp
// token cho agent_id đã tồn tại khi người gọi trình được token hiện tại của agent đó.
func (c *Client) Enroll(ctx context.Context) error {
	c.mu.Lock()
	current, blocked := c.token, c.enrollBlocked
	c.mu.Unlock()
	if time.Now().Before(blocked) {
		return ErrEnrollConflict
	}
	headers := map[string]string{"X-Enrollment-Key": c.enrollmentKey}
	if current != "" {
		headers["Authorization"] = "Bearer " + current
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/agents/enroll", c.info, &resp, headers, false); err != nil {
		var se *statusError
		if errors.As(err, &se) && se.code == http.StatusConflict {
			c.mu.Lock()
			c.enrollBlocked = time.Now().Add(enrollCooldown)
			c.mu.Unlock()
			return ErrEnrollConflict
		}
		return fmt.Errorf("enroll thất bại: %w", err)
	}
	if resp.Token == "" {
		return errors.New("enroll thất bại: manager không trả token")
	}
	// Ghi token trước khi dùng: mất file token giữa chừng thì agent bị khóa ngoài, phải nhờ analyst.
	if err := writeFileAtomic(c.tokenPath, []byte(resp.Token), 0o600); err != nil {
		return fmt.Errorf("không lưu được token: %w", err)
	}
	c.mu.Lock()
	c.token = resp.Token
	c.mu.Unlock()
	return nil
}

// writeFileAtomic ghi file tạm rồi rename: crash giữa chừng không để lại file hỏng.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
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

type statusError struct {
	code int
	msg  string
}

func (e *statusError) Error() string { return fmt.Sprintf("server trả về %d: %s", e.code, e.msg) }

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
		return &statusError{code: resp.StatusCode, msg: strings.TrimSpace(string(msg))}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
