// Package response là phần "R" trong XDR: nhận lệnh phản ứng (Action) từ manager
// (do SOAR playbook tự động tạo, hoặc analyst bấm trên console) và thực thi trên máy:
//
//	block_ip / unblock_ip          chặn/bỏ chặn IP cả hai chiều (iptables/ip6tables, netsh advfirewall)
//	kill_process                   diệt tiến trình theo pid (đối chiếu tên) hoặc theo tên
//	isolate_host / unisolate_host  cô lập máy khỏi mạng, chỉ giữ kết nối tới manager (IPv4 + IPv6)
//
// AN TOÀN: mọi tham số đều được validate chặt (IP phải parse được, pid là số,
// tên tiến trình theo whitelist ký tự) và chạy qua exec.Command với danh sách
// đối số — KHÔNG qua shell -> không có command injection. Có chế độ dry_run chỉ log.
//
// Trạng thái (IP đang chặn kèm hạn, đang cô lập) lưu ở response.state.json:
//   - chặn có hạn được agent TỰ GỠ đúng hạn, kể cả khi mất kết nối tới manager lúc đó;
//   - đang cô lập thì agent gọi manager bằng IP đã ghim (DNS bị chặn), kể cả sau khi khởi động lại.
package response

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"siem-agent/core"
)

var procNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Tiến trình hệ thống tuyệt đối không được diệt (tránh tự làm sập máy), kể cả theo PID.
var criticalProcs = set("init", "systemd", "systemd-journald", "systemd-logind", "dbus-daemon", "sshd",
	"siem-agent", "siem-agent.exe", "system", "csrss.exe", "lsass.exe", "lsaiso.exe", "wininit.exe",
	"winlogon.exe", "services.exe", "smss.exe", "svchost.exe", "dwm.exe", "msmpeng.exe")

// Tiến trình dùng chung (shell, desktop): kill theo TÊN sẽ giết cả phiên của người khác,
// nên chỉ cho phép kill theo PID cụ thể.
var sharedProcs = set("bash", "sh", "dash", "zsh", "fish", "login", "sudo", "su", "cron", "python", "python3",
	"explorer.exe", "powershell.exe", "pwsh.exe", "cmd.exe", "conhost.exe", "rundll32.exe")

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// Manager là phần của client mà executor cần (tách interface để test).
type Manager interface {
	PollActions(ctx context.Context) ([]core.Action, error)
	ReportAction(ctx context.Context, id string, res core.ActionResult) error
	ServerHost() string
	PinServerIPs(ips []string)
}

type state struct {
	Isolated      bool              `json:"isolated,omitempty"`
	ManagerIPs    []string          `json:"manager_ips,omitempty"`
	FirewallState map[string]string `json:"firewall_state,omitempty"` // Windows: profile -> ON/OFF trước khi cô lập
	Blocks        map[string]string `json:"blocks,omitempty"`         // ip -> hạn gỡ (RFC3339)
}

type Executor struct {
	client       Manager
	dryRun       bool
	pollInterval time.Duration
	statePath    string

	mu sync.Mutex
	st state

	// thay được trong test
	goos     string
	now      func() time.Time
	run      func(cmd []string) ([]byte, error)
	lookPath func(string) (string, error)
	resolve  func(host string) ([]string, error)
	procName func(pid int) (string, error)
	hasIPv6  func() bool
}

func New(client Manager, dryRun bool, pollInterval time.Duration, stateDir string) *Executor {
	e := &Executor{
		client: client, dryRun: dryRun, pollInterval: pollInterval,
		statePath: filepath.Join(stateDir, "response.state.json"),
		goos:      runtime.GOOS, now: time.Now, run: runCmd, lookPath: exec.LookPath,
		resolve:  lookupHost,
		procName: processName,
		hasIPv6:  ipv6Enabled,
	}
	if raw, err := os.ReadFile(e.statePath); err == nil {
		_ = json.Unmarshal(raw, &e.st)
	}
	if e.st.Blocks == nil {
		e.st.Blocks = map[string]string{}
	}
	if e.st.Isolated && client != nil {
		// Máy đang bị cô lập từ trước khi khởi động lại: DNS bị chặn, gọi manager bằng IP đã ghim.
		client.PinServerIPs(e.st.ManagerIPs)
		log.Printf("[response] máy đang ở trạng thái cô lập, kết nối manager qua %v", e.st.ManagerIPs)
	}
	return e
}

func runCmd(cmd []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, cmd[0], cmd[1:]...).CombinedOutput()
}

func lookupHost(host string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, host)
}

func ipv6Enabled() bool {
	_, err := os.Stat("/proc/net/if_inet6")
	return err == nil
}

// Run: poll lệnh từ manager, thực thi, báo kết quả; đồng thời tự gỡ các chặn đã hết hạn.
func (e *Executor) Run(ctx context.Context) {
	log.Printf("[response] bật phản ứng tự động (dry_run=%v, poll=%s)", e.dryRun, e.pollInterval)
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	lastExpiry := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if time.Since(lastExpiry) >= 30*time.Second {
			e.ExpireBlocks()
			lastExpiry = time.Now()
		}
		actions, err := e.client.PollActions(ctx)
		if err != nil {
			log.Printf("[response] không lấy được lệnh: %v", err)
			continue
		}
		for _, a := range actions {
			res := e.Execute(a)
			log.Printf("[response] action %s (%s) -> %s: %s", a.ID, a.Type, res.Status, res.Output)
			if err := e.client.ReportAction(ctx, a.ID, res); err != nil {
				log.Printf("[response] không gửi được kết quả action %s: %v", a.ID, err)
			}
		}
	}
}

// Heartbeat chạy riêng để manager biết agent còn sống.
func Heartbeat(ctx context.Context, hb func(context.Context) error, every time.Duration) {
	for {
		if err := hb(ctx); err != nil {
			log.Printf("[heartbeat] lỗi: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

func (e *Executor) Execute(a core.Action) core.ActionResult {
	switch a.Type {
	case "block_ip", "unblock_ip":
		return e.blockIP(a)
	case "kill_process":
		return e.killProcess(a)
	case "isolate_host":
		return e.isolate()
	case "unisolate_host":
		return e.unisolate()
	}
	return fail("loại action không hỗ trợ: %s", a.Type)
}

func fail(format string, args ...interface{}) core.ActionResult {
	return core.ActionResult{Status: "failed", Output: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// Chặn IP
// ---------------------------------------------------------------------------

func (e *Executor) blockIP(a core.Action) core.ActionResult {
	addr, err := netip.ParseAddr(strings.TrimSpace(fmt.Sprint(a.Params["ip"])))
	if err != nil {
		return fail("IP không hợp lệ: %v", a.Params["ip"])
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsMulticast() {
		return fail("từ chối chặn IP đặc biệt %s", addr)
	}
	block := a.Type == "block_ip"
	if block && e.isManagerIP(addr) {
		return fail("từ chối chặn IP của chính manager %s", addr)
	}
	var until time.Time
	if block {
		until = expiry(a)
		if !until.IsZero() && !until.After(e.now()) {
			return core.ActionResult{Status: "success", Output: "lệnh chặn đã hết hạn trước khi agent nhận được, không thực thi"}
		}
	}
	var steps []step
	if e.goos == "windows" {
		steps = windowsBlock(addr, block)
	} else {
		if addr.Is6() {
			if _, err := e.lookPath("ip6tables"); err != nil && !e.dryRun {
				return fail("không có ip6tables để chặn IPv6 %s", addr)
			}
		}
		steps = linuxBlock(addr, block)
	}
	res := e.runSteps(steps)
	if res.Status != "success" || e.dryRun {
		return res
	}
	e.mu.Lock()
	if block && !until.IsZero() {
		e.st.Blocks[addr.String()] = until.UTC().Format(time.RFC3339)
		res.Output += fmt.Sprintf("\nagent sẽ tự gỡ chặn lúc %s", until.Local().Format("2006-01-02 15:04:05"))
	} else {
		delete(e.st.Blocks, addr.String()) // chặn vĩnh viễn, hoặc đã gỡ
	}
	e.saveLocked()
	e.mu.Unlock()
	return res
}

// expiry: hạn gỡ chặn do manager gửi (expires_at), hoặc created_at + duration.
func expiry(a core.Action) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, a.ExpiresAt); err == nil {
		return t
	}
	secs, _ := strconv.Atoi(strings.TrimSuffix(fmt.Sprint(a.Params["duration"]), ".0"))
	if secs <= 0 {
		return time.Time{}
	}
	start, err := time.Parse(time.RFC3339Nano, a.CreatedAt)
	if err != nil {
		start = time.Now()
	}
	return start.Add(time.Duration(secs) * time.Second)
}

// ExpireBlocks gỡ các chặn đã tới hạn. Manager sau đó gửi unblock_ip cũng không sao (idempotent).
func (e *Executor) ExpireBlocks() {
	e.mu.Lock()
	var due []string
	for ip, until := range e.st.Blocks {
		if t, err := time.Parse(time.RFC3339, until); err == nil && !t.After(e.now()) {
			due = append(due, ip)
		}
	}
	e.mu.Unlock()
	sort.Strings(due)
	for _, ip := range due {
		res := e.blockIP(core.Action{Type: "unblock_ip", Params: map[string]interface{}{"ip": ip}})
		log.Printf("[response] hết hạn chặn %s, agent tự gỡ: %s", ip, res.Status)
	}
}

// ---------------------------------------------------------------------------
// Cô lập máy
// ---------------------------------------------------------------------------

func (e *Executor) isolate() core.ActionResult {
	mgr := e.managerIPs()
	if len(mgr) == 0 {
		return fail("không phân giải được IP manager — hủy cô lập để tránh mất kết nối vĩnh viễn")
	}
	var steps []step
	var fwState map[string]string
	if e.goos == "windows" {
		if !e.dryRun {
			fwState = e.firewallState()
		}
		steps = windowsIsolate(mgr)
	} else {
		withV6 := e.hasIPv6()
		if withV6 {
			if _, err := e.lookPath("ip6tables"); err != nil && !e.dryRun {
				return fail("máy bật IPv6 nhưng không có ip6tables: không cô lập được hoàn toàn, hủy")
			}
		}
		steps = linuxIsolate(mgr, withV6)
	}
	// Ghim IP manager TRƯỚC khi chặn mạng: DNS sẽ bị chặn nhưng agent vẫn gọi được manager.
	ips := make([]string, len(mgr))
	for i, m := range mgr {
		ips[i] = m.String()
	}
	if !e.dryRun {
		e.client.PinServerIPs(ips)
	}
	res := e.runSteps(steps)
	if e.dryRun {
		return res
	}
	e.mu.Lock()
	wasIsolated := e.st.Isolated
	if res.Status == "success" {
		if !wasIsolated { // cô lập lại lần nữa: giữ trạng thái tường lửa GỐC, không lấy trạng thái đang cô lập
			e.st.FirewallState = fwState
		}
		e.st.Isolated, e.st.ManagerIPs = true, ips
	} else if !wasIsolated {
		e.client.PinServerIPs(nil)
	}
	e.saveLocked()
	e.mu.Unlock()
	return res
}

func (e *Executor) unisolate() core.ActionResult {
	var steps []step
	e.mu.Lock()
	prev := e.st.FirewallState
	e.mu.Unlock()
	if e.goos == "windows" {
		steps = windowsUnisolate(prev)
	} else {
		_, err := e.lookPath("ip6tables")
		steps = linuxUnisolate(err == nil)
	}
	res := e.runSteps(steps)
	if res.Status == "success" && !e.dryRun {
		e.mu.Lock()
		e.st.Isolated, e.st.ManagerIPs, e.st.FirewallState = false, nil, nil
		e.saveLocked()
		e.mu.Unlock()
		e.client.PinServerIPs(nil)
	}
	return res
}

// firewallState đọc trạng thái bật/tắt của từng profile Windows Firewall (để trả lại khi bỏ cô lập).
// Không đọc được (vd Windows tiếng khác) thì trả nil: khi bỏ cô lập tường lửa được để BẬT.
func (e *Executor) firewallState() map[string]string {
	out, err := e.run([]string{"netsh", "advfirewall", "show", "allprofiles", "state"})
	if err != nil {
		return nil
	}
	return parseFirewallState(string(out))
}

func parseFirewallState(out string) map[string]string {
	st := map[string]string{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "domain profile"):
			cur = "domain"
		case strings.HasPrefix(lower, "private profile"):
			cur = "private"
		case strings.HasPrefix(lower, "public profile"):
			cur = "public"
		case cur != "" && strings.HasPrefix(lower, "state"):
			if f := strings.Fields(line); len(f) >= 2 {
				st[cur] = strings.ToUpper(f[len(f)-1])
			}
		}
	}
	if len(st) == 0 {
		return nil
	}
	return st
}

func (e *Executor) managerIPs() []netip.Addr {
	host := e.client.ServerHost()
	var raw []string
	if a, err := netip.ParseAddr(host); err == nil {
		raw = []string{a.String()}
	} else if ips, err := e.resolve(host); err == nil {
		raw = ips
	} else {
		e.mu.Lock()
		raw = e.st.ManagerIPs // đang cô lập, DNS bị chặn: dùng IP đã ghim
		e.mu.Unlock()
	}
	var out []netip.Addr
	for _, s := range raw {
		if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func (e *Executor) isManagerIP(ip netip.Addr) bool {
	for _, m := range e.managerIPs() {
		if m == ip {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Diệt tiến trình
// ---------------------------------------------------------------------------

func (e *Executor) killProcess(a core.Action) core.ActionResult {
	want := strings.TrimSpace(fmt.Sprint(a.Params["name"]))
	if a.Params["name"] == nil {
		want = ""
	}
	if raw, ok := a.Params["pid"]; ok && raw != nil && fmt.Sprint(raw) != "" {
		pid, err := strconv.Atoi(strings.TrimSuffix(fmt.Sprint(raw), ".0"))
		if err != nil || pid <= 4 || pid == os.Getpid() {
			return fail("pid không hợp lệ/được bảo vệ: %v", raw)
		}
		name, err := e.procName(pid)
		if err != nil {
			return fail("không tìm thấy tiến trình pid %d (có thể đã kết thúc): %v", pid, err)
		}
		if criticalProcs[strings.ToLower(name)] {
			return fail("từ chối kill tiến trình hệ thống được bảo vệ: %s (pid %d)", name, pid)
		}
		if want != "" && !sameProc(name, want) {
			return fail("pid %d hiện là %q, không phải %q như trong alert (PID đã bị tái sử dụng?) — không kill", pid, name, want)
		}
		if e.dryRun {
			return core.ActionResult{Status: "success", Output: fmt.Sprintf("dry-run: kill pid %d (%s)", pid, name)}
		}
		p, err := os.FindProcess(pid)
		if err == nil {
			err = p.Kill()
		}
		if err != nil {
			return fail("%v", err)
		}
		return core.ActionResult{Status: "success", Output: fmt.Sprintf("đã kill pid %d (%s)", pid, name)}
	}

	if !procNameRe.MatchString(want) {
		return fail("cần params.pid hoặc params.name hợp lệ")
	}
	lower := strings.ToLower(want)
	if criticalProcs[lower] {
		return fail("từ chối kill tiến trình hệ thống được bảo vệ: %s", want)
	}
	if sharedProcs[lower] {
		return fail("%s là tiến trình dùng chung (shell/desktop): kill theo tên sẽ giết cả phiên của người khác, hãy kill theo pid", want)
	}
	if e.goos == "windows" {
		return e.runSteps([]step{{cmd: []string{"taskkill", "/F", "/IM", want}}})
	}
	return e.runSteps([]step{{cmd: []string{"pkill", "-9", "-x", want}}})
}

// sameProc so tên tiến trình, bỏ qua hoa/thường, đường dẫn và đuôi .exe
// (Linux /proc/<pid>/comm cắt tên ở 15 ký tự).
func sameProc(actual, want string) bool {
	norm := func(s string) string {
		s = strings.ToLower(filepath.Base(strings.ReplaceAll(s, `\`, "/")))
		return strings.TrimSuffix(s, ".exe")
	}
	a, w := norm(actual), norm(want)
	if len(a) == 15 && len(w) > 15 {
		w = w[:15]
	}
	return a == w
}

// ---------------------------------------------------------------------------

func (e *Executor) runSteps(steps []step) core.ActionResult {
	var out []string
	for _, s := range steps {
		if e.dryRun {
			out = append(out, "dry-run: "+strings.Join(s.cmd, " "))
			continue
		}
		if s.unless != nil {
			if _, err := e.run(s.unless); err == nil {
				out = append(out, "đã có sẵn: "+strings.Join(s.cmd, " "))
				continue
			}
		}
		b, err := e.run(s.cmd)
		line := strings.TrimSpace(strings.Join(s.cmd, " ") + " => " + strings.TrimSpace(string(b)))
		if err != nil {
			if s.optional {
				out = append(out, line+" (bỏ qua)")
				continue
			}
			out = append(out, line)
			return core.ActionResult{Status: "failed", Output: strings.Join(out, "\n") + "\nlỗi: " + err.Error()}
		}
		out = append(out, line)
	}
	return core.ActionResult{Status: "success", Output: strings.Join(out, "\n")}
}

func (e *Executor) saveLocked() {
	raw, _ := json.MarshalIndent(e.st, "", "  ")
	tmp := e.statePath + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err == nil {
		_ = os.Rename(tmp, e.statePath)
	}
}
