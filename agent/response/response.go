// Package response là phần "R" trong XDR: nhận lệnh phản ứng (Action) từ manager
// (do SOAR playbook tự động tạo, hoặc analyst bấm trên console) và thực thi trên máy:
//
//	block_ip / unblock_ip        chặn/bỏ chặn IP (iptables trên Linux, netsh advfirewall trên Windows)
//	kill_process                 diệt tiến trình theo pid hoặc tên
//	isolate_host / unisolate_host  cô lập máy khỏi mạng, chỉ giữ kết nối tới manager
//
// AN TOÀN: mọi tham số đều được validate chặt (IP phải parse được, pid là số,
// tên tiến trình theo whitelist ký tự) và chạy qua exec.Command với danh sách
// đối số — KHÔNG qua shell -> không có command injection. Có chế độ dry_run chỉ log.
package response

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"siem-agent/core"
	"siem-agent/sender"
)

const ruleTag = "siem-xdr"

var (
	procNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	// Tiến trình hệ thống tuyệt đối không được diệt (tránh tự làm sập máy).
	protectedProcs = map[string]bool{
		"init": true, "systemd": true, "sshd": true, "siem-agent": true, "siem-agent.exe": true,
		"csrss.exe": true, "lsass.exe": true, "wininit.exe": true, "winlogon.exe": true,
		"services.exe": true, "smss.exe": true, "system": true, "svchost.exe": true,
	}
)

type Executor struct {
	client       *sender.Client
	dryRun       bool
	pollInterval time.Duration
}

func New(client *sender.Client, dryRun bool, pollInterval time.Duration) *Executor {
	return &Executor{client: client, dryRun: dryRun, pollInterval: pollInterval}
}

// Run: poll lệnh từ manager, thực thi, báo kết quả. Đồng thời gửi heartbeat.
func (e *Executor) Run(ctx context.Context) {
	log.Printf("[response] bật phản ứng tự động (dry_run=%v, poll=%s)", e.dryRun, e.pollInterval)
	ticker := time.NewTicker(e.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
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
func Heartbeat(ctx context.Context, client *sender.Client, every time.Duration) {
	for {
		if err := client.Heartbeat(ctx); err != nil {
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
	var cmds [][]string
	var err error
	switch a.Type {
	case "block_ip", "unblock_ip":
		cmds, err = e.ipCommands(a)
		if err == nil && !e.dryRun {
			// Idempotent: chặn khi đã có luật / gỡ khi luật không còn (vd: máy reboot) đều coi là thành công.
			exists := e.ipRuleExists(a)
			if a.Type == "block_ip" && exists {
				return core.ActionResult{Status: "success", Output: "luật chặn đã tồn tại"}
			}
			if a.Type == "unblock_ip" && !exists {
				return core.ActionResult{Status: "success", Output: "không có luật chặn nào cần gỡ"}
			}
		}
	case "kill_process":
		return e.killProcess(a)
	case "isolate_host":
		cmds, err = e.isolateCommands(true)
	case "unisolate_host":
		cmds, err = e.isolateCommands(false)
	default:
		err = fmt.Errorf("loại action không hỗ trợ: %s", a.Type)
	}
	if err != nil {
		return core.ActionResult{Status: "failed", Output: err.Error()}
	}
	return e.runAll(cmds)
}

func (e *Executor) ipCommands(a core.Action) ([][]string, error) {
	ip := net.ParseIP(fmt.Sprint(a.Params["ip"]))
	if ip == nil {
		return nil, fmt.Errorf("IP không hợp lệ: %v", a.Params["ip"])
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return nil, fmt.Errorf("từ chối chặn IP đặc biệt %s", ip)
	}
	if e.isManagerIP(ip) {
		return nil, fmt.Errorf("từ chối chặn IP của chính manager %s", ip)
	}
	s := ip.String()
	block := a.Type == "block_ip"
	switch runtime.GOOS {
	case "windows":
		name := "SIEM-XDR-Block-" + s
		if block {
			return [][]string{{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + name, "dir=in", "action=block", "remoteip=" + s}}, nil
		}
		return [][]string{{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + name}}, nil
	default:
		op := "-I"
		if !block {
			op = "-D"
		}
		return [][]string{{"iptables", op, "INPUT", "-s", s, "-m", "comment", "--comment", ruleTag, "-j", "DROP"}}, nil
	}
}

// ipRuleExists kiểm tra luật chặn IP (đã validate trong ipCommands) có đang tồn tại không.
func (e *Executor) ipRuleExists(a core.Action) bool {
	s := net.ParseIP(fmt.Sprint(a.Params["ip"])).String()
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=SIEM-XDR-Block-"+s)
	} else {
		c = exec.Command("iptables", "-C", "INPUT", "-s", s, "-m", "comment", "--comment", ruleTag, "-j", "DROP")
	}
	return c.Run() == nil
}

func (e *Executor) isolateCommands(isolate bool) ([][]string, error) {
	mgrIPs := e.managerIPs()
	if isolate && len(mgrIPs) == 0 {
		return nil, fmt.Errorf("không phân giải được IP manager — hủy cô lập để tránh mất kết nối vĩnh viễn")
	}
	switch runtime.GOOS {
	case "windows":
		if !isolate {
			return [][]string{
				{"netsh", "advfirewall", "firewall", "delete", "rule", "name=SIEM-XDR-Allow-Manager"},
				{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound"},
			}, nil
		}
		ips := strings.Join(mgrIPs, ",")
		return [][]string{
			{"netsh", "advfirewall", "firewall", "add", "rule", "name=SIEM-XDR-Allow-Manager", "dir=out", "action=allow", "remoteip=" + ips},
			{"netsh", "advfirewall", "firewall", "add", "rule", "name=SIEM-XDR-Allow-Manager", "dir=in", "action=allow", "remoteip=" + ips},
			{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
		}, nil
	default:
		if !isolate {
			return [][]string{
				{"iptables", "-D", "INPUT", "-j", "SIEM_ISOLATE"},
				{"iptables", "-D", "OUTPUT", "-j", "SIEM_ISOLATE"},
				{"iptables", "-F", "SIEM_ISOLATE"},
				{"iptables", "-X", "SIEM_ISOLATE"},
			}, nil
		}
		cmds := [][]string{
			{"iptables", "-N", "SIEM_ISOLATE"},
			{"iptables", "-A", "SIEM_ISOLATE", "-i", "lo", "-j", "RETURN"},
			{"iptables", "-A", "SIEM_ISOLATE", "-o", "lo", "-j", "RETURN"},
		}
		for _, ip := range mgrIPs {
			cmds = append(cmds,
				[]string{"iptables", "-A", "SIEM_ISOLATE", "-s", ip, "-j", "RETURN"},
				[]string{"iptables", "-A", "SIEM_ISOLATE", "-d", ip, "-j", "RETURN"})
		}
		cmds = append(cmds,
			[]string{"iptables", "-A", "SIEM_ISOLATE", "-j", "DROP"},
			[]string{"iptables", "-I", "INPUT", "-j", "SIEM_ISOLATE"},
			[]string{"iptables", "-I", "OUTPUT", "-j", "SIEM_ISOLATE"})
		return cmds, nil
	}
}

func (e *Executor) killProcess(a core.Action) core.ActionResult {
	if raw, ok := a.Params["pid"]; ok && raw != nil && fmt.Sprint(raw) != "" {
		pid, err := strconv.Atoi(strings.TrimSuffix(fmt.Sprint(raw), ".0"))
		if err != nil || pid <= 4 || pid == os.Getpid() {
			return core.ActionResult{Status: "failed", Output: fmt.Sprintf("pid không hợp lệ/được bảo vệ: %v", raw)}
		}
		if e.dryRun {
			return core.ActionResult{Status: "success", Output: fmt.Sprintf("dry-run: kill pid %d", pid)}
		}
		p, err := os.FindProcess(pid)
		if err == nil {
			err = p.Kill()
		}
		if err != nil {
			return core.ActionResult{Status: "failed", Output: err.Error()}
		}
		return core.ActionResult{Status: "success", Output: fmt.Sprintf("đã kill pid %d", pid)}
	}

	name := fmt.Sprint(a.Params["name"])
	if !procNameRe.MatchString(name) {
		return core.ActionResult{Status: "failed", Output: "cần params.pid hoặc params.name hợp lệ"}
	}
	if protectedProcs[strings.ToLower(name)] {
		return core.ActionResult{Status: "failed", Output: "từ chối kill tiến trình hệ thống được bảo vệ: " + name}
	}
	if runtime.GOOS == "windows" {
		return e.runAll([][]string{{"taskkill", "/F", "/IM", name}})
	}
	return e.runAll([][]string{{"pkill", "-9", "-x", name}})
}

func (e *Executor) runAll(cmds [][]string) core.ActionResult {
	var out []string
	for _, c := range cmds {
		if e.dryRun {
			out = append(out, "dry-run: "+strings.Join(c, " "))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		b, err := exec.CommandContext(ctx, c[0], c[1:]...).CombinedOutput()
		cancel()
		line := strings.TrimSpace(strings.Join(c, " ") + " => " + string(b))
		out = append(out, line)
		if err != nil {
			return core.ActionResult{Status: "failed", Output: strings.Join(out, "\n") + "\nlỗi: " + err.Error()}
		}
	}
	return core.ActionResult{Status: "success", Output: strings.Join(out, "\n")}
}

func (e *Executor) managerIPs() []string {
	host := e.client.ServerHost()
	if ip := net.ParseIP(host); ip != nil {
		return []string{ip.String()}
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return nil
	}
	var v4 []string
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			v4 = append(v4, a)
		}
	}
	return v4
}

func (e *Executor) isManagerIP(ip net.IP) bool {
	for _, m := range e.managerIPs() {
		if net.ParseIP(m).Equal(ip) {
			return true
		}
	}
	return false
}
