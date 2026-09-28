package response

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"siem-agent/core"
)

type fakeMgr struct {
	host string
	pins []string
}

func (f *fakeMgr) PollActions(context.Context) ([]core.Action, error)            { return nil, nil }
func (f *fakeMgr) ReportAction(context.Context, string, core.ActionResult) error { return nil }
func (f *fakeMgr) ServerHost() string                                            { return f.host }
func (f *fakeMgr) PinServerIPs(ips []string)                                     { f.pins = ips }

// fakeFW giả lập iptables/netsh: nhớ các luật đã thêm, "-C"/"show" trả thành công nếu luật có.
type fakeFW struct {
	rules map[string]bool
	log   []string
	fail  string // lệnh chứa chuỗi này sẽ lỗi
}

func (f *fakeFW) run(cmd []string) ([]byte, error) {
	line := strings.Join(cmd, " ")
	f.log = append(f.log, line)
	if f.fail != "" && strings.Contains(line, f.fail) {
		return []byte("lỗi giả lập"), errors.New("exit 1")
	}
	key := func(op string) string { return strings.Replace(line, " "+op+" ", " ", 1) }
	switch {
	case len(cmd) > 1 && cmd[1] == "-C":
		if !f.rules[key("-C")] {
			return nil, errors.New("không có luật")
		}
	case len(cmd) > 1 && cmd[1] == "-I":
		f.rules[key("-I")] = true
	case len(cmd) > 1 && cmd[1] == "-D":
		if !f.rules[key("-D")] {
			return nil, errors.New("không có luật")
		}
		delete(f.rules, key("-D"))
	}
	return nil, nil
}

func (f *fakeFW) count(substr string) int {
	n := 0
	for _, l := range f.log {
		if strings.Contains(l, substr) {
			n++
		}
	}
	return n
}

func newExec(t *testing.T, goos string) (*Executor, *fakeFW, *fakeMgr) {
	fw := &fakeFW{rules: map[string]bool{}}
	mgr := &fakeMgr{host: "manager.lab"}
	e := New(mgr, false, time.Second, t.TempDir())
	e.goos, e.run = goos, fw.run
	e.lookPath = func(string) (string, error) { return "/sbin/x", nil }
	e.resolve = func(string) ([]string, error) { return []string{"10.0.0.5", "fd00::5"}, nil }
	e.hasIPv6 = func() bool { return true }
	e.procName = func(pid int) (string, error) { return "", errors.New("không có") }
	return e, fw, mgr
}

func TestBlockBothDirectionsAndIdempotent(t *testing.T) {
	e, fw, _ := newExec(t, "linux")
	a := core.Action{Type: "block_ip", Params: map[string]interface{}{"ip": "203.0.113.9"}}
	if r := e.Execute(a); r.Status != "success" {
		t.Fatal(r.Output)
	}
	if fw.count("iptables -I OUTPUT -d 203.0.113.9") != 1 || fw.count("iptables -I INPUT -s 203.0.113.9") != 1 {
		t.Fatalf("phải chặn cả chiều vào và ra:\n%s", strings.Join(fw.log, "\n"))
	}
	e.Execute(a) // chặn lần 2: không thêm luật trùng
	if fw.count("iptables -I INPUT -s 203.0.113.9") != 1 {
		t.Fatal("chặn lại không được nhân đôi luật")
	}
	if r := e.Execute(core.Action{Type: "block_ip", Params: map[string]interface{}{"ip": "2001:db8::66"}}); r.Status != "success" {
		t.Fatal(r.Output)
	}
	if fw.count("ip6tables -I INPUT -s 2001:db8::66") != 1 {
		t.Fatal("IPv6 phải dùng ip6tables")
	}
	if r := e.Execute(core.Action{Type: "block_ip", Params: map[string]interface{}{"ip": "fd00::5"}}); r.Status != "failed" {
		t.Fatal("không được chặn IP của manager (kể cả IPv6)")
	}
}

func TestAgentExpiresBlockItself(t *testing.T) {
	e, fw, _ := newExec(t, "linux")
	now := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	e.now = func() time.Time { return now }
	a := core.Action{Type: "block_ip", Params: map[string]interface{}{"ip": "198.51.100.7", "duration": 3600},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if r := e.Execute(a); r.Status != "success" {
		t.Fatal(r.Output)
	}
	e.ExpireBlocks()
	if fw.count("-D INPUT -s 198.51.100.7") != 0 {
		t.Fatal("chưa tới hạn đã gỡ")
	}
	// agent khởi động lại vẫn nhớ hạn gỡ
	e2 := New(&fakeMgr{host: "10.0.0.5"}, false, time.Second, filepath.Dir(e.statePath))
	e2.goos, e2.run, e2.now = "linux", fw.run, func() time.Time { return now.Add(61 * time.Minute) }
	e2.ExpireBlocks()
	if fw.count("iptables -D INPUT -s 198.51.100.7") != 1 || len(e2.st.Blocks) != 0 {
		t.Fatalf("hết hạn thì agent phải tự gỡ:\n%s", strings.Join(fw.log, "\n"))
	}
	// lệnh tới muộn, đã quá hạn: không chặn
	late := core.Action{Type: "block_ip", Params: map[string]interface{}{"ip": "198.51.100.8"}, ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339)}
	if r := e.Execute(late); r.Status != "success" || fw.count("198.51.100.8") != 0 {
		t.Fatalf("lệnh đã hết hạn không được thực thi: %s", r.Output)
	}
}

func TestLinuxIsolateOrderAndPins(t *testing.T) {
	e, fw, mgr := newExec(t, "linux")
	if r := e.Execute(core.Action{Type: "isolate_host"}); r.Status != "success" {
		t.Fatal(r.Output)
	}
	joined := strings.Join(fw.log, "\n")
	for _, want := range []string{
		"iptables -A SIEM_ISOLATE -s 10.0.0.5 -j RETURN", "ip6tables -A SIEM_ISOLATE -d fd00::5 -j RETURN",
		"ip6tables -A SIEM_ISOLATE -p ipv6-icmp -j RETURN", "ip6tables -I OUTPUT -j SIEM_ISOLATE",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("thiếu %q:\n%s", want, joined)
		}
	}
	for _, bin := range []string{"iptables ", "ip6tables "} {
		drop := strings.Index(joined, bin+"-A SIEM_ISOLATE -j DROP")
		jump := strings.Index(joined, bin+"-I INPUT -j SIEM_ISOLATE")
		if drop < 0 || jump < 0 || drop > jump {
			t.Fatalf("%s: DROP phải có trước khi gắn jump", bin)
		}
	}
	if fmt.Sprint(mgr.pins) != "[10.0.0.5 fd00::5]" || !e.st.Isolated {
		t.Fatalf("phải ghim IP manager trước khi chặn DNS, pins=%v", mgr.pins)
	}
	// cô lập lần 2 không nhân đôi jump
	e.Execute(core.Action{Type: "isolate_host"})
	if fw.count("iptables -I INPUT -j SIEM_ISOLATE") != 1 {
		t.Fatal("cô lập lại không được gắn jump lần nữa")
	}
	if r := e.Execute(core.Action{Type: "unisolate_host"}); r.Status != "success" || mgr.pins != nil || e.st.Isolated {
		t.Fatalf("bỏ cô lập phải gỡ ghim: %s", r.Output)
	}
}

func TestIsolateFailsLoudlyWithoutIP6Tables(t *testing.T) {
	e, _, mgr := newExec(t, "linux")
	e.lookPath = func(n string) (string, error) {
		if n == "ip6tables" {
			return "", errors.New("không có")
		}
		return "/sbin/" + n, nil
	}
	if r := e.Execute(core.Action{Type: "isolate_host"}); r.Status != "failed" || mgr.pins != nil {
		t.Fatalf("máy bật IPv6 mà không có ip6tables thì phải báo lỗi, không cô lập nửa vời: %+v", r)
	}
}

func TestWindowsIsolateComplementRanges(t *testing.T) {
	e, fw, _ := newExec(t, "windows")
	e.resolve = func(string) ([]string, error) { return []string{"10.0.0.5"}, nil }
	if r := e.Execute(core.Action{Type: "isolate_host"}); r.Status != "success" {
		t.Fatal(r.Output)
	}
	joined := strings.Join(fw.log, "\n")
	want := "remoteip=0.0.0.0-10.0.0.4,10.0.0.6-255.255.255.255,::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
	if !strings.Contains(joined, want) || !strings.Contains(joined, "remoteport=1-66,68-65535") {
		t.Fatalf("luật chặn phải loại trừ đúng IP manager:\n%s", joined)
	}
	if strings.Contains(joined, "firewallpolicy") {
		t.Fatal("không được đổi chính sách mặc định của tường lửa")
	}
}

func TestComplementEdges(t *testing.T) {
	a := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	if got := strings.Join(complementV4([]netip.Addr{a("0.0.0.0"), a("0.0.0.1")}), ","); got != "0.0.0.2-255.255.255.255" {
		t.Fatal(got)
	}
	if got := strings.Join(complementV4([]netip.Addr{a("255.255.255.255")}), ","); got != "0.0.0.0-255.255.255.254" {
		t.Fatal(got)
	}
	if got := strings.Join(complementV4([]netip.Addr{a("10.0.0.9"), a("10.0.0.7")}), ","); got != "0.0.0.0-10.0.0.6,10.0.0.8,10.0.0.10-255.255.255.255" {
		t.Fatal(got)
	}
}

func TestKillChecksProcessIdentity(t *testing.T) {
	e, _, _ := newExec(t, "linux")
	e.dryRun = true
	names := map[int]string{700: "bash", 701: "lsass.exe", 702: "kworker-long-na"}
	e.procName = func(pid int) (string, error) {
		if n, ok := names[pid]; ok {
			return n, nil
		}
		return "", errors.New("không có")
	}
	cases := []struct {
		params map[string]interface{}
		ok     bool
	}{
		{map[string]interface{}{"pid": 700, "name": "bash"}, true},
		{map[string]interface{}{"pid": 700, "name": "nc"}, false},                        // PID đã bị tái sử dụng
		{map[string]interface{}{"pid": 701}, false},                                      // tiến trình hệ thống
		{map[string]interface{}{"pid": 999}, false},                                      // không tồn tại
		{map[string]interface{}{"pid": 702, "name": "/usr/bin/kworker-long-name"}, true}, // comm bị cắt 15 ký tự
		{map[string]interface{}{"name": "bash"}, false},                                  // tên dùng chung: phải kill theo pid
		{map[string]interface{}{"name": "xmrig"}, true},
	}
	for _, c := range cases {
		r := e.Execute(core.Action{Type: "kill_process", Params: c.params})
		if (r.Status == "success") != c.ok {
			t.Errorf("%v -> %s: %s", c.params, r.Status, r.Output)
		}
	}
}

func TestParseFirewallState(t *testing.T) {
	out := "\r\nDomain Profile Settings:\r\n----\r\nState                                 ON\r\n\r\nPrivate Profile Settings:\r\n----\r\nState                                 OFF\r\n\r\nPublic Profile Settings:\r\n----\r\nState                                 ON\r\nOk.\r\n"
	st := parseFirewallState(out)
	if st["private"] != "OFF" || st["public"] != "ON" || len(st) != 3 {
		t.Fatalf("%v", st)
	}
	steps := windowsUnisolate(st)
	if last := strings.Join(steps[len(steps)-1].cmd, " "); last != "netsh advfirewall set privateprofile state off" {
		t.Fatalf("bỏ cô lập phải trả profile đang tắt về tắt: %s", last)
	}
}
