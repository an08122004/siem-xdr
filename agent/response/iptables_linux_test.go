//go:build linux

package response

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"siem-agent/core"
)

// Chạy luật iptables/ip6tables THẬT. Chỉ chạy khi đặt SIEM_IPTABLES_IT=1 và nên chạy trong container
// có network namespace riêng, vd:
//
//	docker run --rm --cap-add NET_ADMIN -e SIEM_IPTABLES_IT=1 -v <dir>:/t --entrypoint /t/response.test <image có iptables>
func TestRealIptables(t *testing.T) {
	if os.Getenv("SIEM_IPTABLES_IT") != "1" {
		t.Skip("đặt SIEM_IPTABLES_IT=1 để chạy với iptables thật (chỉ trong container)")
	}
	rules := func(bin string) string {
		out, err := exec.Command(bin, "-S").CombinedOutput()
		if err != nil {
			t.Fatalf("%s -S: %v %s", bin, err, out)
		}
		return string(out)
	}
	mgr := &fakeMgr{host: "manager.lab"}
	e := New(mgr, false, time.Second, t.TempDir())
	e.resolve = func(string) ([]string, error) { return []string{"10.0.0.5", "fd00::5"}, nil }
	e.hasIPv6 = func() bool { return true }

	for _, ip := range []string{"203.0.113.9", "2001:db8::66"} {
		a := core.Action{Type: "block_ip", Params: map[string]interface{}{"ip": ip}}
		for i := 0; i < 2; i++ { // chạy 2 lần: không được trùng luật
			if r := e.Execute(a); r.Status != "success" {
				t.Fatalf("block %s: %s", ip, r.Output)
			}
		}
	}
	v4, v6 := rules("iptables"), rules("ip6tables")
	if strings.Count(v4, "-A OUTPUT -d 203.0.113.9/32") != 1 || strings.Count(v6, "-A INPUT -s 2001:db8::66/128") != 1 {
		t.Fatalf("luật chặn sai:\n%s\n%s", v4, v6)
	}

	for i := 0; i < 2; i++ {
		if r := e.Execute(core.Action{Type: "isolate_host"}); r.Status != "success" {
			t.Fatalf("isolate lần %d: %s", i+1, r.Output)
		}
	}
	v4, v6 = rules("iptables"), rules("ip6tables")
	if strings.Count(v4, "-A INPUT -j SIEM_ISOLATE") != 1 || !strings.Contains(v6, "-A SIEM_ISOLATE -s fd00::5/128 -j RETURN") ||
		!strings.Contains(v6, "-A SIEM_ISOLATE -j DROP") {
		t.Fatalf("cô lập sai:\n%s\n%s", v4, v6)
	}

	for _, a := range []core.Action{
		{Type: "unisolate_host"}, {Type: "unisolate_host"},
		{Type: "unblock_ip", Params: map[string]interface{}{"ip": "203.0.113.9"}},
		{Type: "unblock_ip", Params: map[string]interface{}{"ip": "2001:db8::66"}},
	} {
		if r := e.Execute(a); r.Status != "success" {
			t.Fatalf("%s: %s", a.Type, r.Output)
		}
	}
	v4, v6 = rules("iptables"), rules("ip6tables")
	if strings.Contains(v4+v6, "SIEM_ISOLATE") || strings.Contains(v4+v6, "siem-xdr") {
		t.Fatalf("gỡ không sạch:\n%s\n%s", v4, v6)
	}
}
