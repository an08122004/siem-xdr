package response

import (
	"net/netip"
	"sort"
	"strings"
)

// step là một lệnh hệ thống trong kịch bản phản ứng.
type step struct {
	cmd      []string
	optional bool     // lỗi thì bỏ qua (vd xóa luật vốn không tồn tại)
	unless   []string // chạy lệnh kiểm tra này trước; thành công thì bỏ qua bước (chạy lại không bị trùng luật)
}

const (
	ruleTag     = "siem-xdr"
	isolChain   = "SIEM_ISOLATE"
	winIsolRule = "SIEM-XDR-Isolate"
	winLegacy   = "SIEM-XDR-Allow-Manager" // luật cô lập của bản cũ
)

func ipBin(a netip.Addr) string {
	if a.Is4() {
		return "iptables"
	}
	return "ip6tables"
}

// linuxBlock: chặn cả chiều vào (INPUT, FORWARD) lẫn chiều ra (OUTPUT, FORWARD) để cắt cả kết nối
// ngược ra C2 (IOC từ Threat Intel), không chỉ kết nối từ IP đó vào.
func linuxBlock(a netip.Addr, block bool) []step {
	bin, ip := ipBin(a), a.String()
	rules := [][]string{
		{"INPUT", "-s", ip}, {"FORWARD", "-s", ip}, {"OUTPUT", "-d", ip}, {"FORWARD", "-d", ip},
	}
	var steps []step
	for _, r := range rules {
		spec := append(r, "-m", "comment", "--comment", ruleTag, "-j", "DROP")
		if block {
			steps = append(steps, step{
				cmd:    append([]string{bin, "-I"}, spec...),
				unless: append([]string{bin, "-C"}, spec...),
			})
		} else {
			steps = append(steps, step{cmd: append([]string{bin, "-D"}, spec...), optional: true})
		}
	}
	return steps
}

func windowsBlock(a netip.Addr, block bool) []step {
	name := "name=SIEM-XDR-Block-" + a.String()
	if !block {
		return []step{{cmd: []string{"netsh", "advfirewall", "firewall", "delete", "rule", name}, optional: true}}
	}
	var steps []step
	for _, dir := range []string{"dir=in", "dir=out"} {
		steps = append(steps, step{
			cmd:    []string{"netsh", "advfirewall", "firewall", "add", "rule", name, dir, "action=block", "remoteip=" + a.String()},
			unless: []string{"netsh", "advfirewall", "firewall", "show", "rule", name, dir},
		})
	}
	return steps
}

// linuxIsolate: chain riêng chỉ cho phép loopback, DHCP và manager; mọi thứ khác (kể cả phiên đang
// mở như reverse shell) bị DROP. Chạy lại được nhiều lần (chain bị flush rồi dựng lại, jump không bị nhân đôi).
func linuxIsolate(managers []netip.Addr, withV6 bool) []step {
	var steps []step
	for _, v6 := range []bool{false, true} {
		if v6 && !withV6 {
			continue
		}
		bin := "iptables"
		if v6 {
			bin = "ip6tables"
		}
		add := func(args ...string) {
			steps = append(steps, step{cmd: append([]string{bin, "-A", isolChain}, args...)})
		}
		steps = append(steps,
			step{cmd: []string{bin, "-N", isolChain}, optional: true}, // đã có thì thôi
			step{cmd: []string{bin, "-F", isolChain}})
		add("-i", "lo", "-j", "RETURN")
		add("-o", "lo", "-j", "RETURN")
		if v6 {
			add("-p", "ipv6-icmp", "-j", "RETURN") // neighbor discovery, không có thì mất kết nối IPv6 tới manager
			add("-p", "udp", "--dport", "547", "-j", "RETURN")
			add("-p", "udp", "--dport", "546", "-j", "RETURN")
		} else {
			add("-p", "udp", "--sport", "68", "--dport", "67", "-j", "RETURN") // gia hạn DHCP, tránh mất IP
			add("-p", "udp", "--sport", "67", "--dport", "68", "-j", "RETURN")
		}
		for _, m := range managers {
			if m.Is6() != v6 {
				continue
			}
			add("-s", m.String(), "-j", "RETURN")
			add("-d", m.String(), "-j", "RETURN")
		}
		add("-j", "DROP") // DROP phải có trước khi gắn jump
		for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			steps = append(steps, step{
				cmd:    []string{bin, "-I", chain, "-j", isolChain},
				unless: []string{bin, "-C", chain, "-j", isolChain},
			})
		}
	}
	return steps
}

func linuxUnisolate(withV6 bool) []step {
	var steps []step
	for _, bin := range []string{"iptables", "ip6tables"} {
		if bin == "ip6tables" && !withV6 {
			continue
		}
		for _, chain := range []string{"INPUT", "OUTPUT", "FORWARD"} {
			steps = append(steps, step{cmd: []string{bin, "-D", chain, "-j", isolChain}, optional: true})
		}
		steps = append(steps,
			step{cmd: []string{bin, "-F", isolChain}, optional: true},
			step{cmd: []string{bin, "-X", isolChain}, optional: true})
	}
	return steps
}

// windowsIsolate: luật BLOCK cho mọi địa chỉ trừ manager. Luật block của Windows Firewall thắng mọi
// luật allow sẵn có của ứng dụng, nên không cần đổi chính sách mặc định của máy (gỡ ra là sạch).
// UDP chừa cổng 67 để DHCP gia hạn được.
func windowsIsolate(managers []netip.Addr) []step {
	remote := "remoteip=" + strings.Join(append(complementV4(managers), complementV6(managers)...), ",")
	steps := []step{
		{cmd: []string{"netsh", "advfirewall", "set", "allprofiles", "state", "on"}},
		{cmd: []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + winIsolRule}, optional: true},
	}
	for _, dir := range []string{"dir=out", "dir=in"} {
		base := []string{"netsh", "advfirewall", "firewall", "add", "rule", "name=" + winIsolRule, dir, "action=block"}
		steps = append(steps,
			step{cmd: append(append([]string{}, base...), "protocol=TCP", remote)},
			step{cmd: append(append([]string{}, base...), "protocol=UDP", "remoteport=1-66,68-65535", remote)},
			step{cmd: append(append([]string{}, base...), "protocol=ICMPv4", remote)})
	}
	return steps
}

func windowsUnisolate(prevState map[string]string) []step {
	steps := []step{
		{cmd: []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + winIsolRule}, optional: true},
		{cmd: []string{"netsh", "advfirewall", "firewall", "delete", "rule", "name=" + winLegacy}, optional: true},
	}
	// trả tường lửa về trạng thái trước khi cô lập (vd trước đó đang tắt ở profile nào)
	profiles := make([]string, 0, len(prevState))
	for p := range prevState {
		profiles = append(profiles, p)
	}
	sort.Strings(profiles)
	for _, p := range profiles {
		if strings.EqualFold(prevState[p], "OFF") {
			steps = append(steps, step{cmd: []string{"netsh", "advfirewall", "set", p + "profile", "state", "off"}, optional: true})
		}
	}
	return steps
}

// complementV4 trả các dải IPv4 bao phủ mọi địa chỉ TRỪ các IP manager.
func complementV4(managers []netip.Addr) []string {
	return complement(managers, netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255"), true)
}

func complementV6(managers []netip.Addr) []string {
	return complement(managers, netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), false)
}

func complement(managers []netip.Addr, lo, hi netip.Addr, v4 bool) []string {
	var ips []netip.Addr
	for _, m := range managers {
		if m.Is4() == v4 {
			ips = append(ips, m)
		}
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	var out []string
	start := lo
	for _, ip := range ips {
		if ip.Compare(start) > 0 {
			out = append(out, rangeStr(start, ip.Prev()))
		}
		if ip.Compare(start) >= 0 {
			start = ip.Next()
			if !start.IsValid() { // manager là địa chỉ cuối cùng
				return out
			}
		}
	}
	return append(out, rangeStr(start, hi))
}

func rangeStr(a, b netip.Addr) string {
	if a == b {
		return a.String()
	}
	return a.String() + "-" + b.String()
}
