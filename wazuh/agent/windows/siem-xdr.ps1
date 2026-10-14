# Script active response của SOC Platform cho Wazuh agent Windows (A001 PC-01), gọi qua siem-xdr.cmd (tên lệnh giữ từ
# trước khi đổi tên project, để agent đã cài không phải cài lại).
# SOAR gửi: PUT /active-response {"command": "!siem-xdr.cmd", "arguments": [<loại>, <đích>, <action_id>]}
#
#   block_ip / unblock_ip <ip>      Windows Firewall, rule "siem-xdr block <ip>" (chặn chiều vào)
#   kill_process <pid|tên> [tên]    kill cả cây tiến trình; từ chối tiến trình hệ thống và Wazuh agent; SOAR gửi kèm
#                                   tên trong alert: PID đã thuộc tiến trình khác thì không kill
#   isolate_host / unisolate_host   chặn mọi địa chỉ TRỪ wazuh-manager (rule block với dải bù của IP manager,
#                                   vì trong Windows Firewall rule block luôn thắng rule allow)
# Kết quả ghi vào active-responses.log (agent mặc định gửi file này về), cùng định dạng với bản Linux:
#   siem-xdr: action=<id> type=<loại> target=<đích> status=success|failed detail=<mô tả>
$ErrorActionPreference = 'Stop'
$AgentDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent       # ...\ossec-agent
$Log = Join-Path $AgentDir 'active-response\active-responses.log'
$Conf = Join-Path $AgentDir 'ossec.conf'

$msg = [Console]::In.ReadLine() | ConvertFrom-Json
$argv = @($msg.parameters.extra_args)
$Type, $Target, $Id, $Expect = [string]$argv[0], [string]$argv[1], [string]$argv[2], [string]$argv[3]

function Write-Result([string]$Status, [string]$Detail) {
    $line = '{0} siem-xdr: action={1} type={2} target={3} status={4} detail={5}' -f `
        (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $Id, $Type, $Target, $Status, $Detail
    Add-Content -Path $Log -Value $line -Encoding UTF8
}
function Fail([string]$Detail) { Write-Result 'failed' $Detail; exit 1 }

if ($Id -notmatch '^[0-9a-f]{8,64}$') { exit 1 }
if ($msg.command -eq 'delete') { exit 0 }

function Get-ManagerIPs {
    $m = [regex]::Match((Get-Content $Conf -Raw), '<address>\s*([^<\s]+)\s*</address>')
    if (-not $m.Success) { return @() }
    $addr = $m.Groups[1].Value
    $ip = $null
    if ([ipaddress]::TryParse($addr, [ref]$ip)) { return @($ip.ToString()) }
    return @([System.Net.Dns]::GetHostAddresses($addr) | ForEach-Object { $_.IPAddressToString })
}

function Get-Tree([int]$ProcId, [datetime]$Since) {
    # PID và mọi tiến trình con cháu. Windows không gán lại cha khi tiến trình cha kết thúc, nên ParentProcessId có thể
    # trỏ tới một PID đã được cấp lại cho chính tiến trình đang kill: chỉ tính là con nếu được tạo SAU tiến trình cha,
    # không thì kill nhầm tiến trình không liên quan.
    $children = Get-CimInstance Win32_Process -Filter "ParentProcessId=$ProcId" |
        Where-Object { $_.CreationDate -gt $Since } | ForEach-Object { Get-Tree $_.ProcessId $_.CreationDate }
    @($children) + $ProcId
}

$Protected = 'System', 'Idle', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost',
             'wazuh-agent', 'ossec-agent', 'MsMpEng'

function Get-Complement([string]$Ip) {   # các dải IPv4 bao phủ mọi địa chỉ TRỪ $Ip
    $b = ([ipaddress]$Ip).GetAddressBytes(); [array]::Reverse($b)
    $n = [BitConverter]::ToUInt32($b, 0)
    $toIp = { param([uint32]$v) $x = [BitConverter]::GetBytes($v); [array]::Reverse($x); ([ipaddress]$x).ToString() }
    $ranges = @()
    if ($n -gt 0) { $ranges += '0.0.0.0-' + (& $toIp ($n - 1)) }
    if ($n -lt [uint32]::MaxValue) { $ranges += (& $toIp ($n + 1)) + '-255.255.255.255' }
    $ranges
}

try {
    switch ($Type) {
        { $_ -in 'block_ip', 'unblock_ip' } {
            $ip = $null
            if (-not [ipaddress]::TryParse($Target, [ref]$ip)) { Fail 'IP không hợp lệ' }
            if ([ipaddress]::IsLoopback($ip)) { Fail 'không chặn địa chỉ loopback' }
            if ((Get-ManagerIPs) -contains $ip.ToString()) { Fail 'không chặn IP của wazuh-manager' }
            $name = "siem-xdr block $($ip.ToString())"
            if ($Type -eq 'block_ip') {
                if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
                    New-NetFirewallRule -DisplayName $name -Group 'siem-xdr' -Direction Inbound -Action Block `
                        -RemoteAddress $ip.ToString() | Out-Null
                }
                Write-Result 'success' "đã chặn $Target (Windows Firewall, chiều vào)"
            } else {
                Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
                Write-Result 'success' "đã gỡ chặn $Target"
            }
        }
        'kill_process' {
            if ($Target -match '^\d+$') {
                $p = Get-Process -Id ([int]$Target) -ErrorAction SilentlyContinue
                # đã tự kết thúc -> mục tiêu "không còn chạy" đã đạt, không phải lỗi
                if (-not $p) { Write-Result 'success' "PID $Target đã kết thúc trước khi kill, không cần xử lý"; exit 0 }
                if ($Protected -contains $p.ProcessName) { Fail "từ chối kill tiến trình hệ thống $($p.ProcessName)" }
                if ($Expect) {   # tên trong alert có đuôi .exe (Sysmon), ProcessName thì không; so không phân biệt hoa thường
                    if ($Expect -notmatch '^[A-Za-z0-9._-]{1,64}$') { Fail 'tên tiến trình mong đợi không hợp lệ' }
                    if ($p.ProcessName -ne ($Expect -replace '\.exe$', '')) {
                        Fail "không kill: PID $Target hiện là $($p.ProcessName), không phải $Expect như trong alert (PID có thể đã được cấp lại)"
                    }
                }
                $root = Get-CimInstance Win32_Process -Filter "ProcessId=$([int]$Target)"
                $since = if ($root) { $root.CreationDate } else { Get-Date }
                $tree = @(Get-Tree ([int]$Target) $since)
                $kept = 0
                foreach ($procId in $tree) {
                    if ($procId -ne [int]$Target) {     # tiến trình hệ thống nằm trong cây thì giữ nguyên
                        $c = Get-Process -Id $procId -ErrorAction SilentlyContinue
                        if ($c -and $Protected -contains $c.ProcessName) { $kept++; continue }
                    }
                    Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
                }
                if (-not $p.WaitForExit(2000)) { Fail "kill PID $Target thất bại" }
                $note = if ($kept) { ", giữ $kept tiến trình hệ thống" } else { '' }
                Write-Result 'success' "đã kill PID $Target ($($p.ProcessName)) và $($tree.Count - 1 - $kept) tiến trình con$note"
            } elseif ($Target -match '^[A-Za-z0-9._-]{1,64}$') {
                $name = $Target -replace '\.exe$', ''
                if ($Protected -contains $name) { Fail "từ chối kill tiến trình hệ thống $name" }
                $ps = Get-Process -Name $name -ErrorAction SilentlyContinue
                if (-not $ps) { Fail "không có tiến trình $name" }
                $ps | Stop-Process -Force
                Write-Result 'success' "đã kill $(@($ps).Count) tiến trình $name"
            } else { Fail 'PID / tên tiến trình không hợp lệ' }
        }
        'isolate_host' {
            $mips = @(Get-ManagerIPs | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' })
            if ($mips.Count -ne 1) { Fail 'cần đúng 1 IPv4 của wazuh-manager, không cô lập (sẽ mất kênh điều khiển)' }
            Remove-NetFirewallRule -Group 'siem-xdr-isolate' -ErrorAction SilentlyContinue
            $block = Get-Complement $mips[0]
            foreach ($dir in 'Inbound', 'Outbound') {
                New-NetFirewallRule -DisplayName "siem-xdr isolate $dir" -Group 'siem-xdr-isolate' -Direction $dir `
                    -Action Block -RemoteAddress $block | Out-Null
                New-NetFirewallRule -DisplayName "siem-xdr isolate $dir IPv6" -Group 'siem-xdr-isolate' -Direction $dir `
                    -Action Block -RemoteAddress '::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff' | Out-Null
            }
            Write-Result 'success' "đã cô lập máy, chỉ giữ kết nối tới wazuh-manager ($($mips[0]))"
        }
        'unisolate_host' {
            Remove-NetFirewallRule -Group 'siem-xdr-isolate' -ErrorAction SilentlyContinue
            Write-Result 'success' 'đã bỏ cô lập'
        }
        default { Fail 'loại lệnh không hỗ trợ' }
    }
} catch {
    Fail ($_.Exception.Message -replace '\s+', ' ')
}
exit 0
