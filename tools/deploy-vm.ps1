<#
.SYNOPSIS
  Đưa mã nguồn siem-xdr lên máy chủ Ubuntu / Debian và cài bằng MỘT lệnh, chạy trên máy Windows đang có mã nguồn.

.EXAMPLE
  .\tools\deploy-vm.ps1 user@192.168.56.10            # lần đầu: cài toàn bộ hệ thống
  .\tools\deploy-vm.ps1 user@192.168.56.10 -Demo      # kèm máy web demo (có lỗ hổng cố ý)
  .\tools\deploy-vm.ps1 user@192.168.56.10 -Update    # sau khi sửa và commit code: gửi bản mới, build lại

.NOTES
  - Chỉ gửi bản ĐÃ COMMIT (git archive): đúng ký tự xuống dòng LF cho Linux, tự bỏ .venv, datasets, secrets, .env.
  - Dùng ssh / scp có sẵn trên Windows 10/11 (OpenSSH client). ssh hỏi mật khẩu đăng nhập, sudo hỏi mật khẩu sudo.
  - IP máy Windows này (nhìn từ máy chủ) được thêm vào SOAR_WHITELIST: SOAR không bao giờ chặn máy quản trị.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$Target,   # user@IP máy chủ
  [switch]$Demo,
  [switch]$AI,
  [switch]$Update,
  [string]$Ref = "HEAD",                                          # commit / nhánh muốn gửi
  [string]$Dir = "siem-xdr"                                       # thư mục cài trong home của user trên máy chủ
)
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
foreach ($tool in "git", "ssh", "scp") {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    throw "thiếu lệnh $tool (OpenSSH client: Settings > Apps > Optional features > OpenSSH Client)"
  }
}
$tgz = Join-Path $env:TEMP "siem-xdr-deploy.tgz"
Push-Location $repo
try {
  if (git status --porcelain) { Write-Warning "Có thay đổi chưa commit: chỉ bản đã commit ($Ref) được gửi lên máy chủ." }
  git archive --format=tar.gz --prefix="$Dir/" -o $tgz $Ref
  if ($LASTEXITCODE -ne 0) { throw "git archive thất bại" }
  Write-Host "==> Gửi mã nguồn ($([math]::Round((Get-Item $tgz).Length / 1MB, 1)) MB, $Ref) tới $Target"
  scp $tgz "${Target}:siem-xdr-deploy.tgz"
  if ($LASTEXITCODE -ne 0) { throw "scp thất bại" }

  $flags = @()
  if ($Demo) { $flags += "--demo" }
  if ($AI) { $flags += "--ai" }
  if ($Update) { $flags += "--update" }
  # rules/ai, rules/exceptions là rule do analyst duyệt (manager ghi, uid 10001): không ghi đè khi cập nhật.
  # Không dùng dấu nháy kép trong lệnh: PowerShell 5.1 truyền nháy kép lồng vào chương trình ngoài bị sai.
  $remote = "set -e; tar -xzf siem-xdr-deploy.tgz --exclude=$Dir/server/rules/ai --exclude=$Dir/server/rules/exceptions; " +
            "rm -f siem-xdr-deploy.tgz; cd $Dir; sudo ./install.sh --admin-ip `${SSH_CLIENT%% *} $($flags -join ' ')"
  Write-Host "==> Cài trên máy chủ"
  ssh -t $Target $remote
  if ($LASTEXITCODE -ne 0) { throw "cài đặt trên máy chủ thất bại (mã $LASTEXITCODE), xem thông báo ở trên" }
}
finally {
  Remove-Item -ErrorAction SilentlyContinue $tgz
  Pop-Location
}
