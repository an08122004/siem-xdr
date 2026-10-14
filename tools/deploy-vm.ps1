<#
.SYNOPSIS
  Đưa mã nguồn SOC Platform lên máy chủ Ubuntu / Debian và cài bằng MỘT lệnh, chạy trên máy Windows đang có mã nguồn.

.EXAMPLE
  # Windows mặc định chặn chạy file .ps1: gọi qua powershell -ExecutionPolicy Bypass -File (không đổi cấu hình máy)
  powershell -ExecutionPolicy Bypass -File .\tools\deploy-vm.ps1 user@192.168.56.10
.EXAMPLE
  .\tools\deploy-vm.ps1 user@192.168.56.10            # lần đầu: cài toàn bộ hệ thống
  .\tools\deploy-vm.ps1 user@192.168.56.10 -Demo      # kèm máy web demo (có lỗ hổng cố ý)
  .\tools\deploy-vm.ps1 user@192.168.56.10 -Update    # sau khi sửa và commit code: gửi bản mới, build lại

.NOTES
  - Chỉ gửi bản ĐÃ COMMIT (git archive): đúng ký tự xuống dòng LF cho Linux, tự bỏ .venv, datasets, secrets, .env.
  - Dùng ssh / scp có sẵn trên Windows 10/11 (OpenSSH client). ssh hỏi mật khẩu đăng nhập, sudo hỏi mật khẩu sudo.
  - IP máy Windows này (nhìn từ máy chủ) được thêm vào SOAR_WHITELIST: SOAR không bao giờ chặn máy quản trị.
  - Máy chủ cài trước 14/10/2026 có mã nguồn ở ~/siem-xdr: nếu chưa có ~/soc-platform thì vẫn cập nhật vào ~/siem-xdr
    (giữ .env, secrets, rule đã duyệt). Chỉ định -Dir để chọn thư mục khác.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)][string]$Target,   # user@IP máy chủ
  [switch]$Demo,
  [switch]$AI,
  [switch]$Update,
  [string]$Ref = "HEAD",                                          # commit / nhánh muốn gửi
  [string]$Dir = "",                                              # thư mục cài trong home của user trên máy chủ (mặc định soc-platform)
  [int]$Port = 22,                                                # cổng SSH của máy chủ
  [string[]]$SshOption = @()                                      # tùy chọn thêm cho ssh/scp, vd -SshOption '-i','C:\keys\vm'
)
# Không dùng "Stop": PowerShell 5.1 coi dòng cảnh báo trên stderr của ssh / scp là lỗi chặn khi đầu ra bị chuyển hướng.
# Mỗi lệnh ngoài được kiểm tra bằng $LASTEXITCODE.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
foreach ($tool in "git", "ssh", "scp") {
  if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
    throw "thiếu lệnh $tool (OpenSSH client: Settings > Apps > Optional features > OpenSSH Client)"
  }
}
$tgz = Join-Path $env:TEMP "soc-platform-deploy.tgz"
Push-Location $repo
try {
  if (-not $Dir) {
    # Bản cài cũ (~/siem-xdr, chưa có ~/soc-platform): cập nhật tại chỗ, không tạo cài đặt thứ hai trùng cổng
    $Dir = "soc-platform"
    $probe = ssh -p $Port @SshOption $Target "test -d soc-platform || test ! -f siem-xdr/install.sh || echo siem-xdr"
    if ($LASTEXITCODE -eq 0 -and "$probe".Trim() -eq "siem-xdr") {
      $Dir = "siem-xdr"
      Write-Host "==> Máy chủ đã cài ở ~/siem-xdr (trước khi đổi tên): cập nhật vào thư mục đó"
    }
  }
  if (git status --porcelain) { Write-Warning "Có thay đổi chưa commit: chỉ bản đã commit ($Ref) được gửi lên máy chủ." }
  git archive --format=tar.gz --prefix="$Dir/" -o $tgz $Ref
  if ($LASTEXITCODE -ne 0) { throw "git archive thất bại" }
  Write-Host "==> Gửi mã nguồn ($([math]::Round((Get-Item $tgz).Length / 1MB, 1)) MB, $Ref) tới $Target"
  scp -P $Port @SshOption $tgz "${Target}:soc-platform-deploy.tgz"
  if ($LASTEXITCODE -ne 0) { throw "scp thất bại" }

  $flags = @()
  if ($Demo) { $flags += "--demo" }
  if ($AI) { $flags += "--ai" }
  if ($Update) { $flags += "--update" }
  # rules/ai, rules/exceptions là rule do analyst duyệt (manager ghi, uid 10001): không ghi đè khi cập nhật.
  # Không dùng dấu nháy kép trong lệnh: PowerShell 5.1 truyền nháy kép lồng vào chương trình ngoài bị sai.
  $remote = "set -e; tar -xzf soc-platform-deploy.tgz --exclude=$Dir/server/rules/ai --exclude=$Dir/server/rules/exceptions; " +
            "rm -f soc-platform-deploy.tgz; cd $Dir; sudo ./install.sh --admin-ip `${SSH_CLIENT%% *} $($flags -join ' ')"
  Write-Host "==> Cài trên máy chủ"
  ssh -t -p $Port @SshOption $Target $remote
  if ($LASTEXITCODE -ne 0) { throw "cài đặt trên máy chủ thất bại (mã $LASTEXITCODE), xem thông báo ở trên" }
}
finally {
  Remove-Item -ErrorAction SilentlyContinue $tgz
  Pop-Location
}
