#!/usr/bin/env bash
# Thử các hàm của install.sh với docker / python3 giả (server/tests/test_install_sh.py chạy trong CI).
# Dùng: bash tools/test_install_sh.sh [install.sh]
SRC=${1:-install.sh}
LIB=$(mktemp); sed -e '/^cd "\$(dirname/d' -e '/^while \[ \$# -gt 0 \]/,/^done$/d' -e '/^case "\$CMD" in/,/^esac$/d' "$SRC" > "$LIB"
pass=0; fail=0
check() { if eval "$2"; then echo "  ĐẠT: $1"; pass=$((pass+1)); else echo "  HỎNG: $1"; fail=$((fail+1)); fi; }

run() {   # run <tên> <hàm thử>: chạy trong thư mục tạm, subshell riêng
  local d; d=$(mktemp -d); mkdir -p "$d/secrets" "$d/server/rules" "$d/security" "$d/wazuh/manager/entrypoint" "$d/tools"
  touch "$d/docker-compose.yml" "$d/tools/init_secrets.py" "$d/secrets/x" "$d/security/setup.sh" "$d/wazuh/manager/entrypoint/a.sh"
  # giữ set -euo pipefail của install.sh như khi chạy thật: lệnh lỗi làm script dừng thì test cũng thấy
  ( cd "$d" || exit; source "$LIB"; "$2" ) > "$d/out" 2>&1
  echo "rc=$?" >> "$d/out"; [ -f "$d/docker.log" ] && cat "$d/docker.log" >> "$d/out"
  echo "== $1"; OUT=$(cat "$d/out"); rm -rf "$d"
}
# giả lập: docker ghi lệnh ra file (install.sh đẩy đầu ra một số lệnh vào /dev/null); volume siem-xdr_certs có sẵn.
# grep -U: grep của Git for Windows bỏ ký tự CR khi đọc file, trên Linux thì không.
stubs='docker() { echo "DOCKER $*" >> docker.log; [ "$1 ${2:-}" = "volume inspect" ] && [ "${3:-}" != siem-xdr_certs ] && return 1; return 0; }
python3() { echo "đã tạo  misp_api_key"; }; chown() { :; }; chmod() { :; }; who() { :; }; sleep() { :; }; id() { echo 0; }
grep() { command grep -U "$@"; }'

t1() { eval "$stubs"; printf 'MANAGER_TLS_IPS=10.0.0.1\n' > .env; IP=10.0.0.2; ASSUME_YES=1; configure; }
run "đổi IP trên máy chưa ghi tên project" t1
check "down đúng project siem-xdr" 'grep -q "DOCKER compose -p siem-xdr down" <<<"$OUT"'
check "xóa đúng volume siem-xdr_certs" 'grep -q "DOCKER volume rm siem-xdr_certs" <<<"$OUT"'
check "chạy hết, không lỗi" 'grep -q "rc=0" <<<"$OUT"'

t2() { eval "$stubs"; python3() { echo "Traceback: lỗi giả" >&2; return 1; }; printf 'MANAGER_TLS_IPS=10.0.0.1\n' > .env; configure; echo "VẪN CHẠY TIẾP"; }
run "init_secrets.py lỗi" t2
check "dừng với thông báo rõ" 'grep -q "không sinh được bí mật" <<<"$OUT"'
check "không chạy tiếp" '! grep -q "VẪN CHẠY TIẾP" <<<"$OUT"'

t3() { eval "$stubs"; printf 'X=1\n' > .env; status; }
run "status trên máy chưa ghi tên project" t3
check "status xem project siem-xdr" 'grep -q "DOCKER compose -p siem-xdr ps" <<<"$OUT"'

t8() { eval "$stubs"; printf 'COMPOSE_PROJECT_NAME=lab-cu\n' > .env; status; }
run ".env ghi tên project khác" t8
check "giữ tên trong .env" 'grep -q "DOCKER compose -p lab-cu ps" <<<"$OUT"'

t4() { eval "$stubs"; docker() { echo "DOCKER $*" >> docker.log
         [ "${4:-}" = up ] && { echo "dependency failed to start: container siem-xdr-elasticsearch-1 is unhealthy" >&2; return 1; }; return 0; }
       start_stack; echo "VẪN CHẠY TIẾP"; }
run "up lỗi vì Elasticsearch không healthy" t4
check "in trạng thái và log es-setup, elasticsearch" \
  'grep -q "DOCKER compose -p siem-xdr ps -a" <<<"$OUT" && grep -q "DOCKER compose -p siem-xdr logs --tail 30 es-setup elasticsearch" <<<"$OUT"'
check "dừng với gợi ý" 'grep -q "thiếu RAM hoặc vm.max_map_count" <<<"$OUT" && ! grep -q "VẪN CHẠY TIẾP" <<<"$OUT"'

t15() { eval "$stubs"; printf 'MANAGER_TLS_IPS=10.0.0.1,192.168.9.9\n' > .env; configure; grep '^MANAGER_TLS_IPS=' .env
        IP=10.0.0.2; ASSUME_YES=1; configure; grep '^MANAGER_TLS_IPS=' .env; }
run "MANAGER_TLS_IPS có nhiều IP" t15
check "chạy lại giữ IP thêm sau dấu phẩy" 'grep -qx "MANAGER_TLS_IPS=10.0.0.1,192.168.9.9" <<<"$OUT"'
check "đổi IP chỉ thay IP đầu" 'grep -qx "MANAGER_TLS_IPS=10.0.0.2,192.168.9.9" <<<"$OUT"'

t16() { eval "$stubs"; id() { echo 1000; }; printf 'MANAGER_TLS_IPS=10.0.0.1\n' > .env; info; }
run "info không có sudo" t16
check "báo cần quyền root" 'grep -q "cần quyền root (đọc secrets/)" <<<"$OUT"'

t5() { eval "$stubs"; printf 'set -e\r\n' > security/setup.sh; check_system; }
run "script bị đổi sang CRLF" t5
check "phát hiện CRLF" 'grep -q "CRLF" <<<"$OUT"'

t6() { eval "$stubs"; check_system; }
run "không CRLF thì không báo nhầm" t6
check "không báo CRLF" '! grep -q "CRLF" <<<"$OUT"'

mkpkg() {   # tarball giả của GitHub (thư mục gốc r-1/); install.sh trong gói in nơi chạy, tham số, rules/ai, config, bản sao
  mkdir -p pkg/r-1/server/rules/ai pkg/r-1/server/config
  cat > pkg/r-1/install.sh <<'EOF'
cd "$(dirname "$0")"; echo "CHẠY $(basename "$PWD")/install.sh: $*; rules/ai: $(ls server/rules/ai 2>/dev/null); config: $(cat server/config/assets.yml); bak: $(cat server/config.bak-*/assets.yml 2>/dev/null)"
EOF
  touch pkg/r-1/docker-compose.yml pkg/r-1/server/rules/ai/ai-tu-github.yml
  printf 'cau-hinh-github' > pkg/r-1/server/config/assets.yml
  tar -czf pkg.tgz -C pkg r-1
  curl() { echo "CURL $*" >> docker.log; echo "CẤU HÌNH: $(cat)" >> docker.log; cat pkg.tgz; }
  unset SUDO_USER
}
t9() { eval "$stubs"; mkpkg; rm docker-compose.yml; GITHUB_TOKEN=tok; ARGV=(--demo -y); fetch_source; echo "KHÔNG CHẠY BẢN TẢI VỀ"; }
run "máy chỉ có install.sh" t9
check "tải vào ./siem-xdr, chạy install.sh trong đó cùng tham số" 'grep -q "CHẠY siem-xdr/install.sh: --demo -y;" <<<"$OUT"'
check "token qua stdin, không nằm trên dòng lệnh" 'grep -q "CẤU HÌNH: header = \"Authorization: Bearer tok\"" <<<"$OUT" && ! grep -q "CURL .*tok" <<<"$OUT"'
check "không lấy rules/ai từ gói" '! grep -q "ai-tu-github" <<<"$OUT"'

t10() { eval "$stubs"; mkpkg; mkdir -p server/rules/ai server/config; touch server/rules/ai/da-duyet.yml
        printf 'cua-toi' > server/config/assets.yml; FETCH=1; ARGV=(--fetch -y); fetch_source; }
run "--fetch trên mã nguồn có sẵn" t10
check "chạy lại với --update, bỏ --fetch, giữ rule AI đã duyệt" 'grep -q "install.sh: -y --update; rules/ai: da-duyet.yml;" <<<"$OUT"'
check "server/config đã sửa trên máy được lưu bản sao trước khi tải đè" \
  'grep -q "config: cau-hinh-github; bak: cua-toi$" <<<"$OUT" && grep -q "bản cũ của server/config lưu ở server/config.bak-" <<<"$OUT"'

t11() { eval "$stubs"; mkpkg; fetch_source; echo "CÀI TIẾP"; }
run "đã có mã nguồn, không --fetch" t11
check "không tải, cài tiếp tại chỗ" 'grep -q "CÀI TIẾP" <<<"$OUT" && ! grep -q "CURL" <<<"$OUT"'

t12() { eval "$stubs"; mkpkg; curl() { cat >/dev/null; echo "curl: (22) 404" >&2; return 22; }; rm docker-compose.yml; fetch_source; echo "VẪN CHẠY TIẾP"; }
run "không tải được (repo private, thiếu token)" t12
check "dừng với thông báo cần token" 'grep -q "không tải được mã nguồn.*token" <<<"$OUT" && ! grep -q "VẪN CHẠY TIẾP" <<<"$OUT"'

t13() { eval "$stubs"; docker() { echo "DOCKER $*" >> docker.log; [ "$1 ${2:-}" = "image inspect" ] && return 1; return 0; }; start_stack; }
run "lần đầu: chưa có image server" t13
check "build image server trước rồi mới up (up không phải thử pull)" \
  'sed -n "/DOCKER compose -p siem-xdr build manager/,\$p" <<<"$OUT" | grep -q "DOCKER compose -p siem-xdr up -d"'

t14() { eval "$stubs"; start_stack; }
run "đã có image server, không --update" t14
check "không build lại" 'grep -q "DOCKER compose -p siem-xdr up -d" <<<"$OUT" && ! grep -q "DOCKER compose.*build" <<<"$OUT"'

rm -f "$LIB"; echo "Kết quả: $pass đạt, $fail hỏng"; [ "$fail" = 0 ]
