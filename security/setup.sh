#!/bin/bash
# Khởi tạo bảo mật nội bộ cho Elasticsearch (chạy 1 lần bởi service es-setup trong docker-compose):
#   1. Tạo CA nội bộ + chứng chỉ TLS cho elasticsearch và manager (nếu chưa có)
#   2. Phân quyền file khóa: mỗi service chỉ đọc được khóa của chính nó
#   3. Chờ Elasticsearch lên rồi tạo role + user theo nguyên tắc quyền tối thiểu (RBAC)
# Mật khẩu đọc từ Docker secrets (/run/secrets/*), không nằm trong file cấu hình.
#
# Dùng: setup.sh certs  -> chỉ bước 1-2 (chạy TRƯỚC Elasticsearch, service es-certs)
#       setup.sh users  -> chỉ bước 3   (chạy SAU khi Elasticsearch healthy, service es-setup)
set -euo pipefail
MODE=${1:-all}
CERTS=/usr/share/elasticsearch/config/certs
S=/run/secrets
cd /usr/share/elasticsearch

if [ "$MODE" = "certs" ] || [ "$MODE" = "all" ]; then

if [ ! -f "$CERTS/ca/ca.crt" ]; then
  echo "[setup] tạo CA nội bộ"
  bin/elasticsearch-certutil ca --silent --pem -out "$CERTS/ca.zip"
  unzip -q -o "$CERTS/ca.zip" -d "$CERTS" && rm "$CERTS/ca.zip"
fi

if [ ! -f "$CERTS/manager/manager.crt" ]; then
  echo "[setup] tạo chứng chỉ cho elasticsearch, manager (IP thêm: ${MANAGER_TLS_IPS:-không có})"
  cat > "$CERTS/instances.yml" <<YML
instances:
  - name: elasticsearch
    dns: [elasticsearch, localhost]
    ip: [127.0.0.1]
  - name: manager
    dns: [manager, localhost]
    ip: [127.0.0.1${MANAGER_TLS_IPS:+, $MANAGER_TLS_IPS}]
YML
  bin/elasticsearch-certutil cert --silent --pem -out "$CERTS/certs.zip" --in "$CERTS/instances.yml" \
    --ca-cert "$CERTS/ca/ca.crt" --ca-key "$CERTS/ca/ca.key"
  unzip -q -o "$CERTS/certs.zip" -d "$CERTS" && rm "$CERTS/certs.zip"
fi

# Wazuh API (55000) — tách khối riêng để hệ thống đã có chứng chỉ cũ vẫn được sinh thêm chứng chỉ này
if [ ! -f "$CERTS/wazuh-manager/wazuh-manager.crt" ]; then
  echo "[setup] tạo chứng chỉ cho wazuh-manager (Wazuh API)"
  cat > "$CERTS/instances-wazuh.yml" <<YML
instances:
  - name: wazuh-manager
    dns: [wazuh-manager, localhost]
    ip: [127.0.0.1]
YML
  bin/elasticsearch-certutil cert --silent --pem -out "$CERTS/wazuh.zip" --in "$CERTS/instances-wazuh.yml" \
    --ca-cert "$CERTS/ca/ca.crt" --ca-key "$CERTS/ca/ca.key"
  unzip -q -o "$CERTS/wazuh.zip" -d "$CERTS" && rm "$CERTS/wazuh.zip"
fi

# Quyền file: CA công khai cho mọi service; khóa CA chỉ root; khóa ES cho uid 1000; khóa manager cho uid 10001;
# khóa Wazuh API cho user wazuh (uid 999 trong image wazuh-manager)
chown -R root:root "$CERTS"
chmod 755 "$CERTS" "$CERTS"/*/
chmod 644 "$CERTS"/*/*.crt
chmod 600 "$CERTS/ca/ca.key"
chown 1000:0 "$CERTS/elasticsearch/elasticsearch.key"; chmod 600 "$CERTS/elasticsearch/elasticsearch.key"
chown 10001:0 "$CERTS/manager/manager.key";           chmod 600 "$CERTS/manager/manager.key"
chown 999:0 "$CERTS/wazuh-manager/wazuh-manager.key";  chmod 600 "$CERTS/wazuh-manager/wazuh-manager.key"

# Mật khẩu superuser cho Elasticsearch: ES yêu cầu file quyền 400/600, nhưng bind mount từ Windows luôn là 777
# -> chép vào thư mục riêng trong volume certs (chỉ container elasticsearch mount thư mục này)
mkdir -p "$CERTS/bootstrap"
install -m 600 -o 1000 -g 0 "$S/elastic_password" "$CERTS/bootstrap/elastic_password"
chown 1000:0 "$CERTS/bootstrap"; chmod 700 "$CERTS/bootstrap"

# Volume snapshot: Docker tạo thư mục của root, Elasticsearch (uid 1000) không ghi được -> repository lỗi
if [ -d /snapshots ]; then chown 1000:0 /snapshots; chmod 750 /snapshots; fi

echo "[setup] chứng chỉ sẵn sàng"
fi
[ "$MODE" = "certs" ] && exit 0

echo "[setup] chờ Elasticsearch (HTTPS)..."
until curl -s --cacert "$CERTS/ca/ca.crt" https://elasticsearch:9200 | grep -q "missing authentication credentials"; do
  sleep 5
done

EP=$(cat "$S/elastic_password")
# HTTPS đã trả lời nhưng ngay sau khi khởi động, index .security có thể chưa sẵn sàng (API security trả 503)
# -> đợi cluster tối thiểu yellow, và mỗi lệnh gọi được thử lại vài lần trước khi coi là lỗi.
echo "[setup] chờ cluster sẵn sàng..."
for i in $(seq 1 30); do
  curl -sf --cacert "$CERTS/ca/ca.crt" -u "elastic:$EP" \
       "https://elasticsearch:9200/_cluster/health?wait_for_status=yellow&timeout=10s" > /dev/null && break
  sleep 3
done
api() {  # api METHOD PATH JSON
  local out
  for i in $(seq 1 10); do
    out=$(curl -s --cacert "$CERTS/ca/ca.crt" -u "elastic:$EP" -H "Content-Type: application/json" \
               -X "$1" "https://elasticsearch:9200$2" -d "$3" -w '\n%{http_code}')
    case "${out##*$'\n'}" in 2??) return 0 ;; esac
    sleep 3
  done
  echo "[setup] LỖI khi gọi $1 $2: ${out}"
  exit 1
}
role() { api PUT "/_security/role/$1" "$2"; echo "[setup] role $1"; }
user() { api POST "/_security/user/$1" "{\"password\":\"$(cat "$S/$2")\",\"roles\":[\"$3\"],\"full_name\":\"$4\"}"; echo "[setup] user $1 -> $3"; }

META='"cluster": ["monitor", "manage_index_templates"]'
# siem-kpi: KPI tính định kỳ (manager/kpi.py); siem-hunts / siem-handovers: threat hunting, biên bản giao ca
# (manager/soc.py); siem-sources / siem-intel do SOAR ghi
role siem_manager  "{$META, \"indices\": [
  {\"names\": [\"siem-actions\", \"siem-alerts\", \"siem-cases\", \"siem-kpi\", \"siem-hunts\", \"siem-handovers\"], \"privileges\": [\"read\", \"write\", \"create_index\", \"view_index_metadata\"]},
  {\"names\": [\"siem-events-*\", \"siem-agents\", \"siem-sources\", \"siem-intel\"], \"privileges\": [\"read\", \"view_index_metadata\"]},
  {\"names\": [\"console-users\", \"siem-rules\"], \"privileges\": [\"read\", \"write\", \"create_index\", \"view_index_metadata\"]},
  {\"names\": [\"ai-*\"], \"privileges\": [\"read\", \"write\", \"create_index\", \"view_index_metadata\"]}]}"
role siem_analyzer "{$META, \"indices\": [
  {\"names\": [\"siem-events-*\", \"siem-alerts\"], \"privileges\": [\"create_index\", \"create_doc\", \"write\", \"auto_configure\", \"view_index_metadata\"]}]}"
# siem-sources: trạng thái từng nguồn log (soar/health.py); siem-intel: vòng đời IOC + dò ngược (soar/retrohunt.py)
role siem_soar     "{\"cluster\": [\"monitor\", \"manage_index_templates\", \"read_slm\"], \"indices\": [
  {\"names\": [\"siem-alerts\"], \"privileges\": [\"read\", \"write\", \"view_index_metadata\"]},
  {\"names\": [\"siem-actions\", \"siem-cases\", \"siem-agents\", \"siem-sources\", \"siem-intel\"], \"privileges\": [\"read\", \"write\", \"create_index\", \"view_index_metadata\"]},
  {\"names\": [\"siem-events-*\"], \"privileges\": [\"read\", \"view_index_metadata\"]}]}"
role siem_ai      "{\"cluster\": [\"monitor\"], \"indices\": [
  {\"names\": [\"siem-events-*\", \"siem-alerts\", \"siem-cases\"], \"privileges\": [\"read\", \"view_index_metadata\"]},
  {\"names\": [\"ai-*\"], \"privileges\": [\"read\", \"write\", \"create_index\", \"view_index_metadata\"]}]}"
role siem_reader   '{"cluster": ["monitor"], "indices": [{"names": ["siem-*"], "privileges": ["read", "view_index_metadata"]}]}'

user siem_manager  manager_es_password  siem_manager  "SIEM manager API"
user siem_analyzer analyzer_es_password siem_analyzer "SIEM analyzer"
user siem_soar     soar_es_password     siem_soar     "SIEM SOAR"
user siem_ai       ai_es_password       siem_ai       "SIEM AI worker (chỉ đọc siem-*, chỉ ghi ai-*)"
user grafana       grafana_es_password  siem_reader   "Grafana (chỉ đọc)"
user analyst       analyst_es_password  siem_reader   "SOC analyst (chỉ đọc)"

# Giữ event bao lâu: index theo ngày siem-events-YYYY.MM.DD bị xóa N ngày sau khi tạo (ILM). Template (server/siem/
# store.py) gắn policy cho index mới; index đã có được gắn ở đây. Alert, case, lệnh phản ứng không bị xóa.
DAYS=${EVENTS_RETENTION_DAYS:-30}
case "$DAYS" in ''|*[!0-9]*) echo "[setup] EVENTS_RETENTION_DAYS phải là số ngày"; exit 1 ;; esac
api PUT "/_ilm/policy/siem-events" "{\"policy\": {\"phases\": {\"hot\": {\"actions\": {}},
  \"delete\": {\"min_age\": \"${DAYS}d\", \"actions\": {\"delete\": {}}}}}}"
api PUT "/siem-events-*/_settings?allow_no_indices=true" '{"index.lifecycle.name": "siem-events"}'
echo "[setup] event giữ ${DAYS} ngày (ILM policy siem-events)"

# Sao lưu: snapshot hằng ngày bằng SLM vào repository fs (volume essnapshots). Alert, case, lệnh phản ứng, tài khoản
# console, đề xuất AI và event còn trong hạn ILM. SOAR báo HLT-007 khi bản sao lưu thành công gần nhất quá cũ
# (soar/health.py); thử khôi phục: python tools/es_snapshot.py verify (SOC-OPERATIONS.md mục 5).
SNAP_DAYS=${SNAPSHOT_RETENTION_DAYS:-30}
case "$SNAP_DAYS" in ''|*[!0-9]*) echo "[setup] SNAPSHOT_RETENTION_DAYS phải là số ngày"; exit 1 ;; esac
api PUT "/_snapshot/siem-backup" '{"type": "fs", "settings": {"location": "/usr/share/elasticsearch/snapshots", "compress": true}}'
api PUT "/_slm/policy/daily-snapshots" "{\"schedule\": \"${SNAPSHOT_SCHEDULE:-0 30 18 * * ?}\",
  \"name\": \"<siem-snap-{now/d}>\", \"repository\": \"siem-backup\",
  \"config\": {\"indices\": [\"siem-*\", \"console-users\", \"ai-*\"], \"include_global_state\": false,
               \"ignore_unavailable\": true},
  \"retention\": {\"expire_after\": \"${SNAP_DAYS}d\", \"min_count\": 3, \"max_count\": 100}}"
echo "[setup] snapshot hằng ngày (SLM daily-snapshots, lịch '${SNAPSHOT_SCHEDULE:-0 30 18 * * ?}' UTC), giữ ${SNAP_DAYS} ngày"
echo "[setup] hoàn tất"
