# Dashboard Grafana: truy vấn, số liệu, cách đọc

Tài liệu này giải thích từng dashboard Grafana của siem-xdr: nó hỏi Elasticsearch điều gì, con số nghĩa là gì, và chỗ nào dễ đọc sai.
Dashboard nằm trong `grafana/dashboards/*.json`. Các file này do `tools/gen_dashboard.py` sinh ra, đừng sửa tay: sửa generator rồi chạy lại `python tools/gen_dashboard.py`.

Console SOC nhúng 4 dashboard bằng iframe (`server/siem/manager/static/console.html`, hàm `grafanaUrl`):

| Dashboard (uid) | Trang trên console | Dùng để |
|---|---|---|
| `siem-overview` | Tổng quan | Nhìn nhanh tình hình: alert, case, log, đăng nhập, phản ứng |
| `siem-investigate` | Điều tra | Mọi thứ liên quan một thực thể (IP, máy, tài khoản) |
| `siem-rules` | Thư viện rule | Rule, ngoại lệ, đề xuất AI, so sánh đề xuất với rule hiện có |
| `soc-kpi` | KPI | Chỉ số vận hành SOC so với đích |

## 1. Cơ chế: một panel Grafana trở thành truy vấn Elasticsearch như thế nào

### 1.1 Datasource

Grafana kết nối Elasticsearch bằng user `grafana` (role `siem_reader`, chỉ đọc `siem-*`). Mỗi datasource trỏ vào một index và có một **trường thời gian** (`grafana/provisioning/datasources/elasticsearch.yml`):

| Datasource (uid) | Index | Trường thời gian |
|---|---|---|
| `siem-events` | `siem-events-*` | `@timestamp` |
| `siem-alerts` (mặc định) | `siem-alerts` | `@timestamp` |
| `siem-actions` | `siem-actions` | `created_at` |
| `siem-cases` | `siem-cases` | `created_at` |
| `siem-rules` | `siem-rules` | `@timestamp` |
| `siem-kpi` | `siem-kpi` | `@timestamp` |
| `siem-sources` | `siem-sources` | `checked_at` |

### 1.2 Bốn phần của một truy vấn

Mỗi panel có một hoặc nhiều truy vấn (A, B, C ...). Mỗi truy vấn gồm:

1. **Query (Lucene)**: chuỗi lọc, ví dụ `severity:critical AND NOT alert.shadow:true`. Grafana gói nó thành `query_string` của Elasticsearch. Để trống nghĩa là `*` (mọi bản ghi).
2. **Khoảng thời gian**: Grafana tự thêm điều kiện `range` trên **trường thời gian của datasource** (bảng trên) theo khoảng thời gian của dashboard (`now-1h`, `now-7d` ...). Console chọn khoảng này. Panel đặt `timeFrom 10y` thì bỏ qua khoảng của dashboard và nhìn 10 năm (dùng cho "case đang mở", vì case mở từ lâu vẫn là case mở).
3. **Metric**: phép tính trên các bản ghi khớp.
   - `count`: đếm bản ghi.
   - `sum`, `avg`, `max` của một trường số (ví dụ `max(mttd_critical_s)`).
   - `raw_data`: lấy nguyên các bản ghi (cho bảng), tối đa `size` dòng.
   - "Unique count" (cardinality) là đếm số giá trị khác nhau, **gần đúng** (thuật toán HyperLogLog; sai số nhỏ khi số giá trị lớn, chính xác khi dưới vài nghìn). Dashboard hiện tại không dùng; chỉ `kpi.py` dùng để đếm số analyst.
4. **Bucket**: cách chia nhóm.
   - `terms`: nhóm theo giá trị của một trường **keyword** (hoặc ip, số), lấy top `size` nhóm. Các nhóm ngoài top bị cắt, tổng các dòng có thể nhỏ hơn tổng thật.
   - `date_histogram`: chia theo thời gian (khoảng `auto` do Grafana chọn theo độ rộng panel). Trường chia là `@timestamp`.
   - `filters`: mỗi nhóm là một query riêng (dùng ở biểu đồ mã HTTP).
   - Có thể lồng: `terms` ngoài rồi `date_histogram` trong = nhiều đường, mỗi đường một giá trị.

Biến dashboard (`$q`, `$origin` ...) được thay vào chuỗi query trước khi gửi. `${q:raw}` giữ nguyên chuỗi người dùng nhập, `${proposal:lucene}` tự thoát ký tự đặc biệt.

Trường phải đúng kiểu: `terms` cần keyword/ip/số (trong siem-xdr mọi chuỗi mặc định là keyword, `server/siem/store.py`), `date_histogram` cần date, `avg/sum/max` cần số.

### 1.3 Ví dụ trọn vẹn: panel "Alert theo mức độ" (Tổng quan)

Trong JSON: datasource `siem-alerts`, query để trống, metric `count`, bucket 1 là `terms severity` (size 10, sắp theo `_count` giảm), bucket 2 là `date_histogram @timestamp auto`. Khoảng thời gian dashboard: 30/10 đến 05/11/2026.

Grafana gửi (rút gọn) tới `POST siem-alerts/_search`:

```json
{
  "size": 0,
  "query": { "bool": { "filter": [
    { "range": { "@timestamp": { "gte": "2026-10-30T00:00:00Z", "lte": "2026-11-05T00:00:00Z" } } },
    { "query_string": { "analyze_wildcard": true, "query": "*" } }
  ] } },
  "aggs": { "3": {
    "terms": { "field": "severity", "size": 10, "order": { "_count": "desc" }, "min_doc_count": 1 },
    "aggs": { "2": { "date_histogram": { "field": "@timestamp", "fixed_interval": "1d", "min_doc_count": 0 } } }
  } }
}
```

- `size: 0`: không lấy bản ghi, chỉ lấy tổng hợp.
- `range`: do khoảng thời gian dashboard. `query_string` là ô Query (ở đây `*`).
- `aggs."3"` là bucket `terms` (số 3 là `id` của bucket trong JSON). `aggs."2"` lồng bên trong là `date_histogram`.

Kết quả thật trên stack (đã rút gọn):

```
hits.total = 49
high     30 : 30/10=0, 31/10=17, 01/11=10, 02/11=1, 03/11=1, 04/11=1, 05/11=0
critical 14 : 31/10=9, 01/11=5, còn lại 0
medium    5 : 31/10=3, 01/11=2
```

Cách đọc: `hits.total` là số alert khớp (49). Mỗi phần tử của `aggregations."3".buckets` là một mức độ với `doc_count` (tổng) và bên trong có các bucket theo ngày. Grafana vẽ mỗi mức độ thành một đường; ô "Tổng alert" chỉ khác ở chỗ bỏ bucket `terms`. Chú ý: 49 alert này chưa loại alert chạy bóng, health, RBA (mục 5).

### 1.4 Tự xem truy vấn

- Trong Grafana: bấm tiêu đề panel, chọn **Inspect > Query** rồi **Refresh**: thấy đúng body gửi đi và phản hồi. Tab **Data** cho xem bảng kết quả, **Panel JSON** cho xem cấu hình.
- Bằng dòng lệnh, chỉ đọc (thay mật khẩu bằng nội dung secret `grafana_es_password`, đừng in ra màn hình):

```bash
docker exec siem-xdr-elasticsearch-1 curl -sk -u "grafana:$MATKHAU" \
  https://localhost:9200/siem-alerts/_search -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"query_string":{"query":"severity:critical"}},"aggs":{"s":{"terms":{"field":"rule.id"}}}}'
```

- Xem kiểu của một trường: `GET siem-alerts/_field_caps?fields=severity,priority`. Trường không có trong kết quả nghĩa là chưa có bản ghi nào mang trường đó.

## 2. Dashboard "Tổng quan SOC" (`siem-overview`)

- **Dùng để**: nhìn nhanh trong ngày. Trang đầu của console; Grafana cũng đặt làm trang chủ.
- **Ai dùng**: mọi vai trò, nhất là analyst trực ca.
- **Khoảng thời gian**: mặc định 1 giờ, tự làm mới 30 giây; console cho chọn 1 giờ, 24 giờ, 7 ngày, 30 ngày. **Biến**: không có.
- Bảng alert / case có liên kết "Mở trên SOC console" dẫn tới `/go/alert/<alert.id>` hoặc `/go/case/<id>`.

**Hàng: Tổng quan**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Tổng event (không tính console/phản ứng) | Số event log hệ thống trong khoảng thời gian đang chọn. | siem-events-* | `NOT event.module:(console OR siem-xdr)` | count / date_histogram theo thời gian | Loại event nội bộ của nền tảng (`console` = đăng nhập/đăng xuất giao diện SOC, `siem-xdr` = kết quả phản ứng). |
| Tổng alert | Số alert phát hiện trong khoảng. | siem-alerts | `(NOT alert.source:health) AND NOT alert.shadow:true` | count / date_histogram theo thời gian | Không gồm alert chạy bóng và alert sức khỏe nền tảng (HLT, xem *SOC KPI*). Vẫn gồm alert RBA (có ô riêng bên cạnh). |
| Alert nghiêm trọng | Số alert mức nghiêm trọng (critical). | siem-alerts | `((severity:critical) AND NOT alert.source:health) AND NOT alert.shadow:true` | count / date_histogram theo thời gian | Cùng quy ước với "Tổng alert". |
| Alert mức cao | Số alert mức cao (high). | siem-alerts | `((severity:high) AND NOT alert.source:health) AND NOT alert.shadow:true` | count / date_histogram theo thời gian | Cùng quy ước. |
| Alert RBA (cộng dồn rủi ro) | Số alert RBA (`alert.source:rba`), sinh khi điểm rủi ro của một thực thể vượt ngưỡng. | siem-alerts | `(alert.source:rba) AND NOT alert.shadow:true` | count / date_histogram theo thời gian | Cộng dồn từ alert khác nên cùng hoạt động có thể đếm hai lần (một lần ở alert gốc, một lần ở RBA). |
| Alert chạy bóng | Số alert của rule đang đo thử (`alert.shadow:true`). | siem-alerts | `alert.shadow:true` | count / date_histogram theo thời gian | Không tính vào mọi số alert khác, không mở case, không phản ứng. Chỉ để thấy lượng đo thử. |
| Case đang mở | Số case chưa đóng (mở, đang xử lý, đã khoanh vùng) tính toàn bộ lịch sử. | siem-cases | `status:(open OR in_progress OR contained)` | count / date_histogram theo thời gian | `timeFrom 10y`: bỏ qua khoảng thời gian của dashboard. "Đã khoanh vùng" vẫn tính là còn mở. |
| Lệnh phản ứng XDR | Số lệnh phản ứng XDR (block IP, kill process, cô lập máy ...) được tạo trong khoảng. | siem-actions | `*` | count / date_histogram theo thời gian | Tính mọi trạng thái, cả `failed`. |
| Alert theo mức độ | Đường theo thời gian của số alert, mỗi mức độ một đường. | siem-alerts | `(NOT alert.source:health) AND NOT alert.shadow:true` | count / terms `severity` top 10; date_histogram theo thời gian | `terms severity` rồi `date_histogram`: đọc từng đường như một series. |
| Event theo loại (event.category) | Số event theo `event.category`. | siem-events-* | `*` | count / terms `event.category` top 12 | Top 12; phần còn lại bị cắt. |

**Hàng: Phát hiện (Detection)**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Top rule kích hoạt | Rule sinh nhiều alert nhất. | siem-alerts | `(NOT alert.source:health) AND NOT alert.shadow:true` | count / terms `rule.name` top 15 | Gom theo `rule.name`, không phải mã rule: tên có phần biến đổi (đường dẫn file) thì tách thành nhiều dòng. Top 15. |
| MITRE ATT&CK tactic | Số alert theo tactic MITRE. | siem-alerts | `(NOT alert.source:health) AND NOT alert.shadow:true` | count / terms `rule.mitre.tactic` top 10 | Alert không có tactic không có dòng nào (HLT đã bị loại khỏi query). Rule Wazuh chỉ ghi tactic đầu. |
| Top IP tấn công (từ alert) | IP nguồn xuất hiện nhiều nhất trong alert. | siem-alerts | `(NOT alert.source:health) AND NOT alert.shadow:true` | count / terms `source.ip` top 10 | Có thể là IP nội bộ / cổng Docker, không hẳn kẻ tấn công. |
| Host bị nhắm tới | Máy bị nhắm tới nhiều nhất (`host.name` của alert). | siem-alerts | `(NOT alert.source:health) AND NOT alert.shadow:true` | count / terms `host.name` top 10 | Một máy có thể mang nhiều tên (`web-01`, `web01`). |
| Alert mới nhất — bấm tên rule để mở trên console | 200 alert mới nhất, bấm tên rule để mở trên console. | siem-alerts | `NOT alert.shadow:true` | raw_data 200 dòng | Cột `alert.id` ẩn dùng cho liên kết `/go/alert/<id>`. Chỉ 200 dòng. Giữ cả alert RBA và HLT, chỉ bỏ alert bóng. |

**Hàng: Telemetry**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| HTTP status code (Apache) | Số request Apache theo nhóm mã HTTP (2xx, 3xx, 4xx, 5xx). | siem-events-* | `event.module:apache` | count / filters: 2xx thành công = `http.response.status_code:[200 TO 299]`, 3xx chuyển hướng = `http.response.status_code:[300 TO 399]`, 4xx lỗi phía client = `http.response.status_code:[400 TO 499]`, 5xx lỗi máy chủ = `http.response.status_code:[500 TO 599]`; date_histogram theo thời gian | Request không có mã không rơi vào nhóm nào. |
| IP xác thực thất bại nhiều nhất | IP có nhiều lần xác thực thất bại nhất. | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr) AND event.outcome:failure` | count / terms `source.ip` top 10 | Chỉ log hệ thống, không gồm đăng nhập console SOC. |
| Nguồn dữ liệu (event.module) | Số event theo nguồn (`event.module`). | siem-events-* | `*` | count / terms `event.module` top 10 | Dùng để biết nguồn nào đang gửi log; "console" và "siem-xdr" là nội bộ. |
| Top URL bị truy cập | URL được truy cập nhiều nhất. | siem-events-* | `event.category:web` | count / terms `url.path` top 15 | Chỉ event web; `url.path` chưa gồm tham số. |
| Kết nối bị firewall chặn (IP nguồn) | IP nguồn bị firewall chặn (`event.action:deny`). | siem-events-* | `event.action:deny` | count / terms `source.ip` top 10 | Rỗng nếu chưa có log firewall (pf / iptables). |

**Hàng: Phiên đăng nhập**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Đăng nhập hệ thống thành công | Số đăng nhập thành công vào máy (ssh, PAM, Windows). | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr) AND event.outcome:success` | count / date_histogram theo thời gian | Không gồm đăng nhập console SOC (ô riêng bên phải). Là 0 khi chưa có log ssh / Windows. |
| Đăng nhập hệ thống thất bại | Số đăng nhập thất bại vào máy. | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr) AND event.outcome:failure` | count / date_histogram theo thời gian | Như trên. |
| Đặc quyền đăng nhập hệ thống được (root/Administrator/admin) | Đăng nhập thành công bằng tài khoản root / Administrator / admin trên máy. | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr) AND event.outcome:success AND user.name:(root OR Administrator OR admin)` | count / date_histogram theo thời gian | Khớp đúng chữ hoa thường (keyword). Trước đây ô tên "Tài khoản đặc quyền đăng nhập được" thực chất đếm `admin` đăng nhập console; nay đã tách console ra. |
| Đăng nhập form web bị từ chối | POST vào URL có chữ `login` bị trả 401/403. | siem-events-* | `event.category:web AND http.request.method:POST AND url.path:*login* AND http.response.status_code:(401 OR 403)` | count / date_histogram theo thời gian | Dấu hiệu dò mật khẩu form web. `*login*` có ký tự đại diện đầu nên chậm với dữ liệu lớn. |
| Đăng nhập console SOC thành công | Số lần analyst đăng nhập giao diện SOC. | siem-events-* | `event.category:authentication AND event.module:console AND event.outcome:success` | count / date_histogram theo thời gian | Event do chính console phát ra, không phải log hệ thống. |
| Đăng nhập console SOC thất bại | Số lần đăng nhập console sai mật khẩu. | siem-events-* | `event.category:authentication AND event.module:console AND event.outcome:failure` | count / date_histogram theo thời gian | Nên theo dõi: dò mật khẩu vào chính SOC. |
| Đăng nhập hệ thống theo kết quả | Đăng nhập hệ thống theo thời gian, tách `success` / `failure`. | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr)` | count / terms `event.outcome` top 10; date_histogram theo thời gian | Hai đường; so sánh tỉ lệ. |
| IP đăng nhập form web nhiều nhất | IP gửi POST vào URL `login` nhiều nhất. | siem-events-* | `event.category:web AND http.request.method:POST AND url.path:*login*` | count / terms `source.ip` top 10 | Không lọc theo mã trả về. |
| Tài khoản đăng nhập thất bại nhiều nhất | Tài khoản bị đăng nhập thất bại nhiều nhất. | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr) AND event.outcome:failure` | count / terms `user.name` top 10 | Tên tài khoản bịa (vd `khong-co-ai`) cũng hiện. |
| IP nguồn đăng nhập thành công | IP đăng nhập thành công nhiều nhất. | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr) AND event.outcome:success` | count / terms `source.ip` top 10 | — |
| Đăng nhập theo máy | Số event đăng nhập hệ thống theo máy (`host.name`). | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr)` | count / terms `host.name` top 10 | — |
| Hình thức đăng nhập | Số event đăng nhập hệ thống theo `event.action`. | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr)` | count / terms `event.action` top 10 | — |
| Phiên đăng nhập gần đây | 200 sự kiện đăng nhập gần nhất (hệ thống và form web, không gồm console). | siem-events-* | `event.category:authentication AND NOT event.module:(console OR siem-xdr) OR (event.category:web AND http.request.method:POST AND url.path:*login*)` | raw_data 200 dòng | Cột `auth.method`, `winlog.logon.type` chỉ có khi nguồn log có. |

**Hàng: Phản ứng (XDR / SOAR)**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Lệnh phản ứng gần đây | 200 lệnh phản ứng mới nhất. | siem-actions | `*` | raw_data 200 dòng | Cột `output` là kết quả chạy trên agent. |
| Case đang mở — bấm tiêu đề để mở trên console | Các case chưa đóng, bấm tiêu đề để mở trên console. | siem-cases | `status:(open OR in_progress OR contained)` | raw_data 200 dòng | `timeFrom 10y`. 200 dòng. |

## 3. Dashboard "Điều tra thực thể" (`siem-investigate`)

- **Dùng để**: sau khi chọn một IP, máy hoặc tài khoản, xem mọi event và alert liên quan.
- **Biến duy nhất**: `q` (Lucene, mặc định `*`). Console gửi `var-q` qua URL. Mỗi query là `(${q:raw})` và có thể nối thêm điều kiện. Ví dụ console đổi một IP thành `source.ip:"1.2.3.4" OR destination.ip:"1.2.3.4"`, một tên thành `host.name:"x" OR user.name:"x" OR agent.name:"x"`. Dấu ngoặc giữ cho `OR` không phá điều kiện nối thêm.
- Cùng một `q` được dùng cho cả index event và alert, nên chỉ nên dùng trường có ở cả hai (`source.ip`, `host.name`, `user.name`). Dùng trường chỉ có ở event (vd `process.name`) thì các ô alert về 0.
- Khoảng thời gian mặc định 24 giờ.

**Hàng: Thực thể: ${q}**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Event | Số event khớp thực thể trong biến q. | siem-events-* | `(${q:raw})` | count / date_histogram theo thời gian | — |
| Alert | Số alert khớp q. | siem-alerts | `((${q:raw})) AND NOT alert.shadow:true` | count / date_histogram theo thời gian | Không gồm alert bóng (cùng mặc định với console). Vẫn gồm RBA và HLT vì chúng có thể nói về chính thực thể này. |
| Alert nghiêm trọng / cao | Số alert critical hoặc high khớp q. | siem-alerts | `((${q:raw}) AND severity:(critical OR high)) AND NOT alert.shadow:true` | count / date_histogram theo thời gian | — |
| Đăng nhập thất bại (cả console) | Số đăng nhập thất bại khớp q. | siem-events-* | `(${q:raw}) AND event.category:authentication AND event.outcome:failure` | count / date_histogram theo thời gian | Cố ý gồm cả đăng nhập console: điều tra tài khoản `admin` phải thấy các lần sai mật khẩu vào console. |
| Event theo loại | Event của thực thể, nhóm theo loại. | siem-events-* | `(${q:raw})` | count / terms `event.category` top 12 | — |
| Alert theo mức độ | Alert của thực thể theo mức độ, theo thời gian. | siem-alerts | `((${q:raw})) AND NOT alert.shadow:true` | count / terms `severity` top 10; date_histogram theo thời gian | — |
| Hành động (event.action) | Hành động (`event.action`) của thực thể. | siem-events-* | `(${q:raw})` | count / terms `event.action` top 10 | Top 10. |
| URL bị truy cập | URL thực thể truy cập. | siem-events-* | `(${q:raw}) AND event.category:web` | count / terms `url.path` top 10 | Chỉ event web. |
| Tiến trình | Tiến trình do thực thể chạy. | siem-events-* | `(${q:raw}) AND event.category:process` | count / terms `process.name` top 10 | Chỉ event process. |
| IP liên quan | IP nguồn xuất hiện cùng thực thể. | siem-events-* | `(${q:raw})` | count / terms `source.ip` top 10 | Chỉ `source.ip`, không có `destination.ip`. |
| Alert của thực thể — bấm tên rule để mở trên console | Alert của thực thể, bấm tên rule mở trên console. | siem-alerts | `((${q:raw})) AND NOT alert.shadow:true` | raw_data 200 dòng | 200 dòng. Ẩn alert bóng để khớp số ở các ô trên; xem alert bóng ở console. |
| Event gần đây | 200 event gần nhất của thực thể. | siem-events-* | `(${q:raw})` | raw_data 200 dòng | — |

## 4. Dashboard "Thư viện rule" (`siem-rules`)

- **Dùng để**: tra rule đang chạy (YAML và Wazuh), ngoại lệ, đề xuất AI; so sánh một đề xuất với rule hiện có. Khoảng thời gian `now-20y` (ẩn trên console) vì `@timestamp` của bản ghi thư viện là ngày sửa file / ngày đề xuất, không phải thời điểm xảy ra sự kiện.
- **Ai dùng**: Detection Engineer, người duyệt đề xuất AI.
- Dữ liệu do `server/siem/rules_catalog.py` ghi vào index `siem-rules` mỗi `RULES_CATALOG_SECONDS` (60 giây) khi có thay đổi. Mỗi bản ghi có `origin`: `rule` (rule YAML / AI đã duyệt), `wazuh_rule` (rule Wazuh, nhánh hợp nhất rule), `ai_proposal`, `exception`, `comparison` (cặp đề xuất - rule), `detector` (RBA / HLT), `coverage` (độ phủ ATT&CK).
- Rule Wazuh (`origin:wazuh_rule`) có `source:wazuh`, `mode` (`active`, `shadow`, `nobridge` = không bao giờ ra alert, `off` = đã tắt), `shadow` (true / false), `bridged` (có qua cầu nối sinh alert không). Mã rule `WZH-<id Wazuh>`.
- **Sáu biến**:

| Biến | Loại | Nghĩa |
|---|---|---|
| `origin` | chọn một | Loại bản ghi; mặc định "Tất cả" = `(rule OR wazuh_rule OR ai_proposal OR exception)`; "Rule YAML của dự án" = `rule` |
| `tactic` | nhiều giá trị | Lọc theo `mitre.tactic`; lấy từ `terms` của index, tối đa 300 giá trị |
| `tag` | nhiều giá trị | Lọc theo `tags`; tối đa 300 giá trị |
| `field` | nhiều giá trị | Lọc theo trường log rule xét (`fields`) |
| `q` | ô nhập | Lucene tự do, mặc định `*` |
| `proposal` | chọn một | Đề xuất cần so sánh (giá trị là nhãn `proposal.pick`); console điền sẵn khi mở từ trang đề xuất |

- "Tất cả" của `tactic`, `tag`, `field` là `*`, tức điều kiện `mitre.tactic:* AND tags:* AND fields:*` đòi bản ghi **có** cả ba trường. Chạy được vì thư viện ghi giá trị giữ chỗ (`(chưa gắn)`, `—`) khi rule không có tactic / tag / trường.

**Hàng: Tổng quan thư viện (rule YAML + rule Wazuh)**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Rule đang chạy (YAML + Wazuh, tạo alert thật) | Số rule đang tạo alert thật. | siem-rules | `origin:(rule OR wazuh_rule) AND mode:active` | count / date_histogram theo thời gian | Gồm cả hai nguồn nên vẫn đúng khi tắt engine YAML (Task 18). Không gồm rule chạy bóng. |
| Rule chạy bóng (đo thử, không ra alert thật) | Số rule đang đo thử. | siem-rules | `origin:(rule OR wazuh_rule) AND mode:shadow` | count / date_histogram theo thời gian | Rule bóng ra alert gắn `alert.shadow`, SOAR bỏ qua. |
| Rule Wazuh không cầu nối (không ra alert) | Số rule Wazuh không bao giờ ra alert. | siem-rules | `origin:(rule OR wazuh_rule) AND mode:nobridge` | count / date_histogram theo thời gian | Rule Wazuh không đi qua cầu nối sinh alert. |
| Rule đã tắt | Số rule tắt. | siem-rules | `origin:(rule OR wazuh_rule) AND mode:off` | count / date_histogram theo thời gian | — |
| Rule Wazuh (tổng, mọi chế độ) | Số rule Wazuh trong thư viện. | siem-rules | `origin:wazuh_rule` | count / date_histogram theo thời gian | Gồm cả `nobridge`, `off`, `shadow`: đây là tổng kho rule Wazuh, không phải số rule đang chạy. |
| Rule im lặng 7 ngày (đang chạy) | Số rule đang chạy không sinh alert nào trong 7 ngày. | siem-rules | `origin:(rule OR wazuh_rule) AND mode:active AND alerts.d7:0` | count / date_histogram theo thời gian | Rule im lặng có thể là rule chết hoặc chỉ là chưa gặp tấn công. Rule tắt / bóng / không cầu nối không tính. |
| Rule do AI viết (đã duyệt) | Số rule YAML do AI viết đã được duyệt (`source:ai`). | siem-rules | `origin:rule AND source:ai` | count / date_histogram theo thời gian | Chỉ rule YAML. |
| Ngoại lệ đang áp dụng | Số ngoại lệ đang áp dụng. | siem-rules | `origin:exception` | count / date_histogram theo thời gian | — |
| Đề xuất AI chờ duyệt | Số đề xuất AI còn chờ duyệt. | siem-rules | `origin:ai_proposal AND proposal.status:pending` | count / date_histogram theo thời gian | — |
| Đề xuất không đạt kiểm định | Số đề xuất có trạng thái `invalid`. | siem-rules | `origin:ai_proposal AND proposal.status:invalid` | count / date_histogram theo thời gian | Cùng định nghĩa với dòng "không đạt kiểm định" của biểu đồ trạng thái bên dưới. Gồm cả đề xuất đã vượt kiểm định nhưng sau đó thành không hợp lệ (vd rule đích đã đổi). |
| Rule đang chạy theo MITRE tactic | Số rule đang chạy theo tactic MITRE. | siem-rules | `origin:(rule OR wazuh_rule) AND mode:active` | count / terms `mitre.tactic` top 10 | Top 10. Gồm cả rule Wazuh. |
| Đề xuất AI theo trạng thái | Số đề xuất AI theo trạng thái. | siem-rules | `origin:ai_proposal` | count / terms `proposal.status_label` top 10 | — |
| Rule kêu nhiều nhất (7 ngày): mã rule và tên | Rule kêu nhiều nhất 7 ngày (tổng `alerts.d7`). | siem-rules | `origin:(rule OR wazuh_rule) AND alerts.d7:>0` | sum(alerts.d7) / terms `rule.id` top 10 (theo metric), rồi terms `rule.name` size 1 | Gom theo mã rule (ổn định), tên là cột thứ hai. Không lọc `mode`: rule bóng vẫn ra alert nên cũng hiện. `sum` rồi sắp theo kết quả metric (`orderBy 1`). |

**Hàng: Danh sách rule, ngoại lệ, đề xuất AI — lọc bằng các ô phía trên**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Rule và đề xuất AI — bấm mã rule xem cảnh báo của rule, bấm trạng thái đề xuất để mở trên console | Bảng rule, ngoại lệ, đề xuất AI, lọc bằng các biến phía trên. | siem-rules | `origin:${origin:raw} AND mitre.tactic:$tactic AND tags:$tag AND fields:$field AND (${q:raw})` | raw_data 500 dòng | Tối đa 500 dòng. Bấm mã rule xem alert của rule, bấm trạng thái đề xuất để mở trên console. |

**Hàng: So sánh đề xuất AI với rule hiện có — chọn đề xuất ở ô “Đề xuất cần so sánh”**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Đề xuất đã chọn | Chi tiết đề xuất AI đang chọn ở biến `proposal`. | siem-rules | `origin:ai_proposal AND proposal.pick:${proposal:lucene}` | raw_data 200 dòng | Dùng `${proposal:lucene}` để thoát ký tự đặc biệt trong tên đề xuất. |
| Rule hiện có liên quan — điều kiện hai bên đặt cạnh nhau, xếp theo mức liên quan | Rule hiện có gần với đề xuất đã chọn, điều kiện hai bên đặt cạnh nhau. | siem-rules | `origin:comparison AND proposal.pick:${proposal:lucene}` | raw_data 200 dòng | Xếp theo cột "Mức liên quan" giảm dần; cột "Vì sao liên quan" giải thích. |

## 5. Dashboard "SOC KPI" (`soc-kpi`)

- **Dùng để**: theo dõi chỉ số vận hành SOC so với đích (SOC-OPERATIONS.md mục 7).
- **Ai dùng**: SOC lead, người quản lý.
- **Cách hoạt động**: `server/siem/manager/kpi.py` tính KPI trên cửa sổ **30 ngày** mỗi 5 phút (`KPI_SECONDS`) và ghi một bản ghi vào `siem-kpi`. Hàng "Chỉ số chính" hiện giá trị của bản ghi **mới nhất** (`reduce lastNotNull`), tô màu theo đích giai đoạn 2 / 4. Hàng "Xu hướng" vẽ từng bản ghi theo thời gian. Mọi KPI đều là số tính sẵn, nên metric ở đây là `max` của trường tương ứng (mỗi bucket thường chỉ có một bản ghi).
- Công thức (trích kpi.py): MTTD = trung bình `metrics.ttd_seconds` của alert critical **phát hiện** (R62: `alert.source` rule / wazuh / ml, không bóng; loại rba, health, dò ngược TI-002); MTTA / MTTC = trung bình `metrics.tta_seconds` / `ttc_seconds` của case tạo trong 30 ngày; SLA = (xác nhận đúng hạn + khoanh vùng đúng hạn) / (các case đã có kết quả + case quá hạn chưa nhận); báo nhầm = alert `false_positive` / alert `closed` + `false_positive`; tải = alert / (số analyst × số ngày có alert × số ca mỗi ngày); làm giàu = alert có `asset.id` / tổng alert.
- Khoảng thời gian mặc định 7 ngày, làm mới 5 phút. Panel đặt `timeFrom 10y` (case quá hạn, nguồn log, sự cố nền tảng, độ phủ) là trạng thái hiện tại, không theo khoảng.

**Hàng: Chỉ số chính (30 ngày gần nhất) — xanh: đạt đích giai đoạn 4, vàng: đạt giai đoạn 2, đỏ: chưa đạt**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| MTTD alert critical | MTTD của alert critical: trung bình giây từ event đầu của chuỗi tới lúc sinh alert. | siem-kpi | `*` | max(mttd_critical_s) / date_histogram theo thời gian | Giá trị mới nhất của KPI 30 ngày. Xanh dưới 15 phút, vàng từ 15 đến 30 phút, đỏ từ 30 phút. Chỉ alert phát hiện (R62): không tính RBA, health, dò ngược TI-002. |
| MTTA case P1 | MTTA case P1: trung bình giây từ lúc mở case tới khi có người nhận. | siem-kpi | `*` | max(mtta_p1_s) / date_histogram theo thời gian | Không có số nếu chưa có case P1 nào được nhận. |
| MTTC case P1 | MTTC case P1: từ lúc mở case tới khi khoanh vùng xong. | siem-kpi | `*` | max(mttc_p1_s) / date_histogram theo thời gian | Như trên. |
| Tuân thủ SLA | % case đạt SLA xác nhận / khoanh vùng. | siem-kpi | `*` | max(sla_pct) / date_histogram theo thời gian | Xanh từ 95, vàng từ 85, đỏ dưới 85. |
| Tỉ lệ báo nhầm | Alert kết luận báo nhầm / alert đã đóng (%), chỉ alert phát hiện (R62). | siem-kpi | `*` | max(fp_rate_pct) / date_histogram theo thời gian | Không có số nếu chưa đóng alert nào trong 30 ngày. |
| Alert / analyst / ca | Alert phát hiện (R62) trung bình mỗi analyst mỗi ca. | siem-kpi | `*` | max(alerts_per_analyst_shift) / date_histogram theo thời gian | Tải công việc; xanh dưới 40, vàng 40 đến 60, đỏ từ 60. |
| Làm giàu tự động | % alert phát hiện (R62) có ngữ cảnh tài sản (`asset.id`). | siem-kpi | `*` | max(enrichment_pct) / date_histogram theo thời gian | — |
| Độ phủ ATT&CK ưu tiên | % kỹ thuật ATT&CK ưu tiên có rule đang chạy chính thức. | siem-kpi | `*` | max(attack_coverage_pct) / date_histogram theo thời gian | Danh sách chi tiết ở bảng cuối trang. |
| Sức khỏe nguồn log | % nguồn log đã onboard không im lặng. | siem-kpi | `*` | max(source_health_pct) / date_histogram theo thời gian | — |
| Hunt hoàn thành / tháng | Số cuộc threat hunting hoàn thành trong 30 ngày. | siem-kpi | `*` | max(hunts_month) / date_histogram theo thời gian | Đích ≥ 2. |

**Hàng: Xu hướng**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Thời gian phát hiện / nhận / khoanh vùng | Xu hướng MTTD / MTTA P1 / MTTC P1 / MTTA mọi mức, đơn vị giây. | siem-kpi | A: `*`<br>B: `*`<br>C: `*`<br>D: `*` | A: max(mttd_critical_s) / date_histogram theo thời gian<br>B: max(mtta_p1_s) / date_histogram theo thời gian<br>C: max(mttc_p1_s) / date_histogram theo thời gian<br>D: max(mtta.all) / date_histogram theo thời gian | Bốn truy vấn A-D, mỗi cái `max` theo bucket. |
| Tỉ lệ (%) | Xu hướng các KPI phần trăm (SLA, báo nhầm, làm giàu, độ phủ, nguồn log). | siem-kpi | A: `*`<br>B: `*`<br>C: `*`<br>D: `*`<br>E: `*` | A: max(sla_pct) / date_histogram theo thời gian<br>B: max(fp_rate_pct) / date_histogram theo thời gian<br>C: max(enrichment_pct) / date_histogram theo thời gian<br>D: max(attack_coverage_pct) / date_histogram theo thời gian<br>E: max(source_health_pct) / date_histogram theo thời gian | Năm truy vấn A-E. |

**Hàng: Chất lượng cảnh báo phát hiện (rule/wazuh/ml, không bóng; theo khoảng thời gian của dashboard)**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Kết luận khi đóng alert | Alert đã đóng, nhóm theo kết luận (`alert.verdict`). | siem-alerts | `((alert.status:(closed OR false_positive)) AND alert.source:(rule OR wazuh OR ml)) AND NOT alert.shadow:true` | count / terms `alert.verdict` top 10 | Chỉ alert phát hiện (R62). Chỉ có dữ liệu với alert đóng sau khi có trường kết luận. |
| Rule báo nhầm nhiều nhất | Rule có nhiều alert báo nhầm nhất. | siem-alerts | `((alert.status:false_positive) AND alert.source:(rule OR wazuh OR ml)) AND NOT alert.shadow:true` | count / terms `rule.id` top 10 | Đếm số lượng, không phải tỉ lệ; hiện mã rule. Chỉ alert phát hiện (R62). |
| Alert theo mức ưu tiên | Alert phát hiện theo mức ưu tiên P1-P4. | siem-alerts | `(alert.source:(rule OR wazuh OR ml)) AND NOT alert.shadow:true` | count / terms `priority` top 10 (theo tên, tăng dần) | Chỉ alert phát hiện (R62), không bóng. Sắp theo tên P1 → P4. Alert cũ chưa có `priority` không hiện. |
| MTTA theo mức ưu tiên (case) | MTTA trung bình theo mức ưu tiên của case. | siem-cases | `_exists_:metrics.tta_seconds` | avg(metrics.tta_seconds) / terms `priority` top 10 (theo tên, tăng dần) | `avg(metrics.tta_seconds)` chỉ trên case đã có giá trị. |
| Case quá hạn xác nhận (chưa ai nhận) — bấm tiêu đề để mở trên console | Case quá hạn xác nhận mà chưa ai nhận. | siem-cases | `status:(open OR in_progress OR contained) AND NOT _exists_:acknowledged_at AND sla_due:<now` | raw_data 200 dòng | `sla_due < now` là hạn xác nhận. `timeFrom 10y`. |

**Hàng: Nguồn log (soar/health.py, cập nhật mỗi phút)**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Sự cố nền tảng đang mở | Số sự cố nền tảng (alert `health`) còn mở. | siem-alerts | `alert.source:health AND alert.status:(open OR acknowledged OR in_progress)` | count / date_histogram theo thời gian | `timeFrom 10y`. |
| Trạng thái từng nguồn | Trạng thái từng nguồn log (do `soar/health.py` cập nhật mỗi phút). | siem-sources | `*` | raw_data 200 dòng | `status`: ok / deviation / silent. `timeFrom 10y`. |

**Hàng: Độ phủ kỹ thuật ATT&CK ưu tiên (server/config/threat_profile.yml)**

| Panel | Hiển thị | Index | Query | Metric và bucket | Cách đọc, lưu ý |
|---|---|---|---|---|---|
| Kỹ thuật ưu tiên và rule phát hiện | Danh sách kỹ thuật ATT&CK ưu tiên và rule đang phủ. | siem-rules | `origin:coverage` | raw_data 200 dòng | Bản ghi `origin:coverage`. Rule hiện tối đa 10 mã, phần còn lại ghi `(+n)`. Bỏ qua khoảng thời gian dashboard (`timeFrom 10y`). |

## 6. Mô hình dữ liệu phía sau

Dữ liệu đi: Wazuh (agent + manager) → Kafka → analyzer (Python, chuẩn hóa, phát hiện) → Elasticsearch. Mapping và template ở `server/siem/store.py`: chuỗi mặc định thành keyword (`ignore_above 2048`); các trường dài như `message`, `command_line` có thêm trường con `.text` để tìm toàn văn.

| Index | Ai ghi | Trường chính (dùng trong dashboard) |
|---|---|---|
| `siem-events-*` | analyzer (`pipeline/normalize.py`) | `@timestamp`, `event.category` (authentication, web, process, host, iam ...), `event.outcome` (success / failure), `event.module` (apache, syslog, console ...), `event.action`, `source.ip` (kiểu ip), `user.name`, `host.name`, `url.path`, `http.request.method`, `http.response.status_code` (số), `process.name`, `message` |
| `siem-alerts` | analyzer (`detection/alerts.py`, `detection/wazuh.py`), SOAR (`soar/risk.py`, `soar/health.py`, `soar/retrohunt.py`) | `@timestamp`, `severity` (critical / high / medium / low), `priority` (P1-P4), `rule.id`, `rule.name`, `rule.mitre.tactic`, `risk_score`, `alert.id`, `alert.status` (open, acknowledged, in_progress, closed, false_positive), `alert.verdict`, `alert.source` (rule, wazuh, ml, rba, health), `alert.shadow` (true nếu rule chạy bóng), `rule.mode`, `metrics.ttd_seconds`, `asset.id`, `source.ip`, `host.name`, `user.name` |
| `siem-cases` | manager (`manager/api.py`) | `created_at`, `id`, `title`, `entity`, `priority`, `severity`, `status` (open, in_progress, contained, closed, false_positive), `alert_count`, `assignee`, `acknowledged_at`, `sla_due` (hạn xác nhận), `contain_due`, `sla.ack_met`, `sla.contain_met`, `metrics.tta_seconds`, `metrics.ttc_seconds` |
| `siem-actions` | SOAR (`soar/*`), console | `created_at`, `type` (block_ip, unblock_ip, kill_process, isolate_host ...), `target`, `agent_id`, `source` (soar / manual), `status` (success / failed ...), `expires_at`, `output` |
| `siem-rules` | manager (`rules_catalog.py`) | `origin`, `rule.id`, `rule.name`, `severity`, `mode`, `mitre.tactic`, `tags`, `fields`, `alerts.h24` / `d7` / `d90` / `fp_rate30`, `proposal.*` (`status`, `passed`, `pick` ...), `shadow`, `bridged`, `score` |
| `siem-kpi` | manager (`manager/kpi.py`) | Một bản ghi mỗi 5 phút: `mttd_critical_s`, `mtta_p1_s`, `mttc_p1_s`, `mtta.all`, `sla_pct`, `fp_rate_pct`, `alerts_per_analyst_shift`, `enrichment_pct`, `attack_coverage_pct`, `source_health_pct`, `hunts_month`, kèm `grade` và `targets` |
| `siem-sources` | SOAR (`soar/health.py`) | `source`, `host`, `status` (ok / deviation / silent), `last_event`, `expected_per_hour`, `last_hour`, `events_7d`, `checked_at` |

Hiểu đúng mấy khái niệm hay nhầm:

- **Alert chạy bóng** (`alert.shadow:true`): rule mới hoặc rule gốc Wazuh chưa được tin cậy vẫn sinh alert để đo, nhưng SOAR bỏ qua và console ẩn mặc định. KPI không tính. Alert bóng nằm cùng index `siem-alerts`; mọi ô đếm alert trên Grafana đều có `NOT alert.shadow:true`, riêng ô "Alert chạy bóng" của Tổng quan đếm chúng.
- **`alert.source`**: `rule` (rule YAML), `wazuh` (rule Wazuh, mã `WZH-<id>`), `ml` (Isolation Forest), `rba` (cộng dồn rủi ro nhiều alert trên một máy / tài khoản), `health` (sự cố nền tảng HLT-*).
- **MTTD** (`metrics.ttd_seconds`): từ event đầu của chuỗi tới lúc sinh alert. **MTTA / MTTC** (`metrics.tta_seconds` / `ttc_seconds` của case): từ lúc mở case tới khi có người nhận / khoanh vùng xong. **P1-P4** là mức ưu tiên = mức độ rule kết hợp độ quan trọng tài sản (SOC-OPERATIONS.md mục 2).
- **Báo nhầm** chỉ tính alert có trạng thái `false_positive` (mục 3 SOC-OPERATIONS.md). Alert `closed` với kết luận `duplicate` hay `benign_true_positive` không là báo nhầm.

## 7. Vấn đề đã biết

Đây là tóm tắt kết quả kiểm tra ngày 05/11/2026 (mọi query đã chạy thử trên stack thật; không panel nào lỗi cú pháp hay sai kiểu trường). Bản đầy đủ có bằng chứng và đề nghị sửa nằm ở `.superpowers/sdd/2026-10-31-wazuh-unified-ruleset/dashboards-audit.md` trong thư mục kế hoạch.

**Đã sửa (05/11/2026, nhánh `wzh/dash-fix`)**

- **C1. MTTD critical bị RBA kéo lên.** `kpi.py` chỉ tính alert phát hiện (`alert.source` rule / wazuh / ml, không bóng) cho MTTD, làm giàu, tải analyst, báo nhầm (R62, SOC-OPERATIONS.md mục 7). Trên stack: 8 852 giây xuống 3,6 giây.
- **C2. Alert chạy bóng lọt vào số đếm.** Mọi ô đếm alert của Tổng quan, Điều tra và SOC KPI có `NOT alert.shadow:true` (helper `real()` trong generator). Điều tra ẩn luôn alert bóng để khớp console. Tổng quan thêm ô "Alert chạy bóng".
- **I1. Thư viện rule.** Các ô "đang chạy" đếm `origin:(rule OR wazuh_rule) AND mode:active`; thêm ô chạy bóng, không cầu nối, đã tắt; biểu đồ tactic và "Rule kêu nhiều nhất" dùng cả hai origin, "Rule kêu nhiều nhất" gom theo `rule.id` kèm tên.
- **I3. Đăng nhập và Tổng event.** Các ô đăng nhập hệ thống và "Tổng event" loại `event.module:(console OR siem-xdr)`; thêm hai ô "Đăng nhập console SOC"; ô "Tài khoản đặc quyền" đổi tên cho đúng nghĩa. Trang Điều tra vẫn đếm cả đăng nhập console (ghi trong tên ô).
- **I5. Hai số "không đạt kiểm định".** Ô thống kê dùng `proposal.status:invalid`, cùng định nghĩa với biểu đồ trạng thái (cùng một số).
- **I6. Alert sức khỏe và RBA.** Tổng alert, nghiêm trọng, cao, theo mức độ, top rule, MITRE, IP, host loại `alert.source:health` (đã có ô riêng ở SOC KPI); RBA có ô riêng ở Tổng quan; KPI dùng mẫu số theo R62.
- Generator và JSON nay khớp nhau (test `test_dashboard_json_matches_generator`).

**Còn mở (sau Task 18)**

- **I2.** Bảng thư viện cắt ở 500 dòng, hai ô danh sách lọc (`tag`, `tactic`) cắt ở 300 giá trị; sau khi có hơn 4 nghìn rule Wazuh bảng chỉ hiện 500 dòng tùy ý.
- **I4.** "Top rule kích hoạt" (Tổng quan) vẫn gom theo `rule.name`: tên rule Wazuh chứa đường dẫn hoặc dùng chung sẽ bị tách / gộp sai.
- **Minor** (M1-M13 của bản audit): ô KPI dùng `lastNotNull` nên khi KPI mới rỗng sẽ hiện giá trị cũ; trung bình MTTA/MTTC chưa có trung vị; SLA không tính case quá hạn khoanh vùng còn mở; v.v. Xem audit.

**Panel rỗng là bình thường khi**: chưa có log firewall (panel "Kết nối bị firewall chặn"), chưa có POST `login` trong log Apache, chưa case P1 nào được nhận (MTTA / MTTC P1), chưa alert nào đóng với kết luận (`alert.verdict`), chưa rule AI hay ngoại lệ, và khoảng thời gian chọn ngắn hơn tuổi dữ liệu.

### Khi cắt sang rule Wazuh hoàn toàn (Task 18)

- Alert đều là `alert.source:wazuh`, `rule.id` dạng `WZH-*`; `rule.name` là mô tả Wazuh và tactic MITRE chỉ có tactic đầu.
- Các ô Thư viện rule đã đếm cả `origin:(rule OR wazuh_rule)` với `mode:active` nên không về 0 khi tắt engine YAML (riêng "Rule do AI viết" vẫn là `origin:rule`).
- Độ phủ ATT&CK (KPI và bảng cuối trang) **không** vỡ: `kpi.py` đã đọc cả rule YAML và rule Wazuh không bóng, ghi nguồn ở `attack_coverage_source`.
- Số alert Wazuh tăng mạnh nên "Top rule" (I4, còn mở) sẽ lộ rõ; alert bóng đã bị loại khỏi mọi số đếm.
- Sự kiện đăng nhập console không đi qua Wazuh nên các ô đăng nhập console không đổi ý nghĩa.

### Ghi chú về generator

Mọi JSON trong `grafana/dashboards` khớp đầu ra của `tools/gen_dashboard.py` (test `server/tests/test_kpi.py::test_dashboard_json_matches_generator` kiểm). Biến môi trường `GEN_DASHBOARD_OUT` đổi thư mục ghi (dùng cho test).
