// Package config quản lý việc đọc và validate file cấu hình agent.
//
// GHI CHÚ THIẾT KẾ: parse một tập con đơn giản của YAML bằng tay (không dùng
// thư viện ngoài) để agent không có dependency bên thứ ba -> giảm attack surface
// (supply-chain) và build được offline. Chỉ hỗ trợ cấu trúc phẳng 2 cấp.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AgentID    string
	Server     ServerConfig
	Queue      QueueConfig
	Log        LogConfig
	Collectors CollectorsConfig
	// FileTail: map loại log (parser hint) -> danh sách đường dẫn file.
	// vd: "apache_access" -> ["/var/log/apache2/access.log"]
	FileTail map[string][]string
	Response ResponseConfig
	FIM      FIMConfig
	// Path: đường dẫn file cấu hình đã nạp (để kiểm tra quyền đọc vì file chứa khóa enroll).
	Path string
}

type ServerConfig struct {
	// URL gốc của manager API, vd: http://10.0.0.5:8000
	URL                  string
	EnrollmentKey        string
	CAFile               string // CA nội bộ để xác thực chứng chỉ TLS của manager (URL https://)
	TimeoutSeconds       int
	RetryIntervalSeconds int
	RetryInterval        time.Duration
	BatchSize            int
}

type QueueConfig struct {
	Dir       string
	MaxMB     int // dung lượng tối đa của queue trên đĩa; đầy thì collector chờ (không vứt event)
	SegmentMB int // kích thước mỗi segment; segment đã gửi xong bị xóa
}

// FIMConfig: giám sát toàn vẹn file bằng cách băm định kỳ.
type FIMConfig struct {
	Paths           []string // file hoặc thư mục (quét đệ quy)
	Exclude         []string // mẫu tên file bỏ qua, vd *.log, *.tmp
	IntervalSeconds int
	MaxFileMB       int // file lớn hơn chỉ so kích thước / thời gian sửa, không băm
}

type LogConfig struct {
	Level string
	Path  string
}

type CollectorsConfig struct {
	Mock                   bool
	Process                bool
	ProcessIntervalSeconds int
	WindowsEventLog        bool
	WindowsChannels        []string
	WindowsIntervalSeconds int
	ProcessMode            string // auto | netlink | poll (chỉ Linux)
}

type ResponseConfig struct {
	Enabled             bool
	DryRun              bool // chỉ log lệnh, không thực thi thật (an toàn khi test)
	PollIntervalSeconds int
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("không đọc được file config '%s': %w", path, err)
	}
	defer f.Close()

	flat, err := parseSimpleYAML(f)
	if err != nil {
		return nil, fmt.Errorf("file config '%s' sai định dạng: %w", path, err)
	}

	cfg := Config{
		AgentID: flat["agent_id"],
		Server: ServerConfig{
			URL:                  strings.TrimRight(flat["server.url"], "/"),
			EnrollmentKey:        envOr("SIEM_ENROLLMENT_KEY", flat["server.enrollment_key"]),
			CAFile:               flat["server.ca_file"],
			TimeoutSeconds:       atoiDefault(flat["server.timeout_seconds"], 10),
			RetryIntervalSeconds: atoiDefault(flat["server.retry_interval_seconds"], 5),
			BatchSize:            atoiDefault(flat["server.batch_size"], 100),
		},
		Queue: QueueConfig{
			Dir:       flat["queue.dir"],
			MaxMB:     atoiDefault(flat["queue.max_mb"], 512),
			SegmentMB: atoiDefault(flat["queue.segment_mb"], 16),
		},
		Log: LogConfig{Level: flat["log.level"], Path: flat["log.path"]},
		Collectors: CollectorsConfig{
			Mock:                   flat["collectors.mock"] == "true",
			Process:                flat["collectors.process"] == "true",
			ProcessIntervalSeconds: atoiDefault(flat["collectors.process_interval_seconds"], 2),
			WindowsEventLog:        flat["collectors.windows_eventlog"] == "true",
			WindowsChannels:        splitList(flat["collectors.windows_channels"]),
			WindowsIntervalSeconds: atoiDefault(flat["collectors.windows_interval_seconds"], 5),
			ProcessMode:            flat["collectors.process_mode"],
		},
		FileTail: map[string][]string{},
		Response: ResponseConfig{
			Enabled:             flat["response.enabled"] == "true",
			DryRun:              flat["response.dry_run"] == "true",
			PollIntervalSeconds: atoiDefault(flat["response.poll_interval_seconds"], 5),
		},
		FIM: FIMConfig{
			Paths:           splitList(flat["fim.paths"]),
			Exclude:         splitList(flat["fim.exclude"]),
			IntervalSeconds: atoiDefault(flat["fim.interval_seconds"], 300),
			MaxFileMB:       atoiDefault(flat["fim.max_file_mb"], 32),
		},
		Path: path,
	}
	if v := os.Getenv("SIEM_SERVER_URL"); v != "" {
		cfg.Server.URL = strings.TrimRight(v, "/")
	}
	if v := os.Getenv("SIEM_AGENT_ID"); v != "" {
		cfg.AgentID = v
	}

	for k, v := range flat {
		if strings.HasPrefix(k, "filetail.") {
			if paths := splitList(v); len(paths) > 0 {
				cfg.FileTail[strings.TrimPrefix(k, "filetail.")] = paths
			}
		}
	}

	applyDefaults(&cfg)
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config không hợp lệ: %w", err)
	}
	cfg.Server.RetryInterval = time.Duration(cfg.Server.RetryIntervalSeconds) * time.Second
	return &cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.AgentID == "" {
		hostname, _ := os.Hostname()
		cfg.AgentID = hostname
	}
	if cfg.Queue.Dir == "" {
		cfg.Queue.Dir = "./queue-data"
	}
	if cfg.Log.Level == "" {
		cfg.Log.Level = "info"
	}
	if len(cfg.Collectors.WindowsChannels) == 0 {
		cfg.Collectors.WindowsChannels = []string{"Security", "System"}
	}
}

func validate(cfg *Config) error {
	if cfg.Server.URL == "" {
		return fmt.Errorf("server.url là bắt buộc")
	}
	if cfg.Server.EnrollmentKey == "" {
		return fmt.Errorf("server.enrollment_key (hoặc biến môi trường SIEM_ENROLLMENT_KEY) là bắt buộc")
	}
	if strings.HasPrefix(cfg.Server.URL, "http://") {
		fmt.Fprintln(os.Stderr, "CẢNH BÁO: server.url dùng http:// — dữ liệu và token đi dạng rõ, chỉ chấp nhận trong lab")
	}
	if cfg.Server.BatchSize < 1 {
		cfg.Server.BatchSize = 1
	}
	switch cfg.Collectors.ProcessMode {
	case "", "auto", "netlink", "poll":
	default:
		return fmt.Errorf("collectors.process_mode phải là auto, netlink hoặc poll")
	}
	if cfg.Queue.SegmentMB < 1 || cfg.Queue.MaxMB < cfg.Queue.SegmentMB*2 {
		return fmt.Errorf("queue.max_mb phải >= 2 x queue.segment_mb")
	}
	if cfg.FIM.IntervalSeconds < 10 {
		cfg.FIM.IntervalSeconds = 10
	}
	return nil
}

// parseSimpleYAML đọc tập con YAML: section cấp 1 + key: value thụt lề bên trong.
// Kết quả là map phẳng "section.key" -> value.
func parseSimpleYAML(f *os.File) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(f)
	currentSection := ""
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		rawLine := scanner.Text()
		line := strings.TrimRight(rawLine, " \t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		key, value, hasValue := splitKeyValue(trimmed)
		if !indented {
			if !hasValue {
				currentSection = key
				continue
			}
			currentSection = ""
			result[key] = value
			continue
		}
		if !hasValue {
			return nil, fmt.Errorf("dòng %d: không parse được '%s'", lineNo, rawLine)
		}
		if currentSection == "" {
			return nil, fmt.Errorf("dòng %d: key thụt lề nhưng không nằm trong section nào: '%s'", lineNo, rawLine)
		}
		result[currentSection+"."+key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("lỗi đọc file: %w", err)
	}
	return result, nil
}

// splitKeyValue tách "key: value". Chỉ tách ở dấu ':' ĐẦU TIÊN nên value có thể
// chứa ':' (vd: URL, đường dẫn Windows "C:\...").
func splitKeyValue(line string) (key string, value string, hasValue bool) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return line, "", false
	}
	key = strings.TrimSpace(line[:idx])
	rest := strings.TrimSpace(line[idx+1:])
	if rest == "" {
		return key, "", false
	}
	// Giá trị trong ngoặc: lấy đúng phần giữa cặp ngoặc, bỏ comment phía sau (nếu có)
	if q := rest[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(rest[1:], q); end >= 0 {
			return key, rest[1 : end+1], true
		}
	}
	// Giá trị không ngoặc: bỏ comment cuối dòng
	if i := strings.Index(rest, " #"); i >= 0 {
		rest = strings.TrimSpace(rest[:i])
	}
	return key, rest, true
}

// splitList tách "a, b ,c" -> [a b c]
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoiDefault(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return defaultVal
	}
	return n
}

// envOr: ưu tiên file bí mật (<ENV>_FILE, vd Docker secret), rồi biến môi trường, rồi giá trị config.
func envOr(env, fallback string) string {
	if path := os.Getenv(env + "_FILE"); path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			return strings.TrimSpace(string(raw))
		}
	}
	if v := os.Getenv(env); v != "" {
		return v
	}
	return fallback
}
