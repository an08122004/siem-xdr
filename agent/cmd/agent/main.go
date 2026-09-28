// cmd/agent là entry point của SIEM/XDR agent:
//
//	Collectors (file, eventlog, process, fim, mock) --emit (ghi bền)--> Queue (đĩa) -> Sender -> Manager API
//	Manager API -> Response executor (block IP, kill process, isolate host)
//
// Chạy trực tiếp:          siem-agent -config config.yaml
// Cài thành service:       siem-agent -install -config config.yaml   (systemd / Windows service, cần root/Admin)
// Gỡ service:              siem-agent -uninstall
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"siem-agent/collectors/filetail"
	"siem-agent/collectors/fim"
	"siem-agent/collectors/mock"
	"siem-agent/collectors/process"
	"siem-agent/collectors/winevent"
	"siem-agent/config"
	"siem-agent/core"
	"siem-agent/queue"
	"siem-agent/response"
	"siem-agent/sender"
)

const (
	version     = "1.1.0"
	serviceName = "siem-agent"
	stopTimeout = 15 * time.Second
)

func main() {
	configPath := flag.String("config", "config.yaml", "đường dẫn tới file cấu hình")
	install := flag.Bool("install", false, "cài agent thành service tự khởi động (systemd / Windows service) rồi chạy luôn")
	uninstall := flag.Bool("uninstall", false, "dừng và gỡ service")
	asService := flag.Bool("service", false, "(dùng nội bộ) đang được Windows Service Control Manager gọi")
	flag.Parse()

	switch {
	case *install:
		abs, err := filepath.Abs(*configPath)
		if err == nil {
			_, err = config.Load(abs) // kiểm tra config trước khi cài
		}
		if err == nil {
			err = installService(abs)
		}
		exitOn(err, "đã cài và khởi động service "+serviceName)
	case *uninstall:
		exitOn(uninstallService(), "đã gỡ service "+serviceName)
	case *asService:
		if err := runAsService(func(ctx context.Context) error { return run(ctx, *configPath, true) }); err != nil {
			log.Fatalf("chạy dưới dạng service thất bại: %v", err)
		}
	default:
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := run(ctx, *configPath, false); err != nil {
			log.Fatal(err)
		}
	}
}

func exitOn(err error, okMsg string) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "LỖI:", err)
		os.Exit(1)
	}
	fmt.Println(okMsg)
}

// run chạy agent tới khi ctx bị hủy (Ctrl+C, SIGTERM, hoặc lệnh Stop của service manager).
func run(ctx context.Context, configPath string, service bool) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("không load được config: %w", err)
	}
	if err := os.MkdirAll(cfg.Queue.Dir, 0o700); err != nil {
		return fmt.Errorf("không tạo được thư mục trạng thái: %w", err)
	}
	logPath := cfg.Log.Path
	if logPath == "" && service {
		logPath = filepath.Join(cfg.Queue.Dir, "agent.log") // service không có console
	}
	if logPath != "" {
		_ = os.MkdirAll(filepath.Dir(logPath), 0o750)
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err == nil {
			log.SetOutput(io.MultiWriter(os.Stdout, f))
			defer f.Close()
		}
	}
	hostname, _ := os.Hostname()
	log.Printf("siem-agent %s khởi động, agent_id=%s, os=%s, server=%s", version, cfg.AgentID, runtime.GOOS, cfg.Server.URL)

	// Thư mục trạng thái chứa token, queue (log an ninh) và offset: chỉ SYSTEM/root/Administrators được đọc.
	if err := hardenStateDir(cfg.Queue.Dir); err != nil {
		log.Printf("CẢNH BÁO: không siết được quyền thư mục %s: %v", cfg.Queue.Dir, err)
	}
	warnConfigPerms(cfg.Path)

	q, err := queue.New(cfg.Queue.Dir, queue.Options{
		SegmentBytes: int64(cfg.Queue.SegmentMB) << 20,
		MaxBytes:     int64(cfg.Queue.MaxMB) << 20,
	})
	if err != nil {
		return fmt.Errorf("không khởi tạo được queue: %w", err)
	}
	defer q.Close()
	log.Printf("queue tại '%s' (tối đa %d MB), số byte chưa gửi từ lần trước: %d", cfg.Queue.Dir, cfg.Queue.MaxMB, q.Pending())

	client, err := sender.NewClient(cfg.Server.URL, cfg.Server.EnrollmentKey, sender.AgentInfo{
		AgentID: cfg.AgentID, Hostname: hostname, OS: runtime.GOOS, Version: version,
	}, cfg.Queue.Dir, time.Duration(cfg.Server.TimeoutSeconds)*time.Second, cfg.Server.CAFile)
	if err != nil {
		return fmt.Errorf("không khởi tạo được kết nối tới manager: %w", err)
	}

	var bg sync.WaitGroup
	goBG := func(f func()) {
		bg.Add(1)
		go func() { defer bg.Done(); f() }()
	}
	goBG(func() { sender.New(client, q, cfg.Server.BatchSize, cfg.Server.RetryInterval).Run(ctx) })
	goBG(func() { response.Heartbeat(ctx, client.Heartbeat, 30*time.Second) })
	if cfg.Response.Enabled {
		ex := response.New(client, cfg.Response.DryRun, time.Duration(cfg.Response.PollIntervalSeconds)*time.Second, cfg.Queue.Dir)
		goBG(func() { ex.Run(ctx) })
	}

	collectors := buildCollectors(cfg)
	if len(collectors) == 0 {
		log.Println("CẢNH BÁO: không có collector nào được bật — agent chỉ gửi heartbeat/nhận lệnh")
	}
	emit := newEmitter(ctx, q, cfg.AgentID, hostname, cfg.Queue.MaxMB)
	var wg sync.WaitGroup
	for _, c := range collectors {
		c := c
		log.Printf("bật collector: %s", c.Name())
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.Start(emit); err != nil {
				log.Printf("collector %s dừng với lỗi: %v", c.Name(), err)
			}
		}()
	}

	<-ctx.Done()
	log.Println("đang dừng agent...")
	for _, c := range collectors {
		_ = c.Stop()
	}
	// Chờ collector ghi xong lô đang dở và lưu offset (không mất event đã đọc).
	done := make(chan struct{})
	go func() { wg.Wait(); bg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(stopTimeout):
		log.Printf("CẢNH BÁO: collector không dừng trong %s, thoát luôn (event chưa ghi sẽ được đọc lại lần sau)", stopTimeout)
	}
	log.Println("agent đã dừng hoàn toàn")
	return nil
}

func buildCollectors(cfg *config.Config) []core.Collector {
	var cs []core.Collector
	if cfg.Collectors.Mock {
		cs = append(cs, mock.New(cfg.AgentID, 2*time.Second))
	}
	if len(cfg.FileTail) > 0 {
		cs = append(cs, filetail.New(cfg.FileTail, cfg.Queue.Dir))
	}
	if cfg.Collectors.Process {
		cs = append(cs, process.New(time.Duration(cfg.Collectors.ProcessIntervalSeconds)*time.Second, cfg.Collectors.ProcessMode))
	}
	if cfg.Collectors.WindowsEventLog {
		if runtime.GOOS == "windows" {
			cs = append(cs, winevent.New(cfg.Collectors.WindowsChannels,
				time.Duration(cfg.Collectors.WindowsIntervalSeconds)*time.Second, cfg.Queue.Dir))
		} else {
			log.Println("bỏ qua windows_eventlog vì không chạy trên Windows")
		}
	}
	if len(cfg.FIM.Paths) > 0 {
		cs = append(cs, fim.New(cfg.FIM.Paths, cfg.FIM.Exclude, time.Duration(cfg.FIM.IntervalSeconds)*time.Second,
			cfg.FIM.MaxFileMB, cfg.Queue.Dir))
	}
	return cs
}

// newEmitter: collector gọi hàm này để ghi một lô event. Chỉ trả về khi lô đã fsync xuống queue.
// Queue đầy (manager mất kết nối lâu) thì chờ thay vì vứt event; collector đứng yên nên không
// lưu offset -> nguồn log vẫn giữ dữ liệu, đọc tiếp khi queue có chỗ.
func newEmitter(ctx context.Context, q *queue.Queue, agentID, hostname string, maxMB int) core.Emit {
	var mu sync.Mutex
	var lastWarn time.Time
	return func(evts []core.Event) error {
		if len(evts) == 0 {
			return nil
		}
		for i := range evts {
			evts[i].AgentID, evts[i].Hostname, evts[i].OS = agentID, hostname, runtime.GOOS
			if evts[i].Timestamp.IsZero() {
				evts[i].Timestamp = time.Now().UTC()
			}
		}
		for {
			err := q.Enqueue(evts...)
			if !errors.Is(err, queue.ErrFull) {
				return err
			}
			mu.Lock()
			if time.Since(lastWarn) > time.Minute {
				log.Printf("CẢNH BÁO: queue đầy (%d MB) vì chưa gửi được lên manager — collector tạm dừng, không bỏ event", maxMB)
				lastWarn = time.Now()
			}
			mu.Unlock()
			select {
			case <-ctx.Done():
				return core.ErrStopping
			case <-time.After(time.Second):
			}
		}
	}
}
