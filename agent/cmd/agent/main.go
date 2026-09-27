// cmd/agent là entry point của SIEM/XDR agent:
//
//	Collectors (file, eventlog, process, mock) -> channel -> Queue (đĩa) -> Sender -> Manager API
//	Manager API -> Response executor (block IP, kill process, isolate host)
package main

import (
	"context"
	"flag"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"siem-agent/collectors/filetail"
	"siem-agent/collectors/mock"
	"siem-agent/collectors/process"
	"siem-agent/collectors/winevent"
	"siem-agent/config"
	"siem-agent/core"
	"siem-agent/queue"
	"siem-agent/response"
	"siem-agent/sender"
)

const version = "1.0.0"

func main() {
	configPath := flag.String("config", "config.yaml", "đường dẫn tới file cấu hình")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("không load được config: %v", err)
	}
	if cfg.Log.Path != "" {
		_ = os.MkdirAll(filepath.Dir(cfg.Log.Path), 0o750)
		if f, err := os.OpenFile(cfg.Log.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err == nil {
			log.SetOutput(io.MultiWriter(os.Stdout, f))
			defer f.Close()
		}
	}
	hostname, _ := os.Hostname()
	log.Printf("siem-agent %s khởi động, agent_id=%s, os=%s, server=%s", version, cfg.AgentID, runtime.GOOS, cfg.Server.URL)

	q, err := queue.New(cfg.Queue.Dir)
	if err != nil {
		log.Fatalf("không khởi tạo được queue: %v", err)
	}
	defer q.Close()
	log.Printf("queue tại '%s', số byte chưa gửi từ lần trước: %d", cfg.Queue.Dir, q.Pending())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sigCh
		log.Printf("nhận tín hiệu %v, đang dừng agent...", s)
		cancel()
	}()

	client, err := sender.NewClient(cfg.Server.URL, cfg.Server.EnrollmentKey, sender.AgentInfo{
		AgentID: cfg.AgentID, Hostname: hostname, OS: runtime.GOOS, Version: version,
	}, cfg.Queue.Dir, time.Duration(cfg.Server.TimeoutSeconds)*time.Second, cfg.Server.CAFile)
	if err != nil {
		log.Fatalf("không khởi tạo được kết nối tới manager: %v", err)
	}

	go sender.New(client, q, cfg.Server.BatchSize, cfg.Server.RetryInterval).Run(ctx)
	go response.Heartbeat(ctx, client, 30*time.Second)
	if cfg.Response.Enabled {
		go response.New(client, cfg.Response.DryRun, time.Duration(cfg.Response.PollIntervalSeconds)*time.Second).Run(ctx)
	}

	// --- Khởi động các collector theo cấu hình ---
	var collectors []core.Collector
	if cfg.Collectors.Mock {
		collectors = append(collectors, mock.New(cfg.AgentID, 2*time.Second))
	}
	if len(cfg.FileTail) > 0 {
		collectors = append(collectors, filetail.New(cfg.FileTail, cfg.Queue.Dir))
	}
	if cfg.Collectors.Process {
		collectors = append(collectors, process.New(time.Duration(cfg.Collectors.ProcessIntervalSeconds)*time.Second))
	}
	if cfg.Collectors.WindowsEventLog {
		if runtime.GOOS == "windows" {
			collectors = append(collectors, winevent.New(cfg.Collectors.WindowsChannels,
				time.Duration(cfg.Collectors.WindowsIntervalSeconds)*time.Second, cfg.Queue.Dir))
		} else {
			log.Println("bỏ qua windows_eventlog vì không chạy trên Windows")
		}
	}
	if len(collectors) == 0 {
		log.Println("CẢNH BÁO: không có collector nào được bật — agent chỉ gửi heartbeat/nhận lệnh")
	}

	events := make(chan core.Event, 5000)
	for _, c := range collectors {
		c := c
		log.Printf("bật collector: %s", c.Name())
		go func() {
			if err := c.Start(events); err != nil {
				log.Printf("collector %s dừng với lỗi: %v", c.Name(), err)
			}
		}()
	}

	for {
		select {
		case <-ctx.Done():
			for _, c := range collectors {
				_ = c.Stop()
			}
			log.Println("agent đã dừng hoàn toàn")
			return
		case evt := <-events:
			evt.AgentID = cfg.AgentID
			evt.Hostname = hostname
			evt.OS = runtime.GOOS
			if evt.Timestamp.IsZero() {
				evt.Timestamp = time.Now().UTC()
			}
			if err := q.Enqueue(evt); err != nil {
				log.Printf("LỖI: không ghi được event vào queue: %v", err)
			}
		}
	}
}
