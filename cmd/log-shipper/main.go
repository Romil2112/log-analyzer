package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	kafka "github.com/segmentio/kafka-go"

	"github.com/Romil2112/log-analyzer/internal/shipper"
)

func main() {
	broker   := flag.String("broker", "localhost:9092", "Kafka broker address (host:port)")
	topic    := flag.String("topic", "raw-logs", "Kafka topic for raw log lines")
	stateDir := flag.String("state-dir", "/var/lib/log-shipper", "directory for persisting file offsets")
	poll     := flag.Duration("poll", 2*time.Second, "interval between polls for new log lines")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		slog.Error("no log files specified — pass file paths as positional arguments")
		os.Exit(1)
	}

	pub := &kafka.Writer{
		Addr:     kafka.TCP(*broker),
		Topic:    *topic,
		Balancer: &kafka.LeastBytes{},
	}
	defer pub.Close()

	cfg := shipper.Config{
		Files:        files,
		Topic:        *topic,
		StateDir:     *stateDir,
		PollInterval: *poll,
	}

	s, err := shipper.New(cfg, pub)
	if err != nil {
		slog.Error("failed to initialise shipper", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("log-shipper started",
		"files", strings.Join(files, ", "),
		"broker", *broker,
		"topic", *topic,
		"poll", poll.String(),
	)

	if err := s.Run(ctx); err != nil {
		slog.Error("shipper exited with error", "err", err)
		os.Exit(1)
	}

	slog.Info("log-shipper stopped")
}
