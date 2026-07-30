// Package shipper tails log files and publishes each line as a JSON message
// to a Kafka topic. Each message carries the raw log line, its source path,
// and the wall-clock timestamp at which it was read.
package shipper

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

// Config holds runtime parameters for the Shipper.
type Config struct {
	Files        []string
	Topic        string
	StateDir     string
	PollInterval time.Duration
}

// Publisher is satisfied by *kafka.Writer. Extracted for testing.
type Publisher interface {
	WriteMessages(ctx context.Context, msgs ...kafka.Message) error
	Close() error
}

// logEntry is the JSON envelope written to Kafka for each log line.
type logEntry struct {
	Line   string `json:"line"`
	Source string `json:"source"`
	Ts     string `json:"ts"`
}

// Shipper tails each configured file and publishes new lines to Kafka.
type Shipper struct {
	cfg     Config
	offsets *OffsetStore
	pub     Publisher
}

// New creates a Shipper. pub must remain open for the lifetime of the Shipper;
// the caller is responsible for closing it after Run returns.
func New(cfg Config, pub Publisher) (*Shipper, error) {
	store, err := NewOffsetStore(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	return &Shipper{cfg: cfg, offsets: store, pub: pub}, nil
}

// Run starts one goroutine per file and blocks until ctx is cancelled or a
// file watcher returns a non-context error.
func (s *Shipper) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errc := make(chan error, len(s.cfg.Files))

	for _, path := range s.cfg.Files {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			if err := s.watch(ctx, p); err != nil {
				errc <- err
			}
		}(path)
	}

	go func() {
		wg.Wait()
		close(errc)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err, ok := <-errc:
		if ok {
			return err
		}
		return nil
	}
}

// watch polls path on cfg.PollInterval until ctx is cancelled.
func (s *Shipper) watch(ctx context.Context, path string) error {
	offset, err := s.offsets.Read(path)
	if err != nil {
		return fmt.Errorf("read offset for %s: %w", path, err)
	}

	for {
		if err := s.poll(ctx, path, &offset); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.cfg.PollInterval):
		}
	}
}

// poll reads any new complete lines from path starting at *offset, publishes
// them to Kafka, and advances *offset. Missing files are skipped silently so
// the shipper tolerates files that have not yet been created.
func (s *Shipper) poll(ctx context.Context, path string, offset *int64) error {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	// Detect truncation (e.g., logrotate copytruncate): reset to beginning.
	if fi.Size() < *offset {
		slog.Info("log file truncated, resetting offset", "path", path)
		*offset = 0
		if werr := s.offsets.Write(path, 0); werr != nil {
			slog.Warn("failed to reset offset on disk", "path", path, "err", werr)
		}
	}

	if fi.Size() == *offset {
		return nil // no new data
	}

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Seek(*offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek %s: %w", path, err)
	}

	msgs, consumed, err := s.readLines(path, f)
	if err != nil {
		return err
	}
	if len(msgs) == 0 {
		return nil
	}

	if err := s.pub.WriteMessages(ctx, msgs...); err != nil {
		// Leave offset unchanged so the next poll retries the same batch.
		// The log file acts as the buffer; no lines are lost on a transient outage.
		slog.Warn("publish failed, will retry on next poll",
			"topic", s.cfg.Topic, "count", len(msgs), "err", err)
		return nil
	}

	newOffset := *offset + consumed
	*offset = newOffset
	if werr := s.offsets.Write(path, newOffset); werr != nil {
		slog.Warn("failed to persist offset", "path", path, "err", werr)
	}
	slog.Info("shipped lines", "path", path, "count", len(msgs), "offset", newOffset)
	return nil
}

// readLines scans r for complete newline-terminated lines, returning the
// corresponding Kafka messages and the total byte count of those lines.
// Partial lines at EOF are left unconsumed so they are picked up on the next
// poll once the writer has flushed the trailing newline.
func (s *Shipper) readLines(source string, r io.Reader) ([]kafka.Message, int64, error) {
	br := bufio.NewReader(r)
	var msgs []kafka.Message
	var consumed int64

	for {
		line, err := br.ReadString('\n')

		if len(line) > 0 && line[len(line)-1] == '\n' {
			consumed += int64(len(line))
			if text := strings.TrimRight(line, "\r\n"); text != "" {
				payload, merr := json.Marshal(logEntry{
					Line:   text,
					Source: source,
					Ts:     time.Now().UTC().Format(time.RFC3339Nano),
				})
				if merr != nil {
					return nil, 0, fmt.Errorf("marshal message: %w", merr)
				}
				msgs = append(msgs, kafka.Message{Value: payload})
			}
		}
		// Partial line (no trailing '\n') at EOF is not consumed.

		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("read %s: %w", source, err)
		}
	}

	return msgs, consumed, nil
}
