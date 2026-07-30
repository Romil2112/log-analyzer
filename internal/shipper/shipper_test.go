package shipper

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	kafka "github.com/segmentio/kafka-go"
)

// mockPub captures messages written to it and optionally returns an error.
type mockPub struct {
	mu   sync.Mutex
	msgs []kafka.Message
	err  error
}

func (m *mockPub) WriteMessages(_ context.Context, msgs ...kafka.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.msgs = append(m.msgs, msgs...)
	return nil
}

func (m *mockPub) Close() error { return nil }

func (m *mockPub) received() []kafka.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]kafka.Message, len(m.msgs))
	copy(out, m.msgs)
	return out
}

func newTestShipper(t *testing.T, pub *mockPub) *Shipper {
	t.Helper()
	s, err := New(Config{
		StateDir:     t.TempDir(),
		Topic:        "raw-logs",
		PollInterval: 50 * time.Millisecond,
	}, pub)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeTempLog(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.log")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

// --- readLines tests (unit, no Kafka or disk I/O) ---

func TestReadLinesComplete(t *testing.T) {
	s := newTestShipper(t, &mockPub{})
	r := strings.NewReader("line one\nline two\nline three\n")
	msgs, consumed, err := s.readLines("/test.log", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 {
		t.Fatalf("want 3 messages, got %d", len(msgs))
	}
	if consumed != int64(len("line one\nline two\nline three\n")) {
		t.Fatalf("unexpected consumed byte count: %d", consumed)
	}
}

func TestReadLinesPartialAtEOF(t *testing.T) {
	s := newTestShipper(t, &mockPub{})
	// "line two" has no trailing newline — must not be consumed.
	r := strings.NewReader("line one\nline two")
	msgs, consumed, err := s.readLines("/test.log", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(msgs))
	}
	if consumed != int64(len("line one\n")) {
		t.Fatalf("consumed should cover only the complete line, got %d", consumed)
	}
}

func TestReadLinesEmpty(t *testing.T) {
	s := newTestShipper(t, &mockPub{})
	msgs, consumed, err := s.readLines("/test.log", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 0 || consumed != 0 {
		t.Fatalf("want no messages and 0 consumed, got %d msgs %d bytes", len(msgs), consumed)
	}
}

func TestReadLinesSkipsBlankLines(t *testing.T) {
	s := newTestShipper(t, &mockPub{})
	r := strings.NewReader("first\n\nsecond\n\n")
	msgs, _, err := s.readLines("/test.log", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages (blank lines skipped), got %d", len(msgs))
	}
}

func TestReadLinesCRLF(t *testing.T) {
	s := newTestShipper(t, &mockPub{})
	r := strings.NewReader("alpha\r\nbeta\r\n")
	msgs, _, err := s.readLines("/test.log", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 {
		t.Fatalf("want 2 messages, got %d", len(msgs))
	}
	var entry logEntry
	if err := json.Unmarshal(msgs[0].Value, &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Line != "alpha" {
		t.Fatalf("CRLF not stripped: got %q", entry.Line)
	}
}

func TestReadLinesMessageSchema(t *testing.T) {
	s := newTestShipper(t, &mockPub{})
	r := strings.NewReader("Jun 15 02:00:00 sshd: Failed password\n")
	msgs, _, err := s.readLines("/var/log/auth.log", r)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("want 1 message, got %d", len(msgs))
	}
	var entry logEntry
	if err := json.Unmarshal(msgs[0].Value, &entry); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if entry.Line != "Jun 15 02:00:00 sshd: Failed password" {
		t.Fatalf("unexpected line: %q", entry.Line)
	}
	if entry.Source != "/var/log/auth.log" {
		t.Fatalf("unexpected source: %q", entry.Source)
	}
	if entry.Ts == "" {
		t.Fatal("ts must not be empty")
	}
	if _, err := time.Parse(time.RFC3339Nano, entry.Ts); err != nil {
		t.Fatalf("ts is not RFC3339Nano: %v", err)
	}
}

// --- poll tests (integration-style, use temp files on disk) ---

func TestPollNewLines(t *testing.T) {
	pub := &mockPub{}
	s := newTestShipper(t, pub)
	path := writeTempLog(t, "alpha\nbeta\ngamma\n")

	var offset int64
	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	if got := len(pub.received()); got != 3 {
		t.Fatalf("want 3 messages, got %d", got)
	}
}

func TestPollNoNewData(t *testing.T) {
	pub := &mockPub{}
	s := newTestShipper(t, pub)
	path := writeTempLog(t, "line\n")

	// First poll consumes the line.
	var offset int64
	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	// Second poll: no new data.
	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	if got := len(pub.received()); got != 1 {
		t.Fatalf("want exactly 1 message total, got %d", got)
	}
}

func TestPollIncremental(t *testing.T) {
	pub := &mockPub{}
	s := newTestShipper(t, pub)

	f, err := os.CreateTemp(t.TempDir(), "*.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	path := f.Name()

	if _, err := f.WriteString("first\n"); err != nil {
		t.Fatal(err)
	}

	var offset int64
	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	if got := len(pub.received()); got != 1 {
		t.Fatalf("after first poll: want 1 message, got %d", got)
	}

	if _, err := f.WriteString("second\nthird\n"); err != nil {
		t.Fatal(err)
	}

	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	if got := len(pub.received()); got != 3 {
		t.Fatalf("after second poll: want 3 total messages, got %d", got)
	}
}

func TestPollTruncation(t *testing.T) {
	pub := &mockPub{}
	s := newTestShipper(t, pub)

	f, err := os.CreateTemp(t.TempDir(), "*.log")
	if err != nil {
		t.Fatal(err)
	}
	path := f.Name()

	// Write enough initial content so the stored offset is well past the
	// truncated file's size, triggering the fi.Size() < *offset branch.
	if _, err := f.WriteString("old line one\nold line two\nold line three\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var offset int64
	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	if len(pub.received()) != 3 {
		t.Fatal("initial poll should ship 3 messages")
	}

	// Simulate logrotate copytruncate: new file is shorter than stored offset.
	if err := os.WriteFile(path, []byte("fresh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	if got := len(pub.received()); got != 4 {
		t.Fatalf("after truncation poll: want 4 total messages, got %d", got)
	}
}

func TestPollPublishFailureRetries(t *testing.T) {
	pub := &mockPub{err: fmt.Errorf("kafka unavailable")}
	s := newTestShipper(t, pub)
	path := writeTempLog(t, "line one\nline two\n")

	var offset int64
	// First poll: publish fails — must return nil and leave offset at 0.
	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatalf("publish failure must not propagate as error, got: %v", err)
	}
	if offset != 0 {
		t.Fatalf("offset must not advance on publish failure, got %d", offset)
	}
	if len(pub.received()) != 0 {
		t.Fatal("no messages should be recorded on failure")
	}

	// Clear the error and retry — should now ship both lines.
	pub.mu.Lock()
	pub.err = nil
	pub.mu.Unlock()

	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}
	if got := len(pub.received()); got != 2 {
		t.Fatalf("retry poll: want 2 messages, got %d", got)
	}
}

func TestPollMissingFile(t *testing.T) {
	pub := &mockPub{}
	s := newTestShipper(t, pub)

	var offset int64
	err := s.poll(context.Background(), "/nonexistent/path/file.log", &offset)
	if err != nil {
		t.Fatalf("missing file should not error, got: %v", err)
	}
	if len(pub.received()) != 0 {
		t.Fatal("missing file should produce no messages")
	}
}

func TestPollOffsetPersisted(t *testing.T) {
	pub := &mockPub{}
	s := newTestShipper(t, pub)
	path := writeTempLog(t, "line one\nline two\n")

	var offset int64
	if err := s.poll(context.Background(), path, &offset); err != nil {
		t.Fatal(err)
	}

	stored, err := s.offsets.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if stored != offset {
		t.Fatalf("stored offset %d != in-memory offset %d", stored, offset)
	}
	if offset == 0 {
		t.Fatal("offset must have advanced past 0")
	}
}
