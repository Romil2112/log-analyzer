package shipper

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// OffsetStore persists per-file byte offsets to disk so the shipper resumes
// from the correct position after a restart.
type OffsetStore struct {
	dir string
}

// NewOffsetStore returns an OffsetStore rooted at dir, creating it if needed.
func NewOffsetStore(dir string) (*OffsetStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create offset directory %q: %w", dir, err)
	}
	return &OffsetStore{dir: dir}, nil
}

// stateFile returns the path of the offset file for the given log path.
// A SHA-256 digest of the absolute path avoids slashes and collisions.
func (s *OffsetStore) stateFile(logPath string) string {
	sum := sha256.Sum256([]byte(logPath))
	return filepath.Join(s.dir, fmt.Sprintf("%x.offset", sum))
}

// Read returns the stored byte offset for logPath, or 0 if none exists.
func (s *OffsetStore) Read(logPath string) (int64, error) {
	data, err := os.ReadFile(s.stateFile(logPath))
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read offset for %q: %w", logPath, err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse offset for %q: %w", logPath, err)
	}
	return n, nil
}

// Write persists offset for logPath. It writes to a temp file then renames
// atomically so a crash mid-write never leaves a partial offset file behind.
func (s *OffsetStore) Write(logPath string, offset int64) error {
	target := s.stateFile(logPath)
	tmp := target + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(offset, 10)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}
