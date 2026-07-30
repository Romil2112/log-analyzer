package shipper

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOffsetStoreReadMissing(t *testing.T) {
	store, err := NewOffsetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	n, err := store.Read("/nonexistent/file.log")
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("want 0, got %d", n)
	}
}

func TestOffsetStoreRoundTrip(t *testing.T) {
	store, err := NewOffsetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := "/var/log/auth.log"
	if err := store.Write(path, 12345); err != nil {
		t.Fatal(err)
	}
	n, err := store.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != 12345 {
		t.Fatalf("want 12345, got %d", n)
	}
}

func TestOffsetStoreMultipleFiles(t *testing.T) {
	store, err := NewOffsetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	paths := []struct {
		path   string
		offset int64
	}{
		{"/var/log/auth.log", 100},
		{"/var/log/syslog", 200},
		{"/var/log/nginx/access.log", 300},
	}
	for _, p := range paths {
		if err := store.Write(p.path, p.offset); err != nil {
			t.Fatalf("write %s: %v", p.path, err)
		}
	}
	for _, p := range paths {
		n, err := store.Read(p.path)
		if err != nil {
			t.Fatalf("read %s: %v", p.path, err)
		}
		if n != p.offset {
			t.Fatalf("%s: want %d, got %d", p.path, p.offset, n)
		}
	}
}

func TestOffsetStoreOverwrite(t *testing.T) {
	store, err := NewOffsetStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := "/var/log/app.log"
	for _, offset := range []int64{0, 512, 1024, 99999} {
		if err := store.Write(path, offset); err != nil {
			t.Fatal(err)
		}
		n, err := store.Read(path)
		if err != nil {
			t.Fatal(err)
		}
		if n != offset {
			t.Fatalf("want %d, got %d", offset, n)
		}
	}
}

func TestOffsetStoreCorruptFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewOffsetStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := "/var/log/auth.log"
	// Write a corrupt state file directly.
	sf := store.stateFile(path)
	if err := os.WriteFile(sf, []byte("not-a-number\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = store.Read(path)
	if err == nil {
		t.Fatal("expected error reading corrupt offset file, got nil")
	}
}

func TestOffsetStoreStateFileInSubdir(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "nested", "state")
	store, err := NewOffsetStore(subdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write("/log/test.log", 42); err != nil {
		t.Fatal(err)
	}
	n, err := store.Read("/log/test.log")
	if err != nil {
		t.Fatal(err)
	}
	if n != 42 {
		t.Fatalf("want 42, got %d", n)
	}
}
