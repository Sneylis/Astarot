package core

import (
	"bufio"
	"os"
	"sync"
)

// SafeWriter is a goroutine-safe buffered file writer.
// Multiple goroutines (passive + active) can call WriteLine concurrently.
type SafeWriter struct {
	mu   sync.Mutex
	file *os.File
	buf  *bufio.Writer
}

// NewSafeWriter creates (or truncates) the file at path and returns a SafeWriter.
func NewSafeWriter(path string) (*SafeWriter, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &SafeWriter{
		file: f,
		buf:  bufio.NewWriter(f),
	}, nil
}

// WriteLine appends line + newline to the file, thread-safe.
func (w *SafeWriter) WriteLine(line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.buf.WriteString(line + "\n")
	return err
}

// Close flushes the buffer and closes the underlying file.
func (w *SafeWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.buf.Flush(); err != nil {
		return err
	}
	return w.file.Close()
}
