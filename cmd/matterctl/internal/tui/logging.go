// Copyright (C) 2026 The go-matter Authors. Licensed under the Apache License, Version 2.0.

package tui

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cybergarage/go-logger/log"
	"github.com/cybergarage/go-matter/matter"
)

// LogLevel is how much the TUI writes to its log file.
type LogLevel int

const (
	// LogOff writes nothing; the library's logging stays disabled.
	LogOff LogLevel = iota
	// LogInfo writes the steps of each operation: discovery, PASE, CASE,
	// commissioning and the TUI's own operations.
	LogInfo
	// LogDebug also writes every message sent and received as hex, the
	// decrypted ones included.
	LogDebug
)

func (l LogLevel) String() string {
	switch l {
	case LogInfo:
		return "INFO"
	case LogDebug:
		return "DEBUG"
	default:
		return "OFF"
	}
}

// ParseLogLevel parses off, info or debug, in any case.
func ParseLogLevel(s string) (LogLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off", "none":
		return LogOff, nil
	case "info":
		return LogInfo, nil
	case "debug":
		return LogDebug, nil
	default:
		return LogOff, fmt.Errorf("unknown log level %q: use off, info or debug", s)
	}
}

func (l LogLevel) loggerLevel() log.Level {
	if l == LogDebug {
		return log.LevelDebug
	}
	return log.LevelInfo
}

// logFileMode keeps the log readable by its owner only: at debug level it
// holds the decrypted messages of the sessions, the fabric's IPK included.
const logFileMode = 0o600

// logViewMaxLines bounds the lines the log panel keeps; the file keeps all.
const logViewMaxLines = 2000

// logReadChunk bounds what one refresh reads from the file.
const logReadChunk = 256 * 1024

// DefaultLogFileName is the name of a new log file, in the directory
// matterctl was started from unless --log-file names another.
func DefaultLogFileName(now time.Time) string {
	return "matterctl-" + now.Format("20060102-150405") + ".log"
}

// logSink routes the library's log to a file, through go-logger's file
// logger, and reads the file back for the log panel. go-logger has no
// writer of its own to plug in, and a file also keeps the whole log for
// later analysis.
type logSink struct {
	mu     sync.Mutex
	level  LogLevel
	path   string
	offset int64
}

// Enable starts writing at level to path, creating it with mode 0600 if
// needed, and appending to it otherwise. A path already in use is kept.
func (s *logSink) Enable(level LogLevel, path string) error {
	if level == LogOff {
		s.Disable()
		return nil
	}
	if path == "" {
		return errors.New("no log file")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	// go-logger creates its file 0644 and reopens it for every line, so
	// create it first with the mode it is to keep.
	f, err := os.OpenFile(filepath.Clean(abs), os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFileMode)
	if err != nil {
		return err
	}
	if err := f.Chmod(logFileMode); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	s.mu.Lock()
	if s.path != abs {
		s.path = abs
		s.offset = 0
	}
	s.level = level
	s.mu.Unlock()
	log.SetDefault(log.NewFileLogger(abs, level.loggerLevel()))
	log.Infof("matterctl tui: log level %s, go-matter %s, %s %s/%s", level, matter.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

// Disable stops logging; the file and its path are kept for the panel.
func (s *logSink) Disable() {
	s.mu.Lock()
	wasOn := s.level != LogOff
	s.level = LogOff
	s.mu.Unlock()
	if wasOn {
		log.Infof("matterctl tui: log level OFF")
	}
	log.SetDefault(nil)
}

func (s *logSink) Level() LogLevel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.level
}

func (s *logSink) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// ReadNew returns what was written to the file since the last call, up to
// logReadChunk bytes; the rest follows on the next calls. A file which
// shrank, such as one truncated, is read again from its start.
func (s *logSink) ReadNew() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return "", nil
	}
	f, err := os.Open(filepath.Clean(s.path))
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() < s.offset {
		s.offset = 0
	}
	if info.Size() == s.offset {
		return "", nil
	}
	buf := make([]byte, min(info.Size()-s.offset, logReadChunk))
	n, err := f.ReadAt(buf, s.offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	s.offset += int64(n)
	return string(buf[:n]), nil
}

// tuiLogf writes one line of the TUI's own at info level.
func tuiLogf(format string, args ...any) {
	log.Infof("tui: "+format, args...)
}

// tuiLogErrorf writes one error line of the TUI's own.
func tuiLogErrorf(format string, args ...any) {
	log.Errorf("tui: "+format, args...)
}
