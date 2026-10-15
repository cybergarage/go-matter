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

// logPendingMax bounds the log the panel has not shown yet; when more is
// written in between, such as by a burst of hex dumps, its start is
// dropped from the panel, not from the file.
const logPendingMax = 1 << 20

// DefaultLogFileName is the name of a new log file, in the directory
// matterctl was started from unless --log-file names another.
func DefaultLogFileName(now time.Time) string {
	return "matterctl-" + now.Format("20060102-150405") + ".log"
}

// logSink writes the library's log, with millisecond timestamps, both to a
// file it keeps open and to a buffer the log panel takes its new lines
// from. go-logger writes one line at a time while holding its own lock, and
// calls Write under it, so logSink never logs nor sets the default logger
// while it holds mu.
type logSink struct {
	mu      sync.Mutex
	level   LogLevel
	path    string
	file    *os.File
	logger  *log.Logger
	pending []byte
}

// Enable starts writing at level to path, creating it with mode 0600 if
// needed, and appending to it otherwise; an existing file is set to 0600.
// Enabling again with the same path changes the level only.
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
	s.mu.Lock()
	same := s.file != nil && s.path == abs
	s.mu.Unlock()
	if !same {
		// No line is being written to the old file once the default
		// logger is replaced.
		log.SetDefault(nil)
		if err := s.open(abs, level); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.level = level
	logger := s.logger
	s.mu.Unlock()
	logger.SetLevel(level.loggerLevel())
	log.SetDefault(logger)
	log.Infof("matterctl tui: log level %s, go-matter %s, %s %s/%s", level, matter.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}

func (s *logSink) open(path string, level LogLevel) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_APPEND, logFileMode)
	if err != nil {
		return err
	}
	if err := f.Chmod(logFileMode); err != nil {
		_ = f.Close()
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		_ = s.file.Close()
	}
	s.file = f
	s.path = path
	s.pending = nil
	s.logger = log.NewWriterLogger(io.MultiWriter(f, panelWriter{s}), level.loggerLevel(), log.WithTimeLayout(log.TimeLayoutMilliseconds))
	return nil
}

// Disable stops logging; the file stays open for logging again, and its
// path is kept for the panel.
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

// Close stops logging and closes the file.
func (s *logSink) Close() error {
	s.Disable()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
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

// ReadNew returns the log written since the last call, for the panel: its
// last logPendingMax bytes.
func (s *logSink) ReadNew() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := s.pending
	if over := len(pending) - logPendingMax; over > 0 {
		pending = pending[over:]
	}
	s.pending = nil
	return string(pending), nil
}

// panelWriter keeps what go-logger writes until the panel takes it.
type panelWriter struct{ s *logSink }

func (w panelWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	w.s.pending = append(w.s.pending, p...)
	// Trimmed to logPendingMax once twice as much is kept, so that a burst
	// copies the buffer now and then only.
	if len(w.s.pending) > 2*logPendingMax {
		w.s.pending = append([]byte(nil), w.s.pending[len(w.s.pending)-logPendingMax:]...)
	}
	return len(p), nil
}

// tuiLogf writes one line of the TUI's own at info level.
func tuiLogf(format string, args ...any) {
	log.Infof("tui: "+format, args...)
}

// tuiLogErrorf writes one error line of the TUI's own.
func tuiLogErrorf(format string, args ...any) {
	log.Errorf("tui: "+format, args...)
}
