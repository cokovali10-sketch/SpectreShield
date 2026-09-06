//go:build linux

package logging

import (
	"log/slog"
	"os"
)

// Logger is a type alias for *slog.Logger
type Logger = slog.Logger

var defaultLogger *slog.Logger

func Init(level string, logFile string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			defaultLogger = slog.New(slog.NewJSONHandler(f, opts))
			return
		}
	}

	defaultLogger = slog.New(slog.NewJSONHandler(os.Stdout, opts))
}

func WithComponent(name string) *Logger {
	if defaultLogger == nil {
		Init("info", "")
	}
	return defaultLogger.With("component", name)
}

func NewLogger(name string) *Logger {
	return WithComponent(name)
}
