// Package logging provides the service's structured JSON logger.
//
// Structured JSON from day one (TRD §18): every line is machine-parseable so
// decisions, latencies, and errors can be shipped to an aggregator unchanged.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New returns a JSON slog.Logger writing to stdout at the given level.
// level is one of debug|info|warn|error (case-insensitive); empty => info.
// It also installs the logger as the slog default.
func New(level string) *slog.Logger {
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(level),
	})
	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
