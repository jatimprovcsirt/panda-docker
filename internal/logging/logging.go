// Package logging configures the service logger.
//
// Logs go to stdout, which is the container convention — the platform collects
// them, and nothing writes a file the container would lose on restart.
//
// Note this is the *operator's* log: startup, requests, provider errors. The
// audit trail is a different stream with a different schema; see
// internal/service.AuditRecord. Keeping them separate matters because they
// answer different questions and are read by different people.
package logging

import (
	"log/slog"
	"os"
	"strings"
)

// New builds the logger from the configured format and level.
func New(format, level string) *slog.Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{Level: parseLevel(level)}

	// Text is easier to read in a terminal during development; JSON is what
	// the platform expects in a cluster. The default is JSON because the
	// deployed case is the one that cannot be changed after the fact.
	if strings.EqualFold(format, "text") {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		// Anything unrecognised becomes info rather than erroring. A typo in a
		// log level should not stop a crypto service from starting — the
		// config layer validates what actually matters.
		return slog.LevelInfo
	}
}
