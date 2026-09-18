// Copyright (c) 2026 Visvasity LLC

package subcmds

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/visvasity/appdirs"
	"github.com/visvasity/cli"
	"github.com/visvasity/hostcheck/linuxcheck"
	"github.com/visvasity/hostcheck/report"
	"github.com/visvasity/logdir"
	"github.com/visvasity/runcmd"
)

// ServeCmd runs the host-check agent as a service: it collects a report on a
// fixed interval and writes it to the data directory. Wrapped by runcmd.Wrap, it
// gains -background, -restart, and -self-monitor for systemd/daemon use.
//
// Baseline diffing, alerting, and upload are added in later milestones; for now
// each run overwrites the latest report.
type ServeCmd struct {
	dirs appdirs.Config

	interval  time.Duration
	logDebug  bool
	logStderr bool
}

func (c *ServeCmd) Purpose() string {
	return "Run the host-check agent as a periodic service"
}

func (c *ServeCmd) Command() (string, *flag.FlagSet, cli.CmdFunc) {
	c.dirs.Program = "hostcheck"
	fset := new(flag.FlagSet)
	c.dirs.SetFlags(fset, &c.dirs)
	fset.DurationVar(&c.interval, "interval", 15*time.Minute, "Interval between collections")
	fset.BoolVar(&c.logDebug, "log-debug", false, "When true, enables debug logging")
	fset.BoolVar(&c.logStderr, "logtostderr", false, "When true, logs are written only to stderr")
	return "run", fset, c.run
}

// LocksDir tells runcmd where to place its daemon lock/socket files.
func (c *ServeCmd) LocksDir() string {
	return c.dirs.RuntimeDir
}

func (c *ServeCmd) Check(ctx context.Context) error {
	c.dirs.Program = "hostcheck"
	if err := c.dirs.Check(ctx); err != nil {
		return err
	}
	if c.interval <= 0 {
		return fmt.Errorf("interval (-interval) must be positive")
	}
	if r, ok := runcmd.FromContext(ctx); ok && r.Background && c.logStderr {
		return fmt.Errorf("logging to stderr (-logtostderr) cannot be used with -background")
	}
	return nil
}

func (c *ServeCmd) run(ctx context.Context, args []string) error {
	if err := c.Check(ctx); err != nil {
		return err
	}

	level := slog.LevelInfo
	if c.logDebug {
		level = slog.LevelDebug
	}
	slog.SetLogLoggerLevel(level)
	if !c.logStderr {
		sink, err := logdir.Open(logdir.Config{Dir: c.dirs.LogDir, Level: level})
		if err != nil {
			return err
		}
		slog.SetDefault(sink.Logger(""))
	}

	if err := os.MkdirAll(c.dirs.DataDir, 0o700); err != nil {
		return fmt.Errorf("could not create data dir %q: %w", c.dirs.DataDir, err)
	}

	runner := linuxcheck.LocalRunner()
	reg := linuxcheck.DefaultRegistry()

	collect := func() {
		rep := linuxcheck.CollectReport(ctx, reg, runner, report.Config{}, linuxcheck.Options{})
		if err := writeReport(c.dirs.DataDir, rep); err != nil {
			slog.Error("could not write report", "err", err)
			return
		}
		slog.Info("collected report", "enabled_modules", len(rep.EnabledModules), "generated_at", rep.GeneratedAt)
	}

	// First collection doubles as the initialization step; report its outcome to
	// the foreground/monitor process so -background can succeed or fail fast.
	collect()
	runcmd.Report(ctx, nil)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()
	slog.Info("host-check agent started", "interval", c.interval, "data_dir", c.dirs.DataDir)
	for {
		select {
		case <-ctx.Done():
			slog.Info("host-check agent stopping", "cause", context.Cause(ctx))
			return nil
		case <-ticker.C:
			collect()
		}
	}
}

// writeReport writes rep as indented JSON to <dir>/report.json atomically
// (write to a temp file, then rename).
func writeReport(dir string, rep *report.Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "report-*.json.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(dir, "report.json"))
}
