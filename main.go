// Copyright (c) 2026 Visvasity LLC

// Command hostcheck is the Visvasity host-check agent. It collects a host's
// security-relevant state and (in later milestones) diffs it against a baseline
// and reports changes. Install with:
//
//	go install github.com/visvasity/hostcheck@latest
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/visvasity/cli"
	"github.com/visvasity/hostcheck/subcmds"
	"github.com/visvasity/runcmd"
)

func main() {
	cmds := []cli.Command{
		new(subcmds.CollectCmd),
		new(subcmds.ExplainCmd),
		new(subcmds.VersionCmd),
		runcmd.Wrap(new(subcmds.ServeCmd)),
	}
	if err := cli.Run(context.Background(), cmds, os.Args[1:]); err != nil {
		slog.Error("failed", "err", err)
		os.Exit(1)
	}
}
