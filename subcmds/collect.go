// Copyright (c) 2026 Visvasity LLC

package subcmds

import (
	"context"
	"encoding/json"
	"flag"
	"os"

	"github.com/visvasity/cli"
	"github.com/visvasity/hostcheck/linuxcheck"
)

// CollectCmd runs the enabled collectors once against the local host and prints
// the resulting report as JSON. It is the foreground, one-shot counterpart to
// the `run` service.
type CollectCmd struct {
	enable  string
	disable string
	compact bool
}

func (c *CollectCmd) Purpose() string {
	return "Run the enabled collectors once and print the report as JSON"
}

func (c *CollectCmd) Command() (string, *flag.FlagSet, cli.CmdFunc) {
	fset := flag.NewFlagSet("collect", flag.ContinueOnError)
	fset.StringVar(&c.enable, "enable", "", "comma-separated module keys to force on")
	fset.StringVar(&c.disable, "disable", "", "comma-separated module keys to force off")
	fset.BoolVar(&c.compact, "compact", false, "emit compact (non-indented) JSON")
	return "collect", fset, c.run
}

func (c *CollectCmd) run(ctx context.Context, args []string) error {
	cfg := configFrom(c.enable, c.disable)
	reg := linuxcheck.DefaultRegistry()
	rep := linuxcheck.CollectReport(ctx, reg, linuxcheck.LocalRunner(), cfg, linuxcheck.Options{})

	enc := json.NewEncoder(os.Stdout)
	if !c.compact {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(rep)
}
