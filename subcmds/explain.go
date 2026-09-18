// Copyright (c) 2026 Visvasity LLC

package subcmds

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/visvasity/cli"
	"github.com/visvasity/hostcheck/linuxcheck"
	"github.com/visvasity/hostcheck/report"
)

// ExplainCmd shows, for every module, whether it will run and the exact commands
// it would execute. It does not touch the host.
type ExplainCmd struct {
	asJSON  bool
	enable  string
	disable string
	check   bool
}

func (c *ExplainCmd) Purpose() string {
	return "Show what each module would collect and the commands it runs"
}

func (c *ExplainCmd) Command() (string, *flag.FlagSet, cli.CmdFunc) {
	fset := flag.NewFlagSet("explain", flag.ContinueOnError)
	fset.BoolVar(&c.asJSON, "json", false, "emit machine-readable JSON")
	fset.StringVar(&c.enable, "enable", "", "comma-separated module keys to force on")
	fset.StringVar(&c.disable, "disable", "", "comma-separated module keys to force off")
	fset.BoolVar(&c.check, "check", false, "probe the host to show whether each command is available")
	return "explain", fset, c.run
}

func (c *ExplainCmd) run(ctx context.Context, args []string) error {
	// Without -check, explain does not touch the host. With it, resolve each
	// declared command's tool on the local host to show availability.
	var resolve toolResolver
	if c.check {
		runner := linuxcheck.LocalRunner()
		resolve = func(name string) (string, bool) {
			return linuxcheck.LookTool(ctx, runner, name)
		}
	}

	mods := buildExplain(linuxcheck.DefaultRegistry(), configFrom(c.enable, c.disable), resolve)
	if c.asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(mods)
	}
	printExplain(os.Stdout, mods)
	return nil
}

// toolResolver resolves a tool name to an absolute path on the host, reporting
// false when it is not found. It is nil when availability probing is disabled.
type toolResolver func(name string) (path string, found bool)

// explainCommand mirrors linuxcheck.Command for stable JSON output. Available
// and ResolvedPath are populated only when availability probing (-check) is on.
type explainCommand struct {
	Argv         []string `json:"argv"`
	Purpose      string   `json:"purpose,omitempty"`
	NeedsRoot    bool     `json:"needs_root"`
	Available    *bool    `json:"available,omitempty"`
	ResolvedPath string   `json:"resolved_path,omitempty"`
}

// explainModule is the per-module explain record.
type explainModule struct {
	Key              string           `json:"key"`
	State            string           `json:"state"` // will_run | unsupported | disabled
	Enabled          bool             `json:"enabled"`
	DefaultEnabled   bool             `json:"default_enabled"`
	Sensitivity      string           `json:"sensitivity"`
	IdentityCritical bool             `json:"identity_critical"`
	GatewayEssential bool             `json:"gateway_essential"`
	Commands         []explainCommand `json:"commands,omitempty"`
}

const (
	stateWillRun     = "will_run"
	stateUnsupported = "unsupported"
	stateDisabled    = "disabled"
)

// buildExplain computes the explain records for every catalog module under cfg,
// using reg as the capability set. Commands are shown for any registered module
// regardless of whether it is currently enabled (transparency). When resolve is
// non-nil, each command's tool is probed and its availability recorded.
func buildExplain(reg *linuxcheck.Registry, cfg report.Config, resolve toolResolver) []explainModule {
	out := make([]explainModule, 0, len(report.Catalog))
	for _, d := range report.Catalog {
		m := explainModule{
			Key:              d.Key,
			Enabled:          cfg.Enabled(d.Key),
			DefaultEnabled:   d.DefaultEnabled,
			Sensitivity:      d.Sensitivity.String(),
			IdentityCritical: d.IdentityCritical,
			GatewayEssential: d.GatewayEssential,
		}
		registered := reg.Has(d.Key)
		switch {
		case !m.Enabled:
			m.State = stateDisabled
		case registered:
			m.State = stateWillRun
		default:
			m.State = stateUnsupported
		}
		if registered {
			if cmds, ok := reg.Commands(d.Key); ok {
				for _, cm := range cmds {
					ec := explainCommand{Argv: cm.Argv, Purpose: cm.Purpose, NeedsRoot: cm.NeedsRoot}
					if resolve != nil && len(cm.Argv) > 0 {
						path, found := resolve(cm.Argv[0])
						ec.Available = &found
						if found {
							ec.ResolvedPath = path
						}
					}
					m.Commands = append(m.Commands, ec)
				}
			}
		}
		out = append(out, m)
	}
	return out
}

func printExplain(w *os.File, mods []explainModule) {
	var willRun, unsupported, disabled int
	for _, m := range mods {
		switch m.State {
		case stateWillRun:
			willRun++
		case stateUnsupported:
			unsupported++
		case stateDisabled:
			disabled++
		}
		fmt.Fprintf(w, "%-26s %-12s sens=%-9s %s\n", m.Key, m.State, m.Sensitivity, roleTags(m))
		for _, cm := range m.Commands {
			root := ""
			if cm.NeedsRoot {
				root = " (root)"
			}
			fmt.Fprintf(w, "    $ %s%s   %s%s\n", strings.Join(cm.Argv, " "), root, cm.Purpose, availabilityNote(cm))
		}
	}
	fmt.Fprintf(w, "\n%d will run, %d unsupported (no collector in this build), %d disabled\n",
		willRun, unsupported, disabled)
}

// availabilityNote renders the -check result for a command: nothing when not
// probed, the resolved path when found, or a "command not found" note otherwise.
func availabilityNote(cm explainCommand) string {
	if cm.Available == nil {
		return ""
	}
	if *cm.Available {
		return "   → " + cm.ResolvedPath
	}
	name := ""
	if len(cm.Argv) > 0 {
		name = cm.Argv[0]
	}
	return fmt.Sprintf("   [%s: command not found]", name)
}

func roleTags(m explainModule) string {
	var tags []string
	if m.GatewayEssential {
		tags = append(tags, "gateway-essential")
	}
	if m.IdentityCritical {
		tags = append(tags, "identity-critical")
	}
	return strings.Join(tags, ",")
}
