// Copyright (c) 2026 Visvasity LLC

package subcmds

import (
	"context"
	"flag"
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/visvasity/cli"
)

// VersionCmd prints the version embedded in the binary by the Go toolchain.
type VersionCmd struct{}

func (c *VersionCmd) Purpose() string { return "Print version and build information" }

func (c *VersionCmd) Command() (string, *flag.FlagSet, cli.CmdFunc) {
	return "version", flag.NewFlagSet("version", flag.ContinueOnError), c.run
}

func (c *VersionCmd) run(ctx context.Context, args []string) error {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Println("hostcheck (unknown: build info unavailable)")
		return nil
	}
	fmt.Println(formatVersion(bi))
	return nil
}

// formatVersion renders a one-line version string from build info. The module
// version comes from `go install module@version` (e.g. "v1.2.3") and is
// "(devel)" for local builds; the VCS revision/time/dirty flag are stamped by
// the toolchain when building from a repository.
func formatVersion(bi *debug.BuildInfo) string {
	version := bi.Main.Version
	if version == "" {
		version = "(unknown)"
	}

	var revision, buildTime string
	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			buildTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "hostcheck %s", version)
	if revision != "" {
		if len(revision) > 12 {
			revision = revision[:12]
		}
		fmt.Fprintf(&b, " (%s", revision)
		if modified {
			b.WriteString("-dirty")
		}
		if buildTime != "" {
			fmt.Fprintf(&b, ", %s", buildTime)
		}
		b.WriteString(")")
	}
	if bi.GoVersion != "" {
		fmt.Fprintf(&b, " %s", bi.GoVersion)
	}
	return b.String()
}
