// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"github.com/visvasity/shcmd"
	"github.com/visvasity/unixcmds"
)

// LocalRunner returns a runner that executes commands and file operations on the
// local host via os/exec. It is the runner the on-host agent uses (running as
// root under systemd).
func LocalRunner() unixcmds.Runner {
	return unixcmds.Runner{Runner: shcmd.Runtime()}
}
