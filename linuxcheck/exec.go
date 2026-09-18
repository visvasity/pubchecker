// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/visvasity/hostcheck/report"
	"github.com/visvasity/shcmd"
	"github.com/visvasity/unixcmds"
)

// LookTool resolves name to an absolute path on the host reachable via r,
// searching PATH and the standard admin directories. It reports false only when
// the tool is genuinely absent. It backs the `explain -check` availability view.
func LookTool(ctx context.Context, r unixcmds.Runner, name string) (string, bool) {
	return lookTool(ctx, &Env{Runner: r}, name)
}

// output runs name with args on the target and returns stdout. On failure the
// returned error wraps the underlying execution error (so classify can inspect
// it) and includes trimmed stderr for diagnostics.
func output(ctx context.Context, env *Env, name string, args ...string) (string, error) {
	sout, serr, err := shcmd.OutputString(ctx, env.Runner, name, args)
	if err != nil {
		if serr = strings.TrimSpace(serr); serr != "" {
			return sout, fmt.Errorf("%s: %w (stderr: %s)", name, err, serr)
		}
		return sout, fmt.Errorf("%s: %w", name, err)
	}
	return sout, nil
}

// sh runs a /bin/sh -c pipeline on the target and returns stdout. Use it for the
// pipeline-style collectors (e.g. `ss -tlnp | ...`); prefer output for a single
// command with arguments.
func sh(ctx context.Context, env *Env, script string) (string, error) {
	return output(ctx, env, "sh", "-c", script)
}

// toolSearchDirs are the standard directories searched, in addition to PATH,
// when resolving an admin binary. Many collectors need tools in the sbin dirs,
// which are frequently absent from PATH under sudo, cron, or non-login shells.
var toolSearchDirs = []string{
	"/usr/local/sbin", "/usr/local/bin",
	"/usr/sbin", "/sbin",
	"/usr/bin", "/bin",
}

// toolNameRE guards the tool name embedded in the lookup shell script. Names come
// from collectors (constants), but validating keeps the script injection-proof.
var toolNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// lookTool resolves name to an absolute path on the target, searching PATH first
// (via `command -v`) then toolSearchDirs, in a single sh probe. It reports false
// only when the tool is genuinely absent everywhere — letting a collector return
// not-applicable for "absent" while reserving error for "present but failed".
//
// Each call issues one probe; results are not cached (collectors resolve their
// few tools once per run).
func lookTool(ctx context.Context, env *Env, name string) (string, bool) {
	if !toolNameRE.MatchString(name) {
		return "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "command -v %s 2>/dev/null && exit 0\n", name)
	for _, d := range toolSearchDirs {
		fmt.Fprintf(&b, "if [ -x %s/%s ]; then printf '%%s\\n' %s/%s; exit 0; fi\n", d, name, d, name)
	}
	b.WriteString("exit 1\n")

	out, err := sh(ctx, env, b.String())
	if err != nil {
		return "", false
	}
	path := strings.TrimSpace(out)
	if path == "" {
		return "", false
	}
	return path, true
}

// classify maps a command execution error to a report status. A missing tool
// (local binary not found, or a shell exit code of 127) resolves to
// not-applicable — the provider simply is not present on this host. Any other
// failure is an error (reduced confidence). A nil error means the command
// succeeded.
func classify(err error) report.Status {
	if err == nil {
		return report.StatusCollected
	}
	// Local runner: the binary was not found.
	var execErr *exec.Error
	if errors.As(err, &execErr) {
		return report.StatusNotApplicable
	}
	// sudo/ssh/sh runners: the shell reports "command not found" as exit 127.
	if code, ok := exitCode(err); ok && code == 127 {
		return report.StatusNotApplicable
	}
	return report.StatusError
}

// exitCode extracts a process exit code from err across runner transports:
// *exec.ExitError (local/sudo) exposes ExitCode, while the ssh runner's error
// exposes ExitStatus. Returns false if err carries no exit code.
func exitCode(err error) (int, bool) {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), true
	}
	var se interface{ ExitStatus() int }
	if errors.As(err, &se) {
		return se.ExitStatus(), true
	}
	return 0, false
}
