// Copyright (c) 2026 Visvasity LLC

package linuxcheck

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/visvasity/hostcheck/report"
	"github.com/visvasity/unixcmds"
)

// Defaults for Options.
const (
	defaultConcurrency = 8
	defaultTimeout     = 30 * time.Second
)

// Options tunes a CollectReport run. The zero value is valid; each field falls
// back to a documented default.
type Options struct {
	// Concurrency bounds how many collectors run at once. <= 0 uses the default.
	Concurrency int
	// Timeout bounds each individual collector; a hung command cannot stall the
	// whole report. <= 0 uses the default.
	Timeout time.Duration
	// Redactor applies the shared redaction policy. nil uses an unsalted
	// redactor (callers SHOULD supply a per-host salted one).
	Redactor *Redactor
	// Now supplies the report timestamp; nil uses time.Now. Present for tests.
	Now func() time.Time
}

// CollectReport runs the enabled collectors and assembles a report.Report.
//
// Every module in the catalog is assigned a status: a module disabled by cfg
// becomes StatusDisabled; an enabled module with a registered collector is
// collected; an enabled module with no collector in this build becomes
// StatusUnsupported (a visible coverage gap, not a silent omission). A single
// collector's failure is confined to its own section — the rest proceed.
//
// CollectReport does not itself warn about disabled identity-critical modules or
// validate the gateway-essential set; callers apply cfg.DisabledIdentityCritical
// and cfg.ValidateForGateway as policy requires.
func CollectReport(ctx context.Context, reg *Registry, runner unixcmds.Runner, cfg report.Config, opts Options) *report.Report {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	redact := opts.Redactor
	if redact == nil {
		redact = NewRedactor(nil)
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	env := &Env{Runner: runner, Redact: redact}

	rep := &report.Report{
		SchemaVersion:  report.SchemaVersion,
		GeneratedAt:    now().UTC(),
		Mode:           report.ModeLocal,
		Platform:       detectPlatform(ctx, env),
		EnabledModules: cfg.EnabledKeys(),
	}

	// Partition every catalog module: disabled and unsupported are set inline;
	// the runnable collectors are gathered for concurrent execution.
	var toRun []boundCollector
	for _, d := range report.Catalog {
		switch {
		case !cfg.Enabled(d.Key):
			applyStatus(rep, d.Key, report.StatusDisabled)
		case reg.Has(d.Key):
			bc, _ := reg.get(d.Key)
			toRun = append(toRun, bc)
		default:
			applyStatus(rep, d.Key, report.StatusUnsupported)
		}
	}

	// Run collectors concurrently, bounded by conc. Each writes its own distinct
	// Report section field, so concurrent writes do not race.
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for _, bc := range toRun {
		wg.Add(1)
		sem <- struct{}{}
		go func(bc boundCollector) {
			defer wg.Done()
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			bc.collect(cctx, env, rep)
		}(bc)
	}
	wg.Wait()

	return rep
}

// detectPlatform fills the minimal platform envelope from the target host. It is
// best-effort: a field that cannot be determined is left empty (the envelope is
// not a section and carries no status).
func detectPlatform(ctx context.Context, env *Env) report.Platform {
	var p report.Platform
	if s, err := output(ctx, env, "uname", "-s"); err == nil {
		p.OS = strings.ToLower(strings.TrimSpace(s))
	}
	if m, err := output(ctx, env, "uname", "-m"); err == nil {
		p.Arch = normalizeArch(strings.TrimSpace(m))
	}
	if data, err := env.Runner.ReadFile(ctx, "/etc/os-release"); err == nil {
		kv := parseOSRelease(string(data))
		p.Distribution = kv["ID"]
		p.Version = kv["VERSION_ID"]
	}
	return p
}

// normalizeArch maps uname -m machine names to Go-style arch names where known,
// returning the input unchanged otherwise.
func normalizeArch(m string) string {
	switch m {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7l", "armv6l":
		return "arm"
	case "i386", "i686":
		return "386"
	default:
		return m
	}
}

// parseOSRelease parses the KEY=VALUE lines of an os-release(5) file, stripping
// surrounding quotes from values.
func parseOSRelease(data string) map[string]string {
	kv := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		kv[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return kv
}

// applyStatus sets a data-less section status on the module identified by key.
// It handles every catalog module; a missing case would leave a section with an
// empty status, which TestApplyStatusCoversCatalog guards against.
func applyStatus(r *report.Report, key string, s report.Status) {
	switch key {
	case report.KeyAgent:
		r.Agent = report.Section[report.Agent]{Status: s}
	case report.KeyHostIdentity:
		r.HostIdentity = report.Section[report.HostIdentity]{Status: s}
	case report.KeyPublicIP:
		r.PublicIP = report.Section[report.PublicIP]{Status: s}
	case report.KeyFirewallPolicy:
		r.FirewallPolicy = report.Section[report.FirewallPolicy]{Status: s}
	case report.KeyFirewallAcceptedPorts:
		r.FirewallAcceptedPorts = report.Section[report.FirewallAcceptedPorts]{Status: s}
	case report.KeyFirewallRuleset:
		r.FirewallRuleset = report.Section[report.FirewallRuleset]{Status: s}
	case report.KeyListeningTCP:
		r.ListeningTCP = report.Section[report.ListeningSockets]{Status: s}
	case report.KeyListeningUDP:
		r.ListeningUDP = report.Section[report.ListeningSockets]{Status: s}
	case report.KeyNATForwarding:
		r.NATForwarding = report.Section[report.NATForwarding]{Status: s}
	case report.KeyInterfaces:
		r.Interfaces = report.Section[report.Interfaces]{Status: s}
	case report.KeyRoutes:
		r.Routes = report.Section[report.Routes]{Status: s}
	case report.KeySSHDConfig:
		r.SSHDConfig = report.Section[report.SSHDConfig]{Status: s}
	case report.KeySSHAuthorizedKeys:
		r.SSHAuthorizedKeys = report.Section[report.SSHAuthorizedKeys]{Status: s}
	case report.KeySSHHostKeys:
		r.SSHHostKeys = report.Section[report.SSHHostKeys]{Status: s}
	case report.KeyAccounts:
		r.Accounts = report.Section[report.Accounts]{Status: s}
	case report.KeySudoers:
		r.Sudoers = report.Section[report.Sudoers]{Status: s}
	case report.KeyPrivilegedGroups:
		r.PrivilegedGroups = report.Section[report.PrivilegedGroups]{Status: s}
	case report.KeyPasswordPolicy:
		r.PasswordPolicy = report.Section[report.PasswordPolicy]{Status: s}
	case report.KeyEnabledUnits:
		r.EnabledUnits = report.Section[report.EnabledUnits]{Status: s}
	case report.KeyTimersCron:
		r.TimersCron = report.Section[report.TimersCron]{Status: s}
	case report.KeyStartupPersistence:
		r.StartupPersistence = report.Section[report.StartupPersistence]{Status: s}
	case report.KeySysctlHardening:
		r.SysctlHardening = report.Section[report.SysctlHardening]{Status: s}
	case report.KeyOSProtections:
		r.OSProtections = report.Section[report.OSProtections]{Status: s}
	case report.KeySecureBoot:
		r.SecureBoot = report.Section[report.SecureBoot]{Status: s}
	case report.KeyOSUpdates:
		r.OSUpdates = report.Section[report.OSUpdates]{Status: s}
	case report.KeyPackageInventory:
		r.PackageInventory = report.Section[report.PackageInventory]{Status: s}
	case report.KeyPendingRestart:
		r.PendingRestart = report.Section[report.PendingRestart]{Status: s}
	case report.KeyContainers:
		r.Containers = report.Section[report.Containers]{Status: s}
	case report.KeyCriticalFileIntegrity:
		r.CriticalFileIntegrity = report.Section[report.CriticalFileIntegrity]{Status: s}
	case report.KeySSHLogins:
		r.SSHLogins = report.Section[report.SSHLogins]{Status: s}
	case report.KeySSHAuthFailures:
		r.SSHAuthFailures = report.Section[report.SSHAuthFailures]{Status: s}
	case report.KeySudoActivity:
		r.SudoActivity = report.Section[report.SudoActivity]{Status: s}
	case report.KeySudoAuthFailures:
		r.SudoAuthFailures = report.Section[report.SudoAuthFailures]{Status: s}
	case report.KeyIntrusionResponse:
		r.IntrusionResponse = report.Section[report.IntrusionResponse]{Status: s}
	case report.KeyServiceVersions:
		r.ServiceVersions = report.Section[report.ServiceVersions]{Status: s}
	case report.KeyLanguageLibraries:
		r.LanguageLibraries = report.Section[report.LanguageLibraries]{Status: s}
	}
}
