// Package report defines the data model produced by the HostCheck local agent.
//
// A Report is a single canonical snapshot of a host's security-relevant state.
// It is organized into modules, each covering one category of data (listening
// sockets, firewall policy, SSH configuration, and so on). Every module is an
// independently toggleable unit identified by a stable key, and each is wrapped
// in a Section[T] that records how the module resolved on this host (collected,
// disabled, not-applicable, unsupported, or error) so a consumer can tell "not
// collected" from "collected but empty" and interpret platform-conditioned
// results.
//
// Baselines, diffs, and incidents are computed over Reports elsewhere; this
// package only describes what was collected.
package report

import "time"

// SchemaVersion is the version of the Report envelope schema. Individual modules
// additionally carry their own Section.Schema.
const SchemaVersion = "0.1.0"

// Mode identifies which HostCheck mode produced a report: the on-host local
// agent, or an external remote check.
type Mode string

const (
	ModeLocal  Mode = "local"  // on-host agent (this package's focus)
	ModeRemote Mode = "remote" // external remote check
)

// Status is the resolution of a collection module on a given host.
type Status string

const (
	// StatusCollected: the module ran and Data is populated (possibly empty).
	StatusCollected Status = "collected"
	// StatusDisabled: the operator turned the module off. Nothing was read into
	// memory, stored, or uploaded.
	StatusDisabled Status = "disabled"
	// StatusNotApplicable: no meaningful provider exists on this platform (for
	// example, a systemd-specific module on macOS). Not an incident, and not
	// "no exposure".
	StatusNotApplicable Status = "not_applicable"
	// StatusUnsupported: the fact exists on this platform, but this build of the
	// agent has no provider for it yet. Distinct from not-applicable so coverage
	// gaps stay visible.
	StatusUnsupported Status = "unsupported"
	// StatusError: collection was attempted but failed or was incomplete. Treat
	// as reduced confidence, not "no change".
	StatusError Status = "error"
)

// Section wraps a collection module's payload with its resolution metadata.
// A nil Data is expected for every Status other than StatusCollected.
type Section[T any] struct {
	Status   Status `json:"status"`
	Provider string `json:"provider,omitempty"` // platform provider that supplied the data
	Schema   int    `json:"schema,omitempty"`   // module schema version
	Error    string `json:"error,omitempty"`    // detail when Status is error
	Data     *T     `json:"data,omitempty"`
}

// Get returns the payload and whether it was actually collected.
func (s Section[T]) Get() (*T, bool) {
	return s.Data, s.Status == StatusCollected && s.Data != nil
}

// Platform is the minimal, always-present platform envelope needed to interpret
// per-module providers. The richer, toggleable host identity lives in the
// HostIdentity module.
type Platform struct {
	OS           string `json:"os"`                     // "linux" | "darwin" | "freebsd" | ...
	Distribution string `json:"distribution,omitempty"` // e.g. "debian", "rhel", "macos"
	Version      string `json:"version,omitempty"`
	Arch         string `json:"arch"` // e.g. "amd64", "arm64"
}

// Report is one canonical snapshot from the local agent. Each Section field is a
// collection module; the comment on each field gives the module's stable key.
type Report struct {
	// Envelope.
	SchemaVersion  string    `json:"schema_version"`
	GeneratedAt    time.Time `json:"generated_at"` // UTC capture time
	Mode           Mode      `json:"mode"`
	Platform       Platform  `json:"platform"`
	EnabledModules []string  `json:"enabled_modules"` // exact set of module keys enabled this run

	// Agent & host identity (identity-critical: disabling these can leave a
	// report unattributable).
	Agent        Section[Agent]        `json:"agent"`         // key: agent
	HostIdentity Section[HostIdentity] `json:"host_identity"` // key: host-identity
	PublicIP     Section[PublicIP]     `json:"public_ip"`     // key: public-ip

	// Network exposure.
	FirewallPolicy        Section[FirewallPolicy]        `json:"firewall_policy"`         // key: firewall-policy
	FirewallAcceptedPorts Section[FirewallAcceptedPorts] `json:"firewall_accepted_ports"` // key: firewall-accepted-ports
	FirewallRuleset       Section[FirewallRuleset]       `json:"firewall_ruleset"`        // key: firewall-ruleset
	ListeningTCP          Section[ListeningSockets]      `json:"listening_tcp"`           // key: listening-tcp
	ListeningUDP          Section[ListeningSockets]      `json:"listening_udp"`           // key: listening-udp
	NATForwarding         Section[NATForwarding]         `json:"nat_forwarding"`          // key: nat-forwarding
	Interfaces            Section[Interfaces]            `json:"interfaces"`              // key: interfaces
	Routes                Section[Routes]                `json:"routes"`                  // key: routes

	// Remote access (SSH).
	SSHDConfig        Section[SSHDConfig]        `json:"sshd_config"`         // key: sshd-config
	SSHAuthorizedKeys Section[SSHAuthorizedKeys] `json:"ssh_authorized_keys"` // key: ssh-authorized-keys
	SSHHostKeys       Section[SSHHostKeys]       `json:"ssh_host_keys"`       // key: ssh-hostkeys

	// Accounts & privilege.
	Accounts         Section[Accounts]         `json:"accounts"`          // key: accounts
	Sudoers          Section[Sudoers]          `json:"sudoers"`           // key: sudoers
	PrivilegedGroups Section[PrivilegedGroups] `json:"privileged_groups"` // key: privileged-groups
	PasswordPolicy   Section[PasswordPolicy]   `json:"password_policy"`   // key: password-policy

	// Services & scheduled execution.
	EnabledUnits       Section[EnabledUnits]       `json:"enabled_units"`       // key: enabled-units
	TimersCron         Section[TimersCron]         `json:"timers_cron"`         // key: timers-cron
	StartupPersistence Section[StartupPersistence] `json:"startup_persistence"` // key: startup-persistence

	// Kernel & platform hardening.
	SysctlHardening Section[SysctlHardening] `json:"sysctl_hardening"` // key: sysctl-hardening
	OSProtections   Section[OSProtections]   `json:"os_protections"`   // key: os-protections
	SecureBoot      Section[SecureBoot]      `json:"secure_boot"`      // key: secure-boot

	// Software & patch posture.
	OSUpdates        Section[OSUpdates]        `json:"os_updates"`        // key: os-updates
	PackageInventory Section[PackageInventory] `json:"package_inventory"` // key: package-inventory
	PendingRestart   Section[PendingRestart]   `json:"pending_restart"`   // key: pending-restart

	// Containers & virtualization.
	Containers Section[Containers] `json:"containers"` // key: containers

	// File integrity.
	CriticalFileIntegrity Section[CriticalFileIntegrity] `json:"critical_file_integrity"` // key: critical-file-integrity

	// Authentication & access activity (log-derived).
	SSHLogins         Section[SSHLogins]         `json:"ssh_logins"`         // key: ssh-logins
	SSHAuthFailures   Section[SSHAuthFailures]   `json:"ssh_auth_failures"`  // key: ssh-auth-failures
	SudoActivity      Section[SudoActivity]      `json:"sudo_activity"`      // key: sudo-activity
	SudoAuthFailures  Section[SudoAuthFailures]  `json:"sudo_auth_failures"` // key: sudo-auth-failures
	IntrusionResponse Section[IntrusionResponse] `json:"intrusion_response"` // key: intrusion-response

	// Software versions for vulnerability matching.
	ServiceVersions   Section[ServiceVersions]   `json:"service_versions"`   // key: service-versions
	LanguageLibraries Section[LanguageLibraries] `json:"language_libraries"` // key: language-libraries
}
