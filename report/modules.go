// Copyright (c) 2026 Visvasity LLC

package report

import "time"

// This file defines the payload struct for each collection module. Fields honor
// each module's redaction rules: values that must be hashed or reduced are
// documented as such, and raw secret material is never represented.

// ---- Shared value types --------------------------------------------------

// Package is a name/version pair used by inventory and version modules.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// PublishedPort is a port published to the host by a container. It is reported
// both by the nat-forwarding and the containers modules.
type PublishedPort struct {
	Protocol    string `json:"protocol"`               // "tcp" | "udp"
	BindClass   string `json:"bind_class"`             // "wildcard" | "routable" | "loopback"
	BindAddress string `json:"bind_address,omitempty"` // may be class-only under redaction
	HostPort    int    `json:"host_port"`
	Container   string `json:"container,omitempty"` // name/id; may be reduced under a strict profile
}

// ActivityWindow is embedded by the log-derived activity modules. Events are
// counted over [IntervalStart, IntervalEnd]; ReducedConfidence is set when the
// source logs were unavailable or rotated, so a gap is not read as "zero
// events".
type ActivityWindow struct {
	IntervalStart     time.Time `json:"interval_start"`
	IntervalEnd       time.Time `json:"interval_end"`
	ReducedConfidence bool      `json:"reduced_confidence,omitempty"`
}

// ---- Agent & host identity -----------------------------------------------

// Agent is the "agent" module: the agent's own identity and effective config.
type Agent struct {
	Version    string `json:"version"`
	Build      string `json:"build,omitempty"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	ConfigHash string `json:"config_hash"` // hash of the effective agent configuration
}

// HostIdentity is the "host-identity" module.
type HostIdentity struct {
	Hostname      string    `json:"hostname,omitempty"` // may be hashed under a strict profile
	MachineIDHash string    `json:"machine_id_hash"`    // stable machine id, hashed
	OS            string    `json:"os"`
	Distribution  string    `json:"distribution,omitempty"`
	Version       string    `json:"version,omitempty"`
	KernelVersion string    `json:"kernel_version,omitempty"`
	BootTime      time.Time `json:"boot_time,omitzero"`
	UptimeBucket  string    `json:"uptime_bucket,omitempty"` // coarse bucket, not exact seconds
}

// PublicIP is the "public-ip" module. It is gateway-essential but defaults to
// prefix redaction: IPv4/IPv6 hold network prefixes (or hashes) with Redacted
// true unless the operator explicitly opts into transmitting exact addresses.
// Prefix form still supports host correlation and change detection.
type PublicIP struct {
	IPv4     []string `json:"ipv4,omitempty"` // exact, prefix, or hash depending on Redacted
	IPv6     []string `json:"ipv6,omitempty"`
	Redacted bool     `json:"redacted,omitempty"` // true if reduced to prefix/hash (the default)
	Source   string   `json:"source,omitempty"`   // "routing" | "external-echo"
}

// ---- Network exposure ----------------------------------------------------

// FirewallPolicy is the "firewall-policy" module.
type FirewallPolicy struct {
	Active           bool   `json:"active"`
	Backend          string `json:"backend,omitempty"`  // nftables|iptables|ufw|firewalld|pf|alf
	InboundDefaultV4 string `json:"inbound_default_v4"` // "drop" | "reject" | "accept"
	InboundDefaultV6 string `json:"inbound_default_v6"`
	ForwardDefaultV4 string `json:"forward_default_v4,omitempty"`
	ForwardDefaultV6 string `json:"forward_default_v6,omitempty"`
}

// AcceptedPort is one permitted inbound port or range.
type AcceptedPort struct {
	Protocol    string `json:"protocol"`             // "tcp" | "udp"
	Port        int    `json:"port,omitempty"`       // single port; 0 when PortRange is set
	PortRange   string `json:"port_range,omitempty"` // e.g. "8000-8010"
	SourceScope string `json:"source_scope"`         // "any" | "restricted"
}

// FirewallAcceptedPorts is the "firewall-accepted-ports" module.
type FirewallAcceptedPorts struct {
	Ports []AcceptedPort `json:"ports"`
}

// FirewallRuleset is the "firewall-ruleset" module.
type FirewallRuleset struct {
	Backend     string   `json:"backend,omitempty"`
	Rules       []string `json:"rules,omitempty"` // normalized; source/dest IPs may be masked to prefixes
	RulesetHash string   `json:"ruleset_hash"`
}

// ListeningSocket is one listening socket.
type ListeningSocket struct {
	Protocol    string `json:"protocol"`               // "tcp" | "udp"
	BindClass   string `json:"bind_class"`             // "wildcard" | "routable" | "loopback"
	BindAddress string `json:"bind_address,omitempty"` // may be class-only under redaction
	Port        int    `json:"port"`
	Program     string `json:"program,omitempty"` // owning program name only (no path/args/PID)
}

// ListeningSockets is the payload for the "listening-tcp" and "listening-udp"
// modules.
type ListeningSockets struct {
	Sockets []ListeningSocket `json:"sockets"`
}

// NATRule is one DNAT/port-forward rule.
type NATRule struct {
	Protocol    string `json:"protocol"`
	MatchPort   int    `json:"match_port"`
	ForwardTo   string `json:"forward_to,omitempty"` // internal target; may be masked to a prefix
	ForwardPort int    `json:"forward_port,omitempty"`
}

// NATForwarding is the "nat-forwarding" module.
type NATForwarding struct {
	IPForwardV4             bool            `json:"ip_forward_v4"`
	IPForwardV6             bool            `json:"ip_forward_v6"`
	Rules                   []NATRule       `json:"rules,omitempty"`
	ContainerPublishedPorts []PublishedPort `json:"container_published_ports,omitempty"`
}

// Interface is one network interface.
type Interface struct {
	Name           string   `json:"name"`
	State          string   `json:"state,omitempty"`           // "up" | "down"
	AddressClasses []string `json:"address_classes,omitempty"` // loopback|private|public (or full addrs if not reduced)
}

// Interfaces is the "interfaces" module.
type Interfaces struct {
	Interfaces []Interface `json:"interfaces"`
}

// Route is one routing-table entry.
type Route struct {
	Destination string `json:"destination"`
	NextHop     string `json:"next_hop,omitempty"` // may be masked to a prefix
	Interface   string `json:"interface,omitempty"`
}

// Routes is the "routes" module.
type Routes struct {
	HasDefaultGatewayV4 bool    `json:"has_default_gateway_v4"`
	HasDefaultGatewayV6 bool    `json:"has_default_gateway_v6"`
	IPForward           bool    `json:"ip_forward"`
	Routes              []Route `json:"routes,omitempty"`
}

// ---- Remote access (SSH) -------------------------------------------------

// SSHDConfig is the "sshd-config" module, from the effective `sshd -T` output.
type SSHDConfig struct {
	Port                         []int    `json:"port,omitempty"`
	ListenAddressClass           []string `json:"listen_address_class,omitempty"` // wildcard|routable|loopback
	PermitRootLogin              string   `json:"permit_root_login,omitempty"`
	PasswordAuthentication       bool     `json:"password_authentication"`
	KbdInteractiveAuthentication bool     `json:"kbd_interactive_authentication"`
	PubkeyAuthentication         bool     `json:"pubkey_authentication"`
	PermitEmptyPasswords         bool     `json:"permit_empty_passwords"`
	X11Forwarding                bool     `json:"x11_forwarding"`
	AllowTCPForwarding           string   `json:"allow_tcp_forwarding,omitempty"`
	MaxAuthTries                 int      `json:"max_auth_tries,omitempty"`
	HasAllowUsers                bool     `json:"has_allow_users"` // presence only; names may be reduced to a count/hash
	HasAllowGroups               bool     `json:"has_allow_groups"`
	CipherStrengthSummary        string   `json:"cipher_strength_summary,omitempty"`
	MACStrengthSummary           string   `json:"mac_strength_summary,omitempty"`
	KexStrengthSummary           string   `json:"kex_strength_summary,omitempty"`
}

// AuthorizedKey is one authorized key, represented by a fingerprint only. Raw
// key material is never collected.
type AuthorizedKey struct {
	Type        string `json:"type"`        // e.g. "ssh-ed25519"
	Fingerprint string `json:"fingerprint"` // hash; never the raw key
}

// AuthorizedKeysFile is one user's authorized_keys inventory.
type AuthorizedKeysFile struct {
	User     string          `json:"user,omitempty"` // may be hashed under a strict profile
	Path     string          `json:"path,omitempty"`
	KeyCount int             `json:"key_count"`
	Keys     []AuthorizedKey `json:"keys,omitempty"`
	FileHash string          `json:"file_hash,omitempty"`
}

// SSHAuthorizedKeys is the "ssh-authorized-keys" module.
type SSHAuthorizedKeys struct {
	Files []AuthorizedKeysFile `json:"files"`
}

// HostKey is one SSH host public-key fingerprint.
type HostKey struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

// SSHHostKeys is the "ssh-hostkeys" module.
type SSHHostKeys struct {
	HostKeys []HostKey `json:"host_keys"`
}

// ---- Accounts & privilege ------------------------------------------------

// Account is one local account of interest.
type Account struct {
	Username     string `json:"username,omitempty"` // may be hashed
	UID          int    `json:"uid"`
	Shell        string `json:"shell,omitempty"`
	LoginCapable bool   `json:"login_capable"`
}

// Accounts is the "accounts" module.
type Accounts struct {
	UID0Accounts      []string  `json:"uid0_accounts"` // retained regardless of redaction; names may be hashed
	LoginCapableCount int       `json:"login_capable_count"`
	Accounts          []Account `json:"accounts,omitempty"`
}

// Sudoers is the "sudoers" module.
type Sudoers struct {
	ContentHash    string   `json:"content_hash"`
	SudoUsers      []string `json:"sudo_users,omitempty"` // may be hashed
	SudoGroups     []string `json:"sudo_groups,omitempty"`
	NopasswdGrants []string `json:"nopasswd_grants,omitempty"` // may be hashed/summarized
	Rules          []string `json:"rules,omitempty"`           // full normalized text; omitted in privacy mode
}

// PrivilegedGroup is one security-relevant group and its membership.
type PrivilegedGroup struct {
	Name        string   `json:"name"`              // sudo|wheel|docker|adm|lxd|...
	Members     []string `json:"members,omitempty"` // may be hashed
	MemberCount int      `json:"member_count"`
}

// PrivilegedGroups is the "privileged-groups" module.
type PrivilegedGroups struct {
	Groups []PrivilegedGroup `json:"groups"`
}

// PasswordAccount is per-account password hygiene metadata. Password hashes are
// never collected.
type PasswordAccount struct {
	Username         string `json:"username,omitempty"` // hashed
	Empty            bool   `json:"empty"`
	Locked           bool   `json:"locked"`
	MaxAgeDaysBucket string `json:"max_age_days_bucket,omitempty"`
}

// PasswordPolicy is the "password-policy" module.
type PasswordPolicy struct {
	EmptyPasswordAccounts []string          `json:"empty_password_accounts,omitempty"` // may be hashed
	LockedAccountCount    int               `json:"locked_account_count"`
	Accounts              []PasswordAccount `json:"accounts,omitempty"`
}

// ---- Services & scheduled execution --------------------------------------

// EnabledUnit is one enabled service/unit.
type EnabledUnit struct {
	Name string `json:"name"`
	Type string `json:"type,omitempty"` // service|socket|launchd-daemon|launchd-agent
}

// EnabledUnits is the "enabled-units" module.
type EnabledUnits struct {
	Units []EnabledUnit `json:"units"`
}

// ScheduledJob is one timer/cron/launchd job.
type ScheduledJob struct {
	Source      string `json:"source"` // systemd-timer|cron|at|launchd
	Name        string `json:"name,omitempty"`
	Schedule    string `json:"schedule,omitempty"`
	CommandHash string `json:"command_hash"` // command line reduced to a hash
}

// TimersCron is the "timers-cron" module.
type TimersCron struct {
	Jobs []ScheduledJob `json:"jobs"`
}

// PersistenceEntry is one startup/persistence location.
type PersistenceEntry struct {
	Location    string `json:"location"` // rc.local|profile.d|ld.so.preload|unit-dropin|launchd|login-item|...
	Path        string `json:"path,omitempty"`
	Present     bool   `json:"present"`
	ContentHash string `json:"content_hash,omitempty"` // contents represented by hash
}

// StartupPersistence is the "startup-persistence" module.
type StartupPersistence struct {
	Entries []PersistenceEntry `json:"entries"`
}

// ---- Kernel & platform hardening -----------------------------------------

// SysctlHardening is the "sysctl-hardening" module. Keys are the
// platform-specific sysctl names; values are their observed settings.
type SysctlHardening struct {
	Values map[string]string `json:"values"`
}

// OSProtections is the "os-protections" module. The SELinux/AppArmor fields
// describe Linux; the SIP/Gatekeeper/TCC fields describe macOS. Empty strings
// mean not present or not determinable on this platform.
type OSProtections struct {
	SELinux    string `json:"selinux,omitempty"`    // enforcing|permissive|disabled|absent
	AppArmor   string `json:"apparmor,omitempty"`   // enabled|disabled|absent
	SIP        string `json:"sip,omitempty"`        // enabled|disabled|unknown (macOS)
	Gatekeeper string `json:"gatekeeper,omitempty"` // enabled|disabled|unknown (macOS)
	TCC        string `json:"tcc,omitempty"`        // enabled|unknown (macOS)
}

// SecureBoot is the "secure-boot" module.
type SecureBoot struct {
	SecureBoot     string `json:"secure_boot,omitempty"`     // enabled|disabled|unknown
	KernelLockdown string `json:"kernel_lockdown,omitempty"` // Linux
	FileVault      string `json:"filevault,omitempty"`       // macOS
}

// ---- Software & patch posture --------------------------------------------

// OSUpdates is the "os-updates" module.
type OSUpdates struct {
	PendingTotal          int       `json:"pending_total"`
	PendingSecurity       int       `json:"pending_security"`
	OldestSecurityAgeDays int       `json:"oldest_security_age_days"` // patch lag; -1 if none pending
	AutoUpdatesEnabled    bool      `json:"auto_updates_enabled"`
	LastRunTime           time.Time `json:"last_run_time,omitzero"`
	LastRunOutcome        string    `json:"last_run_outcome,omitempty"` // success|failure|unknown
}

// PackageInventory is the "package-inventory" module.
type PackageInventory struct {
	Packages              []Package `json:"packages"`
	ListeningServicesOnly bool      `json:"listening_services_only,omitempty"` // true if reduced to service-providing packages
}

// PendingRestart is the "pending-restart" module: software that is installed but
// not yet active because a reboot or service restart is pending.
type PendingRestart struct {
	RebootRequired         bool     `json:"reboot_required"`
	RebootRequiredReasons  []string `json:"reboot_required_reasons,omitempty"` // kernel|glibc|openssl|systemd|dbus
	RebootRequiredAgeDays  int      `json:"reboot_required_age_days,omitempty"`
	RunningKernel          string   `json:"running_kernel,omitempty"`
	NewestInstalledKernel  string   `json:"newest_installed_kernel,omitempty"`
	KernelStale            bool     `json:"kernel_stale"`             // running kernel != newest installed
	ServicesNeedingRestart int      `json:"services_needing_restart"` // mapped to deleted/replaced libs
}

// ---- Containers & virtualization -----------------------------------------

// Containers is the "containers" module.
type Containers struct {
	Runtime              string          `json:"runtime,omitempty"` // docker|podman
	RunningCount         int             `json:"running_count"`
	PublishedPorts       []PublishedPort `json:"published_ports,omitempty"`
	ControlSocketExposed bool            `json:"control_socket_exposed"`
	PrivilegedContainers int             `json:"privileged_containers"`
}

// ---- File integrity ------------------------------------------------------

// FileHash is one critical file's presence and content hash.
type FileHash struct {
	Path    string `json:"path"`
	Present bool   `json:"present"`
	Hash    string `json:"hash,omitempty"` // content hash; no file contents
}

// CriticalFileIntegrity is the "critical-file-integrity" module.
type CriticalFileIntegrity struct {
	Files []FileHash `json:"files"`
}

// ---- Authentication & access activity ------------------------------------

// SSHLogins is the "ssh-logins" module.
type SSHLogins struct {
	ActivityWindow
	SuccessCount    int      `json:"success_count"`
	Accounts        []string `json:"accounts,omitempty"` // may be hashed
	DistinctSources int      `json:"distinct_sources"`
	Sources         []string `json:"sources,omitempty"` // prefixes/hashes by default
	NewSourceSeen   bool     `json:"new_source_seen"`   // retained regardless of redaction
	RootLoginSeen   bool     `json:"root_login_seen"`   // retained regardless of redaction
}

// SSHAuthFailures is the "ssh-auth-failures" module.
type SSHAuthFailures struct {
	ActivityWindow
	FailureCount     int      `json:"failure_count"`
	DistinctSources  int      `json:"distinct_sources"`
	TopTargetedUsers []string `json:"top_targeted_users,omitempty"` // may be hashed
}

// SudoActivity is the "sudo-activity" module.
type SudoActivity struct {
	ActivityWindow
	SuccessCount int      `json:"success_count"`
	Users        []string `json:"users,omitempty"` // may be hashed
	NopasswdUsed bool     `json:"nopasswd_used"`
}

// SudoAuthFailures is the "sudo-auth-failures" module.
type SudoAuthFailures struct {
	ActivityWindow
	FailureCount int      `json:"failure_count"`
	Users        []string `json:"users,omitempty"` // may be hashed
}

// IntrusionResponse is the "intrusion-response" module. The tool status (Active,
// Jails) is stable config; the counts are activity over the interval.
type IntrusionResponse struct {
	ActivityWindow
	Tool                string   `json:"tool,omitempty"` // fail2ban|sshguard|crowdsec
	Active              bool     `json:"active"`
	Jails               []string `json:"jails,omitempty"` // jails/scenarios enabled
	CurrentlyBanned     int      `json:"currently_banned"`
	BansAddedInInterval int      `json:"bans_added_in_interval"`
}

// ---- Software versions for vulnerability matching ------------------------

// ServiceVersion is one internet-facing program/library version.
type ServiceVersion struct {
	Program     string `json:"program"`
	Version     string `json:"version"`
	ExposedPort int    `json:"exposed_port,omitempty"` // set when the program owns a listening socket
}

// ServiceVersions is the "service-versions" module.
type ServiceVersions struct {
	Services []ServiceVersion `json:"services"`
}

// LanguageEcosystem is one language package manager's dependency set.
type LanguageEcosystem struct {
	Manager  string    `json:"manager"`         // pip|npm|go|gem|cargo|...
	Scope    string    `json:"scope,omitempty"` // application path this set was scoped to
	Packages []Package `json:"packages"`
}

// LanguageLibraries is the "language-libraries" module.
type LanguageLibraries struct {
	Ecosystems []LanguageEcosystem `json:"ecosystems"`
}
