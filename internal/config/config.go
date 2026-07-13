// Package config loads and validates the certel monitor configuration.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration wraps time.Duration so it can be parsed from YAML strings like "5m"
// or "90d". It accepts the units time.ParseDuration understands (ns…h) plus a
// "d" (day) unit, which is convenient for retention and repeat intervals.
type Duration time.Duration

// dayUnitRe matches a "<number>d" component. "d" is the only duration unit that
// contains the letter, so a match is unambiguously a day count.
var dayUnitRe = regexp.MustCompile(`(\d+(?:\.\d+)?)d`)

// expandDays rewrites each "<number>d" component into its hour equivalent so
// time.ParseDuration — which lacks a day unit — can parse the rest unchanged.
// A leading sign and any standard units are left in place, and Go sums repeated
// units, so "90d" -> "2160h" and "1d12h" -> "24h12h" (= 36h).
func expandDays(s string) string {
	return dayUnitRe.ReplaceAllStringFunc(s, func(m string) string {
		days, err := strconv.ParseFloat(m[:len(m)-1], 64)
		if err != nil {
			return m // leave malformed input for time.ParseDuration to reject
		}
		return strconv.FormatFloat(days*24, 'f', -1, 64) + "h"
	})
}

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(expandDays(s))
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

// repeatSeverities are the alerting severities a persisting problem can hold
// and therefore repeat on. They mirror the string values of probe.SeverityX
// (config cannot import probe — probe imports config — so the names are
// duplicated here rather than referenced). "ok" is excluded: a recovered
// target never repeats. The order is the message/iteration order.
var repeatSeverities = []string{"warning", "critical", "emergency"}

// RepeatInterval is how often a persisting problem is re-alerted. It is either
// a single cadence applied to every severity (scalar form, e.g. `24h`) or a
// per-severity map (e.g. `{warning: 3d, critical: 1d, emergency: 1d}`) so the
// reminder can tighten as severity rises. The map form must be complete —
// every severity in repeatSeverities must have an entry; a missing one is a
// config error, not a silent fall-back — while the scalar form is the explicit
// "same cadence for all" shorthand.
type RepeatInterval struct {
	// perSeverity holds the cadence per severity. Populated for both forms: the
	// scalar form fills every severity with the same value at unmarshal time, so
	// lookups never special-case which form was written. nil means unset (fills
	// from the default in applyDefaults).
	perSeverity map[string]Duration
	// isMap records that the map form was written, so Validate enforces the
	// complete-map/unknown-key rules the scalar form is exempt from and error
	// messages can name the offending entry.
	isMap bool
}

func (r *RepeatInterval) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		var d Duration
		if err := node.Decode(&d); err != nil {
			return err
		}
		*r = scalarRepeat(d)
		return nil
	case yaml.MappingNode:
		m := map[string]Duration{}
		if err := node.Decode(&m); err != nil {
			return err
		}
		*r = RepeatInterval{perSeverity: m, isMap: true}
		return nil
	default:
		return fmt.Errorf("alert_repeat_interval must be a duration (e.g. 24h) or a per-severity map (e.g. {warning: 3d, critical: 1d, emergency: 1d})")
	}
}

// scalarRepeat builds a RepeatInterval that applies one cadence to every
// severity — the scalar YAML form and the built-in default. Exported via
// NewRepeatInterval for tests and ad-hoc construction.
func scalarRepeat(d Duration) RepeatInterval {
	m := make(map[string]Duration, len(repeatSeverities))
	for _, s := range repeatSeverities {
		m[s] = d
	}
	return RepeatInterval{perSeverity: m}
}

// NewRepeatInterval builds a scalar RepeatInterval (one cadence for every
// severity), for callers constructing an AlertConfig outside the YAML loader.
func NewRepeatInterval(d Duration) RepeatInterval { return scalarRepeat(d) }

// NewRepeatIntervalMap builds a per-severity RepeatInterval from an explicit
// map, for callers constructing an AlertConfig outside the YAML loader. The map
// is used as-is (no completeness check — that is Validate's job on loaded
// config).
func NewRepeatIntervalMap(m map[string]Duration) RepeatInterval {
	cp := make(map[string]Duration, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return RepeatInterval{perSeverity: cp, isMap: true}
}

// unset reports whether no repeat_interval was configured, so applyDefaults can
// fill the default without clobbering an explicit value.
func (r RepeatInterval) unset() bool { return r.perSeverity == nil }

// For returns the repeat cadence for a severity. It is only consulted for the
// bad severities (warning/critical/emergency), which validation guarantees are
// present; an unknown severity yields 0, which the caller reads as "repeat now".
func (r RepeatInterval) For(severity string) time.Duration {
	return r.perSeverity[severity].Std()
}

// validate checks one alert_repeat_interval: every entry positive, the map form
// complete with no unknown severity keys, and every entry at least the probe
// check_interval floor (a cadence tighter than the probe loop can never fire and
// would silently degrade — a lie about the very cadence this promises). label is
// the full config path of the field (e.g. "targets[0] (a.com).alert_repeat_interval")
// so the message points at the offending target.
func (r RepeatInterval) validate(label string, checkInterval Duration) error {
	if r.isMap {
		known := map[string]bool{}
		for _, s := range repeatSeverities {
			known[s] = true
		}
		var unknown []string
		for k := range r.perSeverity {
			if !known[k] {
				unknown = append(unknown, k)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return fmt.Errorf("config: %s has unknown severity key(s): %s (valid: %s)",
				label, strings.Join(unknown, ", "), strings.Join(repeatSeverities, ", "))
		}
		var missing []string
		for _, s := range repeatSeverities {
			if _, ok := r.perSeverity[s]; !ok {
				missing = append(missing, s)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("config: %s is missing severity entr(ies): %s (the map form must list %s)",
				label, strings.Join(missing, ", "), strings.Join(repeatSeverities, ", "))
		}
	}
	for _, s := range repeatSeverities {
		d := r.perSeverity[s]
		entryLabel := label
		if r.isMap {
			entryLabel = fmt.Sprintf("%s[%s]", label, s)
		}
		if d.Std() <= 0 {
			return fmt.Errorf("config: %s must be positive (got %s)", entryLabel, d.Std())
		}
		if d.Std() < checkInterval.Std() {
			return fmt.Errorf("config: %s (%s) must not be shorter than probe.check_interval (%s)",
				entryLabel, d.Std(), checkInterval.Std())
		}
	}
	return nil
}

// isRepeatSeverity reports whether s is one of the alerting severities a floor
// or cadence can name (warning/critical/emergency). "ok" is excluded: it is not
// a floor (nothing to carry) and never repeats.
func isRepeatSeverity(s string) bool {
	for _, v := range repeatSeverities {
		if v == s {
			return true
		}
	}
	return false
}

// Protocol selects how the TLS session is established.
type Protocol string

const (
	ProtoTLS      Protocol = "tls" // implicit TLS from the first byte (https, smtps, imaps, ...)
	ProtoSMTP     Protocol = "smtp"
	ProtoIMAP     Protocol = "imap"
	ProtoPOP3     Protocol = "pop3"
	ProtoFTP      Protocol = "ftp"
	ProtoPostgres Protocol = "postgres"
)

// validAlertMethods bounds alert.method to real HTTP methods so a typo like
// "PYST" fails at startup instead of at the first (worst-timed) delivery.
var validAlertMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true,
}

var defaultPorts = map[Protocol]string{
	ProtoTLS:      "443",
	ProtoSMTP:     "587",
	ProtoIMAP:     "143",
	ProtoPOP3:     "110",
	ProtoFTP:      "21",
	ProtoPostgres: "5432",
}

// DefaultPort returns the port probed for a protocol when the target address
// does not name one, and whether the protocol is known. Exposed for the
// `certel check` command, which builds an ad-hoc Target outside the config
// loader and must default the port the same way.
func DefaultPort(p Protocol) (string, bool) {
	port, ok := defaultPorts[p]
	return port, ok
}

// Config is the root of the YAML configuration file.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Probe    ProbeConfig    `yaml:"probe"`
	Database DatabaseConfig `yaml:"database"`
	// Notifiers are the named delivery destinations, keyed by name. The map key
	// is the notifier name a target selects via its `notifiers` list, so name
	// uniqueness and by-name reference come for free (and yaml.v3 rejects
	// duplicate map keys under KnownFields).
	Notifiers      map[string]AlertConfig `yaml:"notifiers"`
	TargetDefaults TargetParams           `yaml:"target_defaults"`
	Targets        []Target               `yaml:"targets"`
}

// ServerConfig configures the built-in HTTP server that exposes the Prometheus
// metrics and health endpoints.
type ServerConfig struct {
	Listen string `yaml:"listen"`
}

// ProbeConfig controls the probe loop: how often targets are checked, how
// many are probed concurrently, and how much random delay spreads probes out
// within a cycle. Its concurrency is separate from alert.concurrency so probing
// and alert delivery do not share one budget.
type ProbeConfig struct {
	CheckInterval Duration `yaml:"check_interval"`
	Concurrency   int      `yaml:"concurrency"`
	Jitter        Duration `yaml:"jitter"`
}

// DatabaseConfig locates the SQLite database that persists alert state
// (so restarts do not re-send alerts or lose pending recoveries) and the
// probe/alert logs, and how long each log is kept before pruning.
type DatabaseConfig struct {
	Path              string   `yaml:"path"`
	ProbeLogRetention Duration `yaml:"probe_log_retention"`
	AlertLogRetention Duration `yaml:"alert_log_retention"`
}

// AlertConfig describes one named notifier: the webhook its alerts are
// delivered to, plus its own template, delivery policy and severity floor.
// Several notifiers coexist under Config.Notifiers, each fully independent. The
// repeat cadence is not here — it is a property of the problem on the target
// (TargetParams.AlertRepeatInterval), so several notifiers fanned out from one
// target share one reminder clock.
type AlertConfig struct {
	URL     string            `yaml:"url"`
	Method  string            `yaml:"method"`
	Headers map[string]string `yaml:"headers"`
	// Body is the notifier's message as a YAML structure: certel renders each
	// string leaf (resolving ${alert.Path} references) and json.Marshals the
	// whole thing, so authors write the message, never JSON braces. A value that
	// is exactly one ${alert.X} reference keeps its native JSON type. Required.
	Body map[string]any `yaml:"body"`
	// RecoveryBody is an optional sparse override applied when the alert is a
	// recovery: certel deep-merges it onto Body (maps merge key-by-key, a scalar
	// or array replaces), so only the diverging keys are written. Absent means
	// recovery reuses Body unchanged.
	RecoveryBody map[string]any `yaml:"recovery_body"`
	Timeout      Duration       `yaml:"timeout"`
	Retries      *int           `yaml:"retries"`
	// SendRecovery controls whether this notifier delivers a recovery ("cert
	// recovered") notice when a problem it tracked clears. A pointer so the
	// default is true (close the loop) while an unset field is distinguishable
	// from an explicit false: an auto-resolving receiver (PagerDuty) opts out
	// with send_recovery: false. Read via SendRecoveryEnabled, which treats the
	// unset pointer as the true default.
	SendRecovery *bool `yaml:"send_recovery"`
	// MinSeverity is the delivery floor: this notifier carries only alerts at or
	// above it, everything below reads as ok (no alert, a per-channel recovery
	// when a problem drops beneath the floor). A stateless filter — the clamp is
	// recomputed each cycle from the real per-target severity, never stored.
	// Default "warning" (carry every alert); valid values are the alerting
	// severities warning/critical/emergency.
	MinSeverity string `yaml:"min_severity"`
	// CAFile is a PEM trust anchor for the webhook endpoint itself — the
	// internal receiver (Mattermost, ntfy, a company relay) behind an internal
	// CA, mirroring the per-target ca_file option.
	CAFile string `yaml:"ca_file"`
	// Insecure skips verification of the webhook endpoint's certificate. Last
	// resort for a self-signed receiver; prefer ca_file.
	Insecure bool `yaml:"insecure"`
	// Concurrency caps how many targets the outbox dispatcher delivers to at once.
	// Independent of the top-level probe concurrency so alert delivery and
	// probing do not share one budget.
	Concurrency int `yaml:"concurrency"`
}

// SendRecoveryEnabled reports whether this notifier delivers recovery notices.
// A nil SendRecovery (the unset pointer) reads as true — the default — so a
// runtime built outside the config loader still closes the loop; applyDefaults
// fills the pointer for loaded configs so an explicit false survives.
func (a AlertConfig) SendRecoveryEnabled() bool {
	return a.SendRecovery == nil || *a.SendRecovery
}

// TargetParams are per-target settings that can also be set globally in defaults.
type TargetParams struct {
	WarningDays  *int      `yaml:"warning_days"`
	CriticalDays *int      `yaml:"critical_days"`
	Timeout      *Duration `yaml:"timeout"`
	// ConnectRetries is how many extra connection attempts a probe makes before
	// declaring a target `unreachable` — an intra-cycle "try harder" knob that
	// governs only the connection, distinct from the cross-cycle FlapStreak
	// debounce below. A pointer so it falls through target_defaults like the
	// thresholds.
	ConnectRetries *int `yaml:"connect_retries"`
	// Notifiers are the destinations this target's alerts fan out to: one
	// per-target decision, one clamped delivery per attached notifier. Set via
	// `notifiers: [a, b]`. An unset value falls through target_defaults exactly
	// like the thresholds; each resolved name must exist (validated).
	Notifiers []string `yaml:"notifiers"`
	// AlertRepeatInterval is how often a persisting problem on this target is
	// re-alerted — a property of the problem, not the channel, so it lives here
	// and is shared by every notifier the target fans out to. Scalar (same
	// cadence for all severities) or a per-severity map so the reminder tightens
	// as severity rises; the cadence is read on the real (unclamped) severity.
	// Falls through target_defaults like the thresholds.
	AlertRepeatInterval RepeatInterval `yaml:"alert_repeat_interval"`
	// FlapStreak is how many consecutive flapping cycles a transition into (or
	// out of) an unreliable, network-shaped status — unreachable, tls_unavailable
	// — must persist before it is trusted and alerted on. It debounces flapping
	// that a single probe blip would otherwise turn into an alert/recovery pair.
	// 1 disables the debounce (alert on first observation, the pre-debounce
	// behaviour). Fact statuses (expired, invalid, ...) are computed from a
	// retrieved certificate and are never debounced regardless of this value. A
	// pointer so it falls through target_defaults like the thresholds.
	FlapStreak *int `yaml:"flap_streak"`
}

// Target is a single monitored TLS endpoint: a (protocol, address, servername)
// triple. One host/address can expose several targets (ports, protocols, SNI).
type Target struct {
	Address    string   `yaml:"address"`
	Servername string   `yaml:"servername"`
	Protocol   Protocol `yaml:"protocol"`
	CAFile     string   `yaml:"ca_file"`
	// Insecure skips chain-of-trust and hostname verification; expiry is
	// still checked. For targets with self-signed certificates.
	Insecure     bool `yaml:"insecure"`
	TargetParams `yaml:",inline"`
}

// Key uniquely identifies a monitored target. It is used for config
// duplicate detection, alert-state tracking and database rows, so its format
// must stay stable across versions.
func (t Target) Key() string {
	return string(t.Protocol) + "//" + t.Address + "/" + t.Servername
}

// EffectiveServername returns the name used for SNI and hostname verification.
func (t Target) EffectiveServername() string {
	if t.Servername != "" {
		return t.Servername
	}
	host, _, err := net.SplitHostPort(t.Address)
	if err != nil {
		return t.Address
	}
	return host
}

// envRe matches one interpolation token: an optional leading "$" escape then
// "${...}". The inner content is "namespace.rest"; only the env namespace is
// resolved here — ${alert.*} references are left untouched for the alert
// renderer, and a "$${env.X}" escape becomes a literal "${env.X}".
var envRe = regexp.MustCompile(`(\$?)\$\{([^}]*)\}`)

// expandEnv substitutes ${env.VAR} references from the environment. It is
// single-pass: it leaves ${alert.*} and anything that is not an env reference
// untouched, decodes "$${env.X}" to a literal "${env.X}", and fails on an unset
// variable so a missing secret is caught at startup, not at alert time.
func expandEnv(s string) (string, error) {
	var missing []string
	out := envRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := envRe.FindStringSubmatch(m)
		escaped, inner := sub[1] == "$", sub[2]
		trimmed := strings.TrimSpace(inner)
		name, isEnv := strings.CutPrefix(trimmed, "env.")
		if !isEnv {
			return m // not an env reference: leave verbatim
		}
		if escaped {
			return "${" + trimmed + "}"
		}
		name = strings.TrimSpace(name)
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("environment variable(s) not set: %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// expandEnvTree resolves ${env.*} references in every string leaf of a decoded
// body structure (map/array/scalars) in place, so secrets in a body are resolved
// once at load like those in url and headers.
func expandEnvTree(v any) error {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if s, ok := val.(string); ok {
				expanded, err := expandEnv(s)
				if err != nil {
					return err
				}
				x[k] = expanded
				continue
			}
			if err := expandEnvTree(val); err != nil {
				return err
			}
		}
	case []any:
		for i, val := range x {
			if s, ok := val.(string); ok {
				expanded, err := expandEnv(s)
				if err != nil {
					return err
				}
				x[i] = expanded
				continue
			}
			if err := expandEnvTree(val); err != nil {
				return err
			}
		}
	}
	return nil
}

// defaultDatabasePath places the database in a db/ directory next to the
// running binary — not in the working directory, which for a service is
// often / or a checkout root. Falls back to ./db when the executable path
// cannot be determined.
func defaultDatabasePath() string {
	exe, err := os.Executable()
	if err != nil {
		return filepath.Join("db", "certel.sqlite")
	}
	return filepath.Join(filepath.Dir(exe), "db", "certel.sqlite")
}

// ListenAddress reads only server.listen from a configuration file, applying
// the same default as Load. The healthcheck command uses it instead of Load so
// a liveness probe does not depend on parts of the config it never touches —
// most importantly ${env.VAR} header expansion, which would fail the probe when
// run from an environment (admin shell, systemd ExecStartPost) that lacks the
// notifier secrets the monitor itself was started with. The flip side is that
// it accepts a config Load would reject; that is validate-config's job, not
// the liveness probe's.
func ListenAddress(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var partial struct {
		Server ServerConfig `yaml:"server"`
	}
	if err := yaml.Unmarshal(raw, &partial); err != nil {
		return "", fmt.Errorf("parsing %s: %w", path, err)
	}
	if partial.Server.Listen == "" {
		return defaultListen, nil
	}
	return partial.Server.Listen, nil
}

// Load reads, parses, applies defaults to and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if err := cfg.applyDefaults(); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// defaultListen is the fallback server.listen address, shared by Load and
// ListenAddress so the healthcheck probes the same port the monitor binds.
const defaultListen = ":8880"

func (c *Config) applyDefaults() error {
	if c.Probe.CheckInterval == 0 {
		c.Probe.CheckInterval = Duration(5 * time.Minute)
	}
	if c.Probe.Concurrency <= 0 {
		c.Probe.Concurrency = 10
	}
	if c.Server.Listen == "" {
		c.Server.Listen = defaultListen
	}
	if c.Database.Path == "" {
		c.Database.Path = defaultDatabasePath()
	}
	if c.Database.ProbeLogRetention == 0 {
		c.Database.ProbeLogRetention = Duration(90 * 24 * time.Hour)
	}
	if c.Database.AlertLogRetention == 0 {
		c.Database.AlertLogRetention = Duration(365 * 24 * time.Hour)
	}
	// Default each notifier independently. Iterate sorted so a header-expansion
	// error is reported for the same notifier across runs. Map values are copies,
	// so scalar fields are written back via reassignment; Headers is a map
	// (reference) and is mutated in place.
	for _, name := range sortedKeys(c.Notifiers) {
		n := c.Notifiers[name]
		if n.Method == "" {
			n.Method = "POST"
		}
		if n.Timeout == 0 {
			n.Timeout = Duration(10 * time.Second)
		}
		if n.Concurrency <= 0 {
			n.Concurrency = 10
		}
		if n.SendRecovery == nil {
			// Default true: a notifier that omits send_recovery still closes the
			// loop when a problem clears. An auto-resolving receiver opts out with
			// an explicit send_recovery: false, which this pointer preserves.
			v := true
			n.SendRecovery = &v
		}
		if n.Retries == nil {
			// "extra attempts after the first", matching target retries — 2 keeps
			// the long-standing default of 3 total delivery attempts. A pointer so
			// an explicit 0 (deliver once, never retry) survives defaulting, per
			// notifier.
			v := 2
			n.Retries = &v
		}
		if n.MinSeverity == "" {
			// The lowest alerting severity: the channel carries every alert, the
			// pre-floor behaviour.
			n.MinSeverity = "warning"
		}
		expandedURL, err := expandEnv(n.URL)
		if err != nil {
			return fmt.Errorf("notifiers[%s].url: %w", name, err)
		}
		n.URL = expandedURL
		for k, v := range n.Headers {
			expanded, err := expandEnv(v)
			if err != nil {
				return fmt.Errorf("notifiers[%s].headers[%s]: %w", name, k, err)
			}
			n.Headers[k] = expanded
		}
		if err := expandEnvTree(n.Body); err != nil {
			return fmt.Errorf("notifiers[%s].body: %w", name, err)
		}
		if err := expandEnvTree(n.RecoveryBody); err != nil {
			return fmt.Errorf("notifiers[%s].recovery_body: %w", name, err)
		}
		c.Notifiers[name] = n
	}
	if c.TargetDefaults.WarningDays == nil {
		v := 30
		c.TargetDefaults.WarningDays = &v
	}
	if c.TargetDefaults.CriticalDays == nil {
		v := 7
		c.TargetDefaults.CriticalDays = &v
	}
	if c.TargetDefaults.Timeout == nil {
		v := Duration(10 * time.Second)
		c.TargetDefaults.Timeout = &v
	}
	if c.TargetDefaults.ConnectRetries == nil {
		v := 2
		c.TargetDefaults.ConnectRetries = &v
	}
	if c.TargetDefaults.FlapStreak == nil {
		// Two consecutive bad cycles: with in-probe connect_retries that means a
		// network blip must outlive roughly one full check_interval before it alerts.
		v := 2
		c.TargetDefaults.FlapStreak = &v
	}
	if c.TargetDefaults.AlertRepeatInterval.unset() {
		c.TargetDefaults.AlertRepeatInterval = scalarRepeat(Duration(24 * time.Hour))
	}

	// The default notifier list each target inherits unless it names its own.
	defaultNotifiers := c.TargetDefaults.Notifiers

	for i := range c.Targets {
		t := &c.Targets[i]
		if t.Protocol == "" {
			t.Protocol = ProtoTLS
		}
		if _, _, err := net.SplitHostPort(t.Address); err != nil && t.Address != "" {
			if port, ok := defaultPorts[t.Protocol]; ok {
				t.Address = net.JoinHostPort(t.Address, port)
			}
		}
		if t.WarningDays == nil {
			t.WarningDays = c.TargetDefaults.WarningDays
		}
		if t.CriticalDays == nil {
			t.CriticalDays = c.TargetDefaults.CriticalDays
		}
		if t.Timeout == nil {
			t.Timeout = c.TargetDefaults.Timeout
		}
		if t.ConnectRetries == nil {
			t.ConnectRetries = c.TargetDefaults.ConnectRetries
		}
		if len(t.Notifiers) == 0 {
			t.Notifiers = defaultNotifiers
		}
		if t.FlapStreak == nil {
			t.FlapStreak = c.TargetDefaults.FlapStreak
		}
		if t.AlertRepeatInterval.unset() {
			t.AlertRepeatInterval = c.TargetDefaults.AlertRepeatInterval
		}
	}
	return nil
}

// sortedKeys returns the map keys in ascending order, so iteration over a
// notifier map is deterministic — "first problem found" is stable across runs
// and tests.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Validate returns a descriptive error for the first problem found.
func (c *Config) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("config: no targets to monitor (targets list is empty)")
	}
	if len(c.Notifiers) == 0 {
		return fmt.Errorf("config: no notifiers defined (at least one is required)")
	}
	// Validate each notifier in name order so the first reported problem is
	// stable across runs. An empty map key is rejected up front: it would
	// otherwise surface only as a confusing "unknown notifier \"\"" on targets.
	for _, name := range sortedKeys(c.Notifiers) {
		n := c.Notifiers[name]
		if name == "" {
			return fmt.Errorf("config: notifier name must not be empty")
		}
		if n.URL == "" {
			return fmt.Errorf("config: notifiers[%s].url is required", name)
		}
		u, err := url.Parse(n.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("config: notifiers[%s].url %q is not a valid http(s) URL", name, n.URL)
		}
		if len(n.Body) == 0 {
			return fmt.Errorf("config: notifiers[%s].body is required", name)
		}
		if !validAlertMethods[n.Method] {
			return fmt.Errorf("config: notifiers[%s].method %q is not a supported HTTP method (supported: GET, POST, PUT, PATCH, DELETE)", name, n.Method)
		}
		if n.Timeout.Std() <= 0 {
			return fmt.Errorf("config: notifiers[%s].timeout must be positive (got %s)", name, n.Timeout.Std())
		}
		if !isRepeatSeverity(n.MinSeverity) {
			return fmt.Errorf("config: notifiers[%s].min_severity %q is not valid (valid: %s)",
				name, n.MinSeverity, strings.Join(repeatSeverities, ", "))
		}
		if n.Retries != nil && *n.Retries < 0 {
			return fmt.Errorf("config: notifiers[%s].retries must not be negative (got %d)", name, *n.Retries)
		}
		if n.CAFile != "" {
			if _, err := os.Stat(n.CAFile); err != nil {
				return fmt.Errorf("config: notifiers[%s].ca_file: %v", name, err)
			}
		}
	}
	// Durations must be positive: a zero or negative check_interval panics
	// time.NewTicker, a non-positive timeout makes every probe instantly fail,
	// and a negative log retention moves the prune cutoff into the future,
	// deleting the whole log. Reject rather than silently clamp.
	if c.Probe.CheckInterval.Std() <= 0 {
		return fmt.Errorf("config: probe.check_interval must be positive (got %s)", c.Probe.CheckInterval.Std())
	}
	if c.Probe.Jitter.Std() < 0 {
		return fmt.Errorf("config: probe.jitter must not be negative (got %s)", c.Probe.Jitter.Std())
	}
	if c.Database.ProbeLogRetention.Std() <= 0 {
		return fmt.Errorf("config: database.probe_log_retention must be positive (got %s)", c.Database.ProbeLogRetention.Std())
	}
	if c.Database.AlertLogRetention.Std() <= 0 {
		return fmt.Errorf("config: database.alert_log_retention must be positive (got %s)", c.Database.AlertLogRetention.Std())
	}
	seen := map[string]bool{}
	for i, t := range c.Targets {
		if t.Address == "" {
			return fmt.Errorf("config: targets[%d]: address is required", i)
		}
		// Protocol first: an unknown protocol also prevents default-port
		// substitution, and "unknown protocol" is the actionable message.
		if _, ok := defaultPorts[t.Protocol]; !ok {
			return fmt.Errorf("config: targets[%d] (%s): unknown protocol %q (supported: tls, smtp, imap, pop3, ftp, postgres)",
				i, t.Address, t.Protocol)
		}
		if _, _, err := net.SplitHostPort(t.Address); err != nil {
			return fmt.Errorf("config: targets[%d]: invalid address %q: %v", i, t.Address, err)
		}
		if t.CAFile != "" {
			if _, err := os.Stat(t.CAFile); err != nil {
				return fmt.Errorf("config: targets[%d] (%s): ca_file: %v", i, t.Address, err)
			}
		}
		if *t.CriticalDays > *t.WarningDays {
			return fmt.Errorf("config: targets[%d] (%s): critical_days (%d) must not exceed warning_days (%d)",
				i, t.Address, *t.CriticalDays, *t.WarningDays)
		}
		if t.Timeout.Std() <= 0 {
			return fmt.Errorf("config: targets[%d] (%s): timeout must be positive (got %s)", i, t.Address, t.Timeout.Std())
		}
		if *t.ConnectRetries < 0 {
			return fmt.Errorf("config: targets[%d] (%s): connect_retries must not be negative (got %d)", i, t.Address, *t.ConnectRetries)
		}
		// flap_streak counts cycles, so it must be at least 1 (alert on the
		// first observation, i.e. debounce disabled); 0 or negative would mean a
		// transition can never be confirmed.
		if *t.FlapStreak < 1 {
			return fmt.Errorf("config: targets[%d] (%s): flap_streak must be at least 1 (got %d)", i, t.Address, *t.FlapStreak)
		}
		// Selector resolution is always explicit: an unset notifier (no
		// target_defaults.notifiers and no per-target value) is an error even when a
		// single notifier is defined — no implicit pick. Each attached notifier must
		// resolve to a defined one; duplicates and an empty name get their own
		// messages so they do not read as "unknown notifier \"\"".
		if len(t.Notifiers) == 0 {
			return fmt.Errorf("config: targets[%d] (%s): no notifier (set target_defaults.notifiers or the target's notifiers)", i, t.Address)
		}
		seenNotifier := map[string]bool{}
		for _, name := range t.Notifiers {
			switch {
			case name == "":
				return fmt.Errorf("config: targets[%d] (%s): notifier must not be empty", i, t.Address)
			case seenNotifier[name]:
				return fmt.Errorf("config: targets[%d] (%s): duplicate notifier %q", i, t.Address, name)
			default:
				if _, ok := c.Notifiers[name]; !ok {
					return fmt.Errorf("config: targets[%d] (%s): unknown notifier %q", i, t.Address, name)
				}
			}
			seenNotifier[name] = true
		}
		if err := t.AlertRepeatInterval.validate(
			fmt.Sprintf("targets[%d] (%s).alert_repeat_interval", i, t.Address), c.Probe.CheckInterval); err != nil {
			return err
		}
		key := t.Key()
		if seen[key] {
			return fmt.Errorf("config: targets[%d]: duplicate entry for %s (%s)", i, t.Address, t.Protocol)
		}
		seen[key] = true
	}
	return nil
}
