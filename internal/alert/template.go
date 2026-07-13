package alert

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/antonkomarev/certel/internal/config"
	"github.com/antonkomarev/certel/internal/probe"
)

// The alert body is a structured YAML value (map/array/scalars) whose string
// leaves carry ${alert.Path} references. There is no Go text/template and no
// hand-built JSON: certel renders each string against a Payload and marshals the
// whole structure to JSON. Secrets (${env.VAR}) are resolved once at config load
// by config.expandEnv; only ${alert.*} survives to render time here.

// refRe matches one interpolation token: an optional leading "$" (the escape, so
// "$${x}" is a literal "${x}") followed by "${...}". The inner content is
// "namespace.rest" — e.g. "alert.Cert.NotAfter | human" or "env.TOKEN".
var refRe = regexp.MustCompile(`(\$?)\$\{([^}]*)\}`)

// wholeRefRe matches a string that is exactly one token and nothing else, used
// to detect the whole-scalar type rule (a value of exactly "${alert.DaysLeft}"
// keeps its native JSON type rather than becoming a string).
var wholeRefRe = regexp.MustCompile(`^(\$?)\$\{([^}]*)\}$`)

// alertFields is the single source of truth for valid ${alert.Path} references:
// it drives both the load-time reference check and render-time resolution. Every
// new field must be added here and populated in NewPayload.
var alertFields = map[string]bool{
	"Host": true, "Address": true, "Port": true, "Protocol": true,
	"Status": true, "Severity": true, "Message": true, "Recovered": true,
	"DaysLeft": true, "CheckedAt": true,
	"Cert.Subject": true, "Cert.SubjectCN": true, "Cert.Issuer": true,
	"Cert.IssuerCN": true, "Cert.IssuerOrg": true, "Cert.NotBefore": true,
	"Cert.NotAfter": true, "Cert.EarliestNotAfter": true, "Cert.SigAlg": true,
	"Cert.Serial": true, "Cert.SANs": true,
}

// alertTimeFields marks the timestamp fields: only these accept a "| format"
// suffix. The check is enforced both statically (at load) and at render.
var alertTimeFields = map[string]bool{
	"CheckedAt": true, "Cert.NotBefore": true, "Cert.NotAfter": true,
	"Cert.EarliestNotAfter": true,
}

// fieldVal is one resolved alert field. For an ordinary field native holds the
// JSON-native value (string/int/bool/[]string) so the whole-scalar type rule can
// keep it typed. For a timestamp isTime is set and t carries the time, formatted
// on demand by a preset or strftime suffix; a zero t renders empty.
type fieldVal struct {
	native any
	isTime bool
	t      time.Time
}

// Payload is the per-alert data a body renders against: a flat field map plus
// the recovery flag that selects the recovery body. Build it with NewPayload.
type Payload struct {
	Recovered bool
	fields    map[string]fieldVal
}

// NewPayload flattens a probe result into the alert field map. Cert.* fields are
// always present — empty when the handshake never completed (Cert == nil) — so a
// reference to a cert field renders empty rather than erroring, exactly like an
// unset scalar.
func NewPayload(r probe.Result, recovered bool) Payload {
	host, port, err := net.SplitHostPort(r.Target.Address)
	if err != nil {
		host, port = r.Target.Address, ""
	}
	var c probe.CertInfo
	if r.Cert != nil {
		c = *r.Cert
	}
	f := map[string]fieldVal{
		"Host":                  {native: host},
		"Address":               {native: r.Target.Address},
		"Port":                  {native: port},
		"Protocol":              {native: string(r.Target.Protocol)},
		"Status":                {native: string(r.Status)},
		"Severity":              {native: string(r.Severity)},
		"Message":               {native: r.Message},
		"Recovered":             {native: recovered},
		"DaysLeft":              {native: r.DaysLeft},
		"CheckedAt":             {isTime: true, t: r.CheckedAt},
		"Cert.Subject":          {native: c.Subject},
		"Cert.SubjectCN":        {native: c.CN},
		"Cert.Issuer":           {native: c.Issuer},
		"Cert.IssuerCN":         {native: c.IssuerCN},
		"Cert.IssuerOrg":        {native: c.IssuerOrg},
		"Cert.SigAlg":           {native: c.SignatureAlgorithm},
		"Cert.Serial":           {native: c.Serial},
		"Cert.SANs":             {native: c.SANs},
		"Cert.NotBefore":        {isTime: true, t: c.NotBefore},
		"Cert.NotAfter":         {isTime: true, t: c.NotAfter},
		"Cert.EarliestNotAfter": {isTime: true, t: c.EarliestNotAfter},
	}
	return Payload{Recovered: recovered, fields: f}
}

// Body is a compiled alert body: the firing structure plus, when a recovery_body
// override was configured, the deep-merged recovery structure. Both are raw
// (pre-render) YAML values validated at build time.
type Body struct {
	fire     map[string]any
	recovery map[string]any // nil when no recovery_body override
}

// ParseBody validates a notifier's body (and optional recovery_body) and returns
// a compiled Body. It checks every ${alert.*} reference against the field
// allowlist, merges recovery_body onto body, and sample-renders both so a broken
// reference or an encoding/format bug fails at startup, not at alert time. Env
// references are expected to have been resolved already at config load.
func ParseBody(body, recoveryBody map[string]any) (*Body, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("alert.body is empty")
	}
	if err := validateRefs(body); err != nil {
		return nil, err
	}
	b := &Body{fire: body}
	if len(recoveryBody) > 0 {
		if err := validateRefs(recoveryBody); err != nil {
			return nil, err
		}
		b.recovery = deepMerge(body, recoveryBody)
	}
	sample := samplePayload()
	if _, err := b.Render(sample); err != nil {
		return nil, fmt.Errorf("alert.body failed sample render: %w", err)
	}
	if b.recovery != nil {
		sample.Recovered = true
		if _, err := b.Render(sample); err != nil {
			return nil, fmt.Errorf("alert.recovery_body failed sample render: %w", err)
		}
	}
	return b, nil
}

// Render resolves the body against a payload and marshals it to JSON. When the
// alert is a recovery and a recovery_body override was configured, the merged
// recovery structure is rendered instead of the firing body.
func (b *Body) Render(p Payload) ([]byte, error) {
	src := b.fire
	if p.Recovered && b.recovery != nil {
		src = b.recovery
	}
	rendered, err := renderValue(src, p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(rendered)
}

// renderValue walks a raw body structure, resolving string leaves and passing
// bool/number/null and nested containers through unchanged.
func renderValue(v any, p Payload) (any, error) {
	switch x := v.(type) {
	case string:
		return renderString(x, p)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			rv, err := renderValue(val, p)
			if err != nil {
				return nil, err
			}
			out[k] = rv
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			rv, err := renderValue(val, p)
			if err != nil {
				return nil, err
			}
			out[i] = rv
		}
		return out, nil
	default:
		return v, nil
	}
}

// renderString resolves one string leaf. A value that is exactly one
// ${alert.Path} reference keeps the field's native JSON type (the whole-scalar
// rule); any other string interpolates references into a string.
func renderString(s string, p Payload) (any, error) {
	if path, format, ok := wholeAlertRef(s); ok {
		return p.resolveNative(path, format)
	}
	return substitute(s, "alert", func(rest string) (string, error) {
		path, format := parseRef(rest)
		return p.resolveString(path, format)
	})
}

// substitute scans s once, resolving ${ns.rest} tokens whose namespace is ns via
// resolve, turning an escaped "$${ns...}" into a literal "${ns...}", and leaving
// every other token (other namespaces, escapes) verbatim for another pass. It is
// single-pass and non-recursive: a resolved value is never re-scanned, so an
// interpolated cert field cannot itself be interpreted as a reference.
func substitute(s, ns string, resolve func(rest string) (string, error)) (string, error) {
	var rerr error
	out := refRe.ReplaceAllStringFunc(s, func(m string) string {
		sub := refRe.FindStringSubmatch(m)
		escaped, inner := sub[1] == "$", sub[2]
		name, rest, ok := cutNamespace(inner)
		if !ok || name != ns {
			return m // not our namespace: leave verbatim for a later pass
		}
		if escaped {
			return "${" + strings.TrimSpace(inner) + "}"
		}
		v, err := resolve(rest)
		if err != nil {
			rerr = err
			return m
		}
		return v
	})
	if rerr != nil {
		return "", rerr
	}
	return out, nil
}

// resolveString returns the interpolation (string) form of an ${alert.*}
// reference. A missing field or a format on a non-timestamp field is an error.
func (p Payload) resolveString(path, format string) (string, error) {
	fv, ok := p.fields[path]
	if !ok {
		return "", fmt.Errorf("unknown alert field %q", path)
	}
	if fv.isTime {
		return formatTime(fv.t, format)
	}
	if format != "" {
		return "", fmt.Errorf("field %q is not a timestamp, cannot apply format %q", path, format)
	}
	return toString(fv.native), nil
}

// resolveNative returns the JSON-native form for a whole-scalar reference — a
// number stays a number, a bool a bool. Timestamps are always JSON strings.
func (p Payload) resolveNative(path, format string) (any, error) {
	fv, ok := p.fields[path]
	if !ok {
		return nil, fmt.Errorf("unknown alert field %q", path)
	}
	if fv.isTime {
		return formatTime(fv.t, format)
	}
	if format != "" {
		return nil, fmt.Errorf("field %q is not a timestamp, cannot apply format %q", path, format)
	}
	return fv.native, nil
}

// validateRefs walks a raw body structure and checks every ${alert.*} reference
// in its string leaves against the field allowlist and the timestamp rule for
// format suffixes.
func validateRefs(v any) error {
	switch x := v.(type) {
	case string:
		return checkStringRefs(x)
	case map[string]any:
		for _, val := range x {
			if err := validateRefs(val); err != nil {
				return err
			}
		}
	case []any:
		for _, val := range x {
			if err := validateRefs(val); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkStringRefs(s string) error {
	for _, m := range refRe.FindAllStringSubmatch(s, -1) {
		escaped, inner := m[1] == "$", m[2]
		if escaped {
			continue // an escaped $${...} literal is never a reference
		}
		name, rest, ok := cutNamespace(inner)
		if !ok {
			// A bare ${VAR} with no namespace is a mistake (the old pre-1.0
			// syntax). Reject it rather than emit it verbatim; a literal is $${...}.
			return fmt.Errorf("${%s} has no namespace (use ${env.%s}, ${alert...}, or $${%s} for a literal)",
				strings.TrimSpace(inner), strings.TrimSpace(inner), strings.TrimSpace(inner))
		}
		switch name {
		case "alert":
			path, format := parseRef(rest)
			if !alertFields[path] {
				return fmt.Errorf("unknown alert field ${alert.%s}", path)
			}
			if format != "" && !alertTimeFields[path] {
				return fmt.Errorf("format %q applied to non-timestamp field ${alert.%s}", format, path)
			}
		case "env":
			// A surviving unescaped ${env.X} is an escaped literal that config
			// load already decoded; a genuine env reference was resolved there.
		default:
			return fmt.Errorf("unknown reference namespace in ${%s} (valid: env, alert)", strings.TrimSpace(inner))
		}
	}
	return nil
}

// wholeAlertRef reports whether s is exactly one unescaped ${alert.Path}
// reference, returning its path and optional format.
func wholeAlertRef(s string) (path, format string, ok bool) {
	m := wholeRefRe.FindStringSubmatch(s)
	if m == nil || m[1] == "$" {
		return "", "", false
	}
	name, rest, cut := cutNamespace(m[2])
	if !cut || name != "alert" {
		return "", "", false
	}
	p, f := parseRef(rest)
	return p, f, true
}

// cutNamespace splits "namespace.rest" on the first dot. Leading/trailing space
// around the whole token is tolerated so "${ alert.Host }" parses.
func cutNamespace(inner string) (ns, rest string, ok bool) {
	inner = strings.TrimSpace(inner)
	i := strings.IndexByte(inner, '.')
	if i < 0 {
		return "", "", false
	}
	return inner[:i], inner[i+1:], true
}

// parseRef splits a reference remainder into its field path and optional format
// suffix, e.g. "Cert.NotAfter | human" -> ("Cert.NotAfter", "human").
func parseRef(rest string) (path, format string) {
	if i := strings.IndexByte(rest, '|'); i >= 0 {
		return strings.TrimSpace(rest[:i]), strings.TrimSpace(rest[i+1:])
	}
	return strings.TrimSpace(rest), ""
}

// deepMerge overlays over onto base: nested maps merge key-by-key recursively; a
// scalar or array at a key replaces. Untouched subtrees are shared (render only
// reads them). Used to apply a sparse recovery_body onto the firing body.
func deepMerge(base, over map[string]any) map[string]any {
	out := make(map[string]any, len(base))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		if bm, ok := out[k].(map[string]any); ok {
			if om, ok := v.(map[string]any); ok {
				out[k] = deepMerge(bm, om)
				continue
			}
		}
		out[k] = v
	}
	return out
}

// toString renders a native field value for interpolation inside a larger
// string. A nil (empty cert field) yields "".
func toString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case []string:
		return strings.Join(x, ", ")
	default:
		return fmt.Sprint(x)
	}
}

const layoutDatetime = "2006-01-02 15:04:05"

// presetLayouts maps a named date preset to its Go layout. No Go reference
// layout is ever exposed in config; authors use these names or strftime.
var presetLayouts = map[string]string{
	"datetime": layoutDatetime,
	"date":     "2006-01-02",
	"time":     "15:04:05",
	"human":    "Jan 02, 2006 15:04",
	"rfc3339":  "2006-01-02T15:04:05Z07:00",
}

// formatTime renders a timestamp in UTC. An empty format is the datetime preset;
// a format containing "%" is strftime; otherwise it is a named preset. A zero
// time renders empty, matching an unset scalar.
func formatTime(t time.Time, format string) (string, error) {
	if t.IsZero() {
		return "", nil
	}
	t = t.UTC()
	switch {
	case format == "":
		return t.Format(layoutDatetime), nil
	case strings.ContainsRune(format, '%'):
		return t.Format(strftimeToLayout(format)), nil
	default:
		layout, ok := presetLayouts[format]
		if !ok {
			return "", fmt.Errorf("unknown date format %q (presets: date, datetime, time, human, rfc3339, or a strftime pattern)", format)
		}
		return t.Format(layout), nil
	}
}

// strftimeMap translates the common strftime directives to Go layout fragments.
var strftimeMap = map[string]string{
	"%Y": "2006", "%y": "06", "%m": "01", "%d": "02", "%e": "_2",
	"%H": "15", "%I": "03", "%M": "04", "%S": "05", "%p": "PM",
	"%b": "Jan", "%B": "January", "%a": "Mon", "%A": "Monday",
	"%Z": "MST", "%z": "-0700", "%%": "%",
}

// strftimeToLayout converts a strftime pattern to a Go layout. An unknown "%X"
// directive is passed through literally.
func strftimeToLayout(f string) string {
	var b strings.Builder
	for i := 0; i < len(f); {
		if f[i] == '%' && i+1 < len(f) {
			if repl, ok := strftimeMap[f[i:i+2]]; ok {
				b.WriteString(repl)
				i += 2
				continue
			}
		}
		b.WriteByte(f[i])
		i++
	}
	return b.String()
}

// samplePayload is a fully populated payload (every field incl. Cert.*) used to
// sample-render a body at load so encoding and format bugs surface at startup.
// The message carries quotes and a newline to exercise JSON escaping.
func samplePayload() Payload {
	r := probe.Result{
		Target:    config.Target{Address: "example.com:443", Protocol: config.ProtoTLS},
		Status:    probe.StatusExpiringSoon,
		Severity:  probe.SeverityWarning,
		Message:   "certificate expires in 10 day(s), with \"quotes\" and\na newline to exercise escaping",
		CheckedAt: time.Date(2026, 1, 1, 7, 47, 0, 0, time.UTC),
		DaysLeft:  10,
		Cert: &probe.CertInfo{
			Subject:            "CN=example.com",
			CN:                 "example.com",
			Issuer:             "CN=R13,O=Let's Encrypt,C=US",
			IssuerCN:           "R13",
			IssuerOrg:          "Let's Encrypt",
			SignatureAlgorithm: "SHA-256 with RSA encryption",
			SANs:               []string{"example.com", "www.example.com"},
			Serial:             "123456789",
			NotBefore:          time.Date(2026, 4, 27, 7, 47, 0, 0, time.UTC),
			NotAfter:           time.Date(2026, 7, 26, 7, 47, 0, 0, time.UTC),
			EarliestNotAfter:   time.Date(2026, 7, 26, 7, 47, 0, 0, time.UTC),
		},
	}
	return NewPayload(r, false)
}
