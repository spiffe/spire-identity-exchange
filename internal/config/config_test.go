package config

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func listener(port int) ListenerConfig { return ListenerConfig{Enable: true, Port: port} }

func TestListenerEnabled(t *testing.T) {
	cases := []struct {
		name string
		lc   ListenerConfig
		want bool
	}{
		{"enabled with port", ListenerConfig{Enable: true, Port: 8443}, true},
		{"zero port disables even when enabled", ListenerConfig{Enable: true, Port: 0}, false},
		{"port without enable", ListenerConfig{Enable: false, Port: 8443}, false},
		{"zero value", ListenerConfig{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.lc.Enabled(); got != c.want {
				t.Errorf("Enabled() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestServerConfigPredicates(t *testing.T) {
	cfg := ServerConfig{
		MetricsPort: 4950,
		TLS:         TLSConfig{REST: listener(8444)},
		SPIFFE:      SPIFFEServerConfig{GRPC: listener(8543)},
	}

	for name, got := range map[string]bool{
		"FileTLSEnabled": cfg.FileTLSEnabled(),
		"SPIFFEEnabled":  cfg.SPIFFEEnabled(),
		"AnyGRPCEnabled": cfg.AnyGRPCEnabled(),
		"AnyRESTEnabled": cfg.AnyRESTEnabled(),
		"AnyEnabled":     cfg.AnyEnabled(),
	} {
		if !got {
			t.Errorf("%s() = false, want true", name)
		}
	}

	empty := ServerConfig{MetricsPort: 4950}
	if empty.AnyEnabled() {
		t.Error("AnyEnabled() = true for a config with no listeners")
	}
}

// writeCertPair creates a cert/key pair on disk. Validate only stats the paths,
// so the contents are irrelevant here.
func writeCertPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	dir := t.TempDir()
	certFile = filepath.Join(dir, "server.crt")
	keyFile = filepath.Join(dir, "server.key")
	for _, p := range []string{certFile, keyFile} {
		if err := os.WriteFile(p, []byte("placeholder"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return certFile, keyFile
}

func TestServerConfigValidate(t *testing.T) {
	certFile, keyFile := writeCertPair(t)

	cases := []struct {
		name    string
		cfg     ServerConfig
		wantErr string // substring; empty means Validate must succeed
	}{
		{
			name: "spiffe only needs no certificate files",
			cfg: ServerConfig{
				MetricsPort: 4950,
				SPIFFE:      SPIFFEServerConfig{GRPC: listener(8543), REST: listener(8544)},
			},
		},
		{
			name: "all four listeners",
			cfg: ServerConfig{
				MetricsPort: 4950,
				TLS:         TLSConfig{CertFile: certFile, KeyFile: keyFile, GRPC: listener(8443), REST: listener(8444)},
				SPIFFE:      SPIFFEServerConfig{GRPC: listener(8543), REST: listener(8544)},
			},
		},
		{
			name: "enabled with zero port is disabled, not an error",
			cfg: ServerConfig{
				MetricsPort: 4950,
				TLS:         TLSConfig{CertFile: certFile, KeyFile: keyFile, GRPC: listener(8443), REST: ListenerConfig{Enable: true, Port: 0}},
			},
		},
		{
			name:    "nothing enabled",
			cfg:     ServerConfig{MetricsPort: 4950},
			wantErr: "no listener enabled",
		},
		{
			name: "file listener without certificate paths",
			cfg: ServerConfig{
				MetricsPort: 4950,
				TLS:         TLSConfig{GRPC: listener(8443)},
			},
			wantErr: "server.tls.certFile path is required",
		},
		{
			name: "file listener with a missing certificate",
			cfg: ServerConfig{
				MetricsPort: 4950,
				TLS:         TLSConfig{CertFile: filepath.Join(t.TempDir(), "absent.crt"), KeyFile: keyFile, GRPC: listener(8443)},
			},
			wantErr: "server.tls.certFile not found",
		},
		{
			name: "duplicate port across certificate sources",
			cfg: ServerConfig{
				MetricsPort: 4950,
				TLS:         TLSConfig{CertFile: certFile, KeyFile: keyFile, GRPC: listener(8443)},
				SPIFFE:      SPIFFEServerConfig{GRPC: listener(8443)},
			},
			wantErr: "server.spiffe.grpc.port 8443 collides with server.tls.grpc",
		},
		{
			name: "listener colliding with the metrics port",
			cfg: ServerConfig{
				MetricsPort: 4950,
				SPIFFE:      SPIFFEServerConfig{REST: listener(4950)},
			},
			wantErr: "collides with server.metricsPort",
		},
		{
			name: "out of range port",
			cfg: ServerConfig{
				MetricsPort: 4950,
				SPIFFE:      SPIFFEServerConfig{GRPC: listener(70000), REST: listener(8544)},
			},
			wantErr: "server.spiffe.grpc.port 70000 is out of range",
		},
		{
			name: "removed grpcPort key",
			cfg: ServerConfig{
				MetricsPort: 4950,
				GrpcPort:    8443,
				SPIFFE:      SPIFFEServerConfig{GRPC: listener(8543)},
			},
			wantErr: "server.grpcPort has been removed; use server.tls.grpc.{enable,port}",
		},
		{
			name: "removed restPort key",
			cfg: ServerConfig{
				MetricsPort: 4950,
				RestPort:    8444,
				SPIFFE:      SPIFFEServerConfig{REST: listener(8544)},
			},
			wantErr: "server.restPort has been removed; use server.tls.rest.{enable,port}",
		},
		{
			name:    "missing metrics port",
			cfg:     ServerConfig{SPIFFE: SPIFFEServerConfig{GRPC: listener(8543)}},
			wantErr: "server.metricsPort is required",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.cfg.Validate()
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want error containing %q", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("Validate() = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}

func TestValidateSocketPathRequirements(t *testing.T) {
	base := func(server ServerConfig) *SpireIdentityExchangeConfig {
		return &SpireIdentityExchangeConfig{
			Server: server,
			SPIRE:  SPIREConfig{TrustDomain: "example.org"},
			Auth:   AuthConfig{Plugins: PluginConfigs{}},
		}
	}

	cases := []struct {
		name    string
		server  ServerConfig
		wantErr string
	}{
		{
			name:    "spiffe listener needs the workload socket",
			server:  ServerConfig{MetricsPort: 4950, SPIFFE: SPIFFEServerConfig{GRPC: listener(8543)}},
			wantErr: "source of the server's own X509-SVID",
		},
		{
			name:    "rest listener needs the workload socket",
			server:  ServerConfig{MetricsPort: 4950, TLS: TLSConfig{REST: listener(8444)}},
			wantErr: "feeds the trust bundle cache",
		},
		{
			name:    "rest listener needs the delegated socket",
			server:  ServerConfig{MetricsPort: 4950, TLS: TLSConfig{REST: listener(8444)}},
			wantErr: "spire.agentDelegatedSocketPath is required",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := base(c.server).Validate()
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, c.wantErr)
			}
		})
	}

	// A gRPC-only file-TLS deployment touches neither socket.
	certFile, keyFile := writeCertPair(t)
	cfg := base(ServerConfig{
		MetricsPort: 4950,
		TLS:         TLSConfig{CertFile: certFile, KeyFile: keyFile, GRPC: listener(8443)},
	})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("gRPC-only file TLS config: Validate() = %v, want nil", err)
	}
}

// TestRepoConfigsDecode guards the config files shipped in this repo against
// schema drift. A stale key decodes silently — yaml.Unmarshal ignores unknown
// fields — so without this a renamed listener key turns a surface off unnoticed,
// which is exactly what happened to the stack suite's "port" key.
func TestRepoConfigsDecode(t *testing.T) {
	for k, v := range map[string]string{
		"SYSTEMD_INSTANCE":       "main",
		"SPIFFE_TRUST_DOMAIN":    "example.org",
		"SIX_LOG_LEVEL":          "info",
		"SIX_PURPOSE_MODE":       "shared",
		"SIX_METRICS_PORT":       "4950",
		"SIX_SVID_TTL":           "1h",
		"SIX_TLS_GRPC_ENABLE":    "true",
		"SIX_TLS_GRPC_PORT":      "8443",
		"SIX_TLS_REST_ENABLE":    "true",
		"SIX_TLS_REST_PORT":      "8444",
		"SIX_SPIFFE_GRPC_ENABLE": "false",
		"SIX_SPIFFE_GRPC_PORT":   "8543",
		"SIX_SPIFFE_REST_ENABLE": "false",
		"SIX_SPIFFE_REST_PORT":   "8544",
	} {
		t.Setenv(k, v)
	}

	// Repo root, relative to internal/config.
	root := filepath.Join("..", "..")

	// plugins/stacks are the expected map keys; nil skips the check. Keys, not
	// counts — both sections are mappings now, and len() alone would pass
	// unchanged against a list, so it would not catch a half-converted file.
	cases := []struct {
		path       string
		tlsGRPC    bool
		tlsREST    bool
		spiffeGRPC bool
		spiffeREST bool
		plugins    []string
		stacks     []string
	}{
		{"config/default.conf", true, true, false, false, []string{"github", "gitlab", "k8s_psat", "spiffe"}, []string{}},
		{"config/legacy/config.example.json", true, true, false, false, nil, nil},
		{"config/legacy/config.example-local.json", true, true, false, false, nil, nil},
		{"tests/integration/github/default.conf", true, true, true, true, []string{"github", "mockhub"}, []string{}},
		{"tests/integration/spiffe/default.conf", true, true, false, false, []string{"spiffe"}, []string{}},
		{"tests/integration/stack/default.conf", true, true, false, false, []string{"k8s_psat", "mockhub"}, []string{"foo"}},
		{"tests/integration/k8s_psat/default.conf", true, true, false, false, []string{"k8s_psat", "spiffe"}, []string{"zot"}},
		{"tests/integration/k8s_deploy/default.conf", true, true, false, false, []string{"k8s_psat"}, []string{}},
	}

	for _, c := range cases {
		t.Run(c.path, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(root, c.path))
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			var cfg SpireIdentityExchangeConfig
			if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(data))), &cfg); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			got := [4]bool{
				cfg.Server.TLS.GRPC.Enabled(), cfg.Server.TLS.REST.Enabled(),
				cfg.Server.SPIFFE.GRPC.Enabled(), cfg.Server.SPIFFE.REST.Enabled(),
			}
			want := [4]bool{c.tlsGRPC, c.tlsREST, c.spiffeGRPC, c.spiffeREST}
			if got != want {
				t.Errorf("listeners [tls.grpc tls.rest spiffe.grpc spiffe.rest] = %v, want %v", got, want)
			}
			if cfg.Server.GrpcPort != 0 || cfg.Server.RestPort != 0 {
				t.Errorf("removed keys still present: grpcPort=%d restPort=%d", cfg.Server.GrpcPort, cfg.Server.RestPort)
			}
			if cfg.Server.MetricsPort == 0 {
				t.Error("server.metricsPort did not decode")
			}
			if cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "" {
				t.Error("server.tls.certFile/keyFile did not decode")
			}
			if c.plugins != nil {
				if got := slices.Sorted(maps.Keys(cfg.Auth.Plugins)); !slices.Equal(got, c.plugins) {
					t.Errorf("auth.plugins keys = %v, want %v", got, c.plugins)
				}
			}
			if c.stacks != nil {
				if got := slices.Sorted(maps.Keys(cfg.Auth.Stacks)); !slices.Equal(got, c.stacks) {
					t.Errorf("auth.stacks keys = %v, want %v", got, c.stacks)
				}
			}
		})
	}
}

// unmarshalAuth decodes a whole config document and hands back its auth block,
// so the tests below exercise the same path an operator's file takes.
func unmarshalAuth(t *testing.T, doc string) (*AuthConfig, error) {
	t.Helper()
	var cfg SpireIdentityExchangeConfig
	if err := yaml.Unmarshal([]byte(doc), &cfg); err != nil {
		return nil, err
	}
	return &cfg.Auth, nil
}

// githubConfig is the smallest github plugin config that passes ValidateConfig,
// inlined so each document below can nest it at its own indentation.
const githubConfig = `config: {audiences: ["spire-identity-exchange"], allowedRepositoryOwners: ["my-org"]}`

func TestAuthConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name: "plugin type defaults to the key",
			doc: `
auth:
  plugins:
    github: {` + githubConfig + `}`,
		},
		{
			name: "explicit plugin field names a different type",
			doc: `
auth:
  plugins:
    mockhub: {plugin: github, ` + githubConfig + `}`,
		},
		{
			name: "unknown plugin type",
			doc: `
auth:
  plugins:
    mockhub: {plugin: bogus, ` + githubConfig + `}`,
			wantErr: `plugin type "bogus" is unknown`,
		},
		{
			name: "key that is not a valid name",
			doc: `
auth:
  plugins:
    "bad name!": {plugin: github, ` + githubConfig + `}`,
			wantErr: "Plugin name bad name! is invalid",
		},
		{
			name: "empty key",
			doc: `
auth:
  plugins:
    "": {plugin: github, ` + githubConfig + `}`,
			wantErr: "Plugin name  is invalid",
		},
		{
			name: "invalid plugin config",
			doc: `
auth:
  plugins:
    github: {config: {audiences: ["x"]}}`,
			wantErr: "at least one of allowedRepositories or allowedRepositoryOwners",
		},
		{
			name: "disabled plugin is not validated",
			doc: `
auth:
  plugins:
    github: {enabled: false, config: {}}`,
		},
		{
			name: "stack name collides with a plugin under passthrough",
			doc: `
auth:
  plugins:
    github: {` + githubConfig + `}
  stacks:
    github: {plugins: [github]}`,
			wantErr: "stack name github is defined the same as an existing plugin",
		},
		{
			name: "same collision is allowed without passthrough",
			doc: `
auth:
  passthroughPlugins: false
  plugins:
    github: {` + githubConfig + `}
  stacks:
    github: {plugins: [github]}`,
		},
		{
			name: "stack key that is not a valid name",
			doc: `
auth:
  plugins:
    github: {` + githubConfig + `}
  stacks:
    "bad name!": {plugins: [github]}`,
			wantErr: "Stack name bad name! is invalid",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			auth, err := unmarshalAuth(t, c.doc)
			if err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			err = auth.Validate()
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("Validate() = nil, want error containing %q", c.wantErr)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("Validate() = %v, want error containing %q", err, c.wantErr)
			}
		})
	}
}

// TestAuthConfigValidateLoadsPlugins covers what Validate leaves behind for the
// loader in main: a resolved plugin type on every entry, a loaded Config on the
// enabled ones, and none on the disabled ones.
func TestAuthConfigValidateLoadsPlugins(t *testing.T) {
	auth, err := unmarshalAuth(t, `
auth:
  plugins:
    github: {`+githubConfig+`}
    mockhub: {plugin: github, `+githubConfig+`}
    gitlab: {enabled: false, config: {}}`)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := auth.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}

	for name, want := range map[string]string{"github": "github", "mockhub": "github"} {
		p, ok := auth.Plugins[name]
		if !ok {
			t.Fatalf("plugin %q missing", name)
		}
		if p.Plugin != want {
			t.Errorf("plugin %q type = %q, want %q", name, p.Plugin, want)
		}
		if p.Config == nil {
			t.Errorf("plugin %q has no loaded config", name)
		}
	}
	if p := auth.Plugins["gitlab"]; p.Config != nil {
		t.Error("disabled plugin gitlab was loaded")
	}
}

// TestAuthConfigRejectsListForm pins the migration message for configs written
// against the removed list schema. Without the explicit check these fail with
// only "cannot unmarshal !!seq into ...", which names no replacement.
func TestAuthConfigRejectsListForm(t *testing.T) {
	cases := map[string]string{
		"plugins": `
auth:
  plugins:
    - {name: github, plugin: github, ` + githubConfig + `}`,
		"stacks": `
auth:
  stacks:
    - {name: foo, plugins: [github]}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := unmarshalAuth(t, doc)
			if err == nil {
				t.Fatalf("unmarshal of the list form = nil, want error")
			}
			if want := "auth." + name + " is a mapping keyed by"; !strings.Contains(err.Error(), want) {
				t.Fatalf("unmarshal = %v, want error containing %q", err, want)
			}
		})
	}
}
