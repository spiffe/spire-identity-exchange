package config

import (
	"os"
	"path/filepath"
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
			Auth:   AuthConfig{Plugins: []PluginConfig{}},
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

	cases := []struct {
		path       string
		tlsGRPC    bool
		tlsREST    bool
		spiffeGRPC bool
		spiffeREST bool
		plugins    int // -1 to skip the check
	}{
		{"config/default.conf", true, true, false, false, 4},
		{"config/legacy/config.example.json", true, true, false, false, -1},
		{"config/legacy/config.example-local.json", true, true, false, false, -1},
		{"tests/integration/github/default.conf", true, true, true, true, -1},
		{"tests/integration/spiffe/default.conf", true, true, false, false, -1},
		{"tests/integration/stack/default.conf", true, true, false, false, -1},
		{"tests/integration/k8s_psat/default.conf", true, true, false, false, -1},
		{"tests/integration/k8s_deploy/default.conf", true, true, false, false, -1},
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
			if c.plugins >= 0 && len(cfg.Auth.Plugins) != c.plugins {
				t.Errorf("auth.plugins = %d, want %d", len(cfg.Auth.Plugins), c.plugins)
			}
		})
	}
}
