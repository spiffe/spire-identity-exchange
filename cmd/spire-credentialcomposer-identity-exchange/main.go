package main

import (
	"context"
	"path"
	"strings"
	"sync"

	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type PluginConfig struct {
	IdentityExchangePrefix string `hcl:"prefix"`
}

type Plugin struct {
	credentialcomposerv1.UnsafeCredentialComposerServer
	configv1.UnsafeConfigServer

	mu                     sync.RWMutex
	identityExchangePrefix string
}

func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := &PluginConfig{
		IdentityExchangePrefix: "spire-exchange/spire-identity-exchange",
	}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to decode configuration: %v", err)
	}
	prefix := path.Clean(strings.Trim(config.IdentityExchangePrefix, "/"))
	p.mu.Lock()
	p.identityExchangePrefix = prefix
	p.mu.Unlock()
	return &configv1.ConfigureResponse{}, nil
}

func (p *Plugin) ComposeWorkloadX509SVID(ctx context.Context, req *credentialcomposerv1.ComposeWorkloadX509SVIDRequest) (*credentialcomposerv1.ComposeWorkloadX509SVIDResponse, error) {
	attrs := req.Attributes
	id, err := spiffeid.FromString(req.SpiffeId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid SPIFFE ID: %v", err)

	}
	if attrs.Subject == nil {
		attrs.Subject = &credentialcomposerv1.DistinguishedName{}
	}
	cleanedPath := path.Clean(strings.TrimPrefix(id.Path(), "/"))
	dir, _ := path.Split(cleanedPath)
	dir = strings.TrimSuffix(dir, "/")
	p.mu.RLock()
	prefix := p.identityExchangePrefix
	p.mu.RUnlock()
	if strings.HasPrefix(cleanedPath, prefix) {
		attrs.Subject.CommonName = dir
	}
	return &credentialcomposerv1.ComposeWorkloadX509SVIDResponse{
		Attributes: attrs,
	}, nil
}

func (p *Plugin) ComposeAgentX509SVID(context.Context, *credentialcomposerv1.ComposeAgentX509SVIDRequest) (*credentialcomposerv1.ComposeAgentX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (p *Plugin) ComposeServerX509SVID(context.Context, *credentialcomposerv1.ComposeServerX509SVIDRequest) (*credentialcomposerv1.ComposeServerX509SVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (p *Plugin) ComposeServerX509CA(context.Context, *credentialcomposerv1.ComposeServerX509CARequest) (*credentialcomposerv1.ComposeServerX509CAResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}
func (p *Plugin) ComposeWorkloadJWTSVID(context.Context, *credentialcomposerv1.ComposeWorkloadJWTSVIDRequest) (*credentialcomposerv1.ComposeWorkloadJWTSVIDResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func main() {
	p := &Plugin{}
	pluginmain.Serve(
		credentialcomposerv1.CredentialComposerPluginServer(p),
		configv1.ConfigServiceServer(p),
	)
}
