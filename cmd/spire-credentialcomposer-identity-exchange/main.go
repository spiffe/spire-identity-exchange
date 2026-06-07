package main

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	credentialcomposerv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/credentialcomposer/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Plugin struct {
	credentialcomposerv1.UnsafeCredentialComposerServer
}

func (p *Plugin) ComposeWorkloadX509SVID(ctx context.Context, req *credentialcomposerv1.ComposeWorkloadX509SVIDRequest) (*credentialcomposerv1.ComposeWorkloadX509SVIDResponse, error) {
	attrs := req.Attributes
	id, err := spiffeid.FromString(req.SpiffeId)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %w", err)
	}
	if attrs.Subject == nil {
		attrs.Subject = &credentialcomposerv1.DistinguishedName{}
	}
	cleanedPath := path.Clean(strings.TrimPrefix(id.Path(), "/"))
	dir, _ := path.Split(cleanedPath)
	dir = strings.TrimSuffix(dir, "/")
	if strings.HasPrefix(cleanedPath, "spire-exchange/identity-exchange") {
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
	pluginmain.Serve(
		credentialcomposerv1.CredentialComposerPluginServer(&Plugin{}),
	)
}
