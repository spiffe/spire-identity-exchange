package service

import (
	"context"
	"testing"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/github"
	"github.com/spiffe/spire-identity-exchange/pkg/validator/stack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSelectorGenerator implements validator.TokenValidatorAndSelectorGenerator
// so it can stand in both for a plain SelectorGenerator and for a member plugin
// of a stack.Validator.
type fakeSelectorGenerator struct {
	selectors []*types.Selector
}

func (f *fakeSelectorGenerator) Validate(context.Context, string, validator.Purpose) (validator.Claims, error) {
	return nil, nil
}

func (f *fakeSelectorGenerator) GenerateSelectors(validator.Claims) []*types.Selector {
	return f.selectors
}

func selector(selectorType, value string) *types.Selector {
	return &types.Selector{Type: selectorType, Value: value}
}

// rendered flattens selectors the way the SPIRE CLI and registration entries
// spell them, so assertions read like the operator-facing contract.
func rendered(selectors []*types.Selector) []string {
	out := make([]string, 0, len(selectors))
	for _, s := range selectors {
		out = append(out, s.Type+":"+s.Value)
	}
	return out
}

// The literals here are deliberate. Asserting against SelectorTypeSIX or
// selectorStackNamePrefix would be tautological and would silently bless a
// rename that breaks every registration entry already deployed by operators.
func TestSIXStackSelectorFormat(t *testing.T) {
	for _, tc := range []struct {
		name      string
		stackName string
		want      string
	}{
		{"explicit stack", "foo", "spire_identity_exchange:stack:name:foo"},
		{"passthrough plugin as stack", "k8s_psat", "spire_identity_exchange:stack:name:k8s_psat"},
		// All three are permitted by config.PluginNamePattern, so the rendered
		// selector must stay unambiguous for each.
		{"hyphenated name", "github-actions", "spire_identity_exchange:stack:name:github-actions"},
		{"underscored name", "my_stack", "spire_identity_exchange:stack:name:my_stack"},
		{"dotted name", "stack.io", "spire_identity_exchange:stack:name:stack.io"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := sixStackSelector(tc.stackName)
			assert.Equal(t, "spire_identity_exchange", s.Type)
			assert.Equal(t, tc.want, s.Type+":"+s.Value)
		})
	}
}

// The empty result is what makes the callers' "No selectors derivable from token
// claims" rejection still mean what it says: runner.go handleGetX509SVID,
// runner.go handleGetJWTSVID, and mintcertificate.go MintCertificateByPlugin all
// treat a zero-length result as a client error. The stack selector must never
// mask an empty claim-derived set, because SPIRE matches an entry when the
// entry's selectors are a subset of those supplied — a lone stack selector would
// match an entry scoped only by stack name.
func TestBuildDelegatedSelectorsEmptyClaimSelectorsReturnsNil(t *testing.T) {
	for _, tc := range []struct {
		name      string
		generated []*types.Selector
	}{
		{"nil", nil},
		{"empty non-nil", []*types.Selector{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gen := &fakeSelectorGenerator{selectors: tc.generated}
			assert.Nil(t, buildDelegatedSelectors(gen, nil, "foo"))
		})
	}
}

func TestBuildDelegatedSelectorsAppendsExactlyOneStackSelector(t *testing.T) {
	gen := &fakeSelectorGenerator{selectors: []*types.Selector{
		selector("k8s_psat", "namespace:default"),
		selector("k8s_psat", "service_account_name:default"),
	}}

	got := buildDelegatedSelectors(gen, nil, "foo")

	require.Len(t, got, 3)
	assert.Equal(t, []string{
		"k8s_psat:namespace:default",
		"k8s_psat:service_account_name:default",
		"spire_identity_exchange:stack:name:foo",
	}, rendered(got))

	for i, s := range got {
		require.NotNil(t, s, "selector %d is nil; the agent dereferences Selector.Type", i)
	}

	sixCount := 0
	for _, s := range got {
		if s.Type == "spire_identity_exchange" {
			sixCount++
		}
	}
	assert.Equal(t, 1, sixCount)
}

// Guards the full slice expression in buildDelegatedSelectors: without it,
// append can write the stack selector into spare capacity of the generator's
// slice, so a second call overwrites the first call's result.
func TestBuildDelegatedSelectorsDoesNotAliasGeneratorSlice(t *testing.T) {
	generated := make([]*types.Selector, 1, 4)
	generated[0] = selector("k8s_psat", "namespace:default")
	gen := &fakeSelectorGenerator{selectors: generated}

	first := buildDelegatedSelectors(gen, nil, "foo")
	second := buildDelegatedSelectors(gen, nil, "bar")

	assert.Equal(t, "stack:name:foo", first[1].Value)
	assert.Equal(t, "stack:name:bar", second[1].Value)
	assert.Len(t, generated, 1, "generator's slice length must be untouched")
}

// The passthrough case from cmd/spire-identity-exchange-server/main.go, where a
// bare plugin validator is registered in LoadedStacks under its own plugin name.
// Uses a real validator rather than a fake to prove the plugin selectors and the
// stack selector coexist.
func TestBuildDelegatedSelectorsPassthroughPluginAsStack(t *testing.T) {
	gen := &github.Validator{}
	claims := &validator.JWTClaims{
		Raw: map[string]interface{}{
			"repository":       "my-org/my-repo",
			"repository_owner": "my-org",
		},
	}

	got := rendered(buildDelegatedSelectors(gen, claims, "mockhub"))

	assert.Contains(t, got, "github_actions:repository:my-org/my-repo")
	assert.Contains(t, got, "github_actions:repository_owner:my-org")
	assert.Contains(t, got, "spire_identity_exchange:stack:name:mockhub")
}

// The composite case: an explicit auth.stacks[] entry. Proves a stack.Validator
// and a passthrough plugin travel the identical code path.
func TestBuildDelegatedSelectorsCompositeStack(t *testing.T) {
	member := &fakeSelectorGenerator{selectors: []*types.Selector{
		selector("k8s_psat", "namespace:default"),
	}}
	gen, err := stack.NewValidator(stack.Config{
		Plugins: []string{"k8s_psat"},
		PluginMap: map[string]validator.TokenValidatorAndSelectorGenerator{
			"k8s_psat": member,
		},
	})
	require.NoError(t, err)

	claims := &stack.Claims{
		PluginClaims: map[string]validator.Claims{
			"k8s_psat": &validator.JWTClaims{},
		},
	}

	assert.Equal(t, []string{
		"k8s_psat:namespace:default",
		"spire_identity_exchange:stack:name:foo",
	}, rendered(buildDelegatedSelectors(gen, claims, "foo")))
}
