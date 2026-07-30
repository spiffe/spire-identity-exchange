package service

import (
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// SelectorTypeSIX is the selector type for selectors spire-identity-exchange
// asserts on its own behalf, rather than deriving from a plugin's token claims.
// Underscored to match the per-plugin selector types (k8s_psat, github_actions,
// gitlab_ci, spiffe).
//
// The SPIRE agent does not require selector types to be registered attestor
// types; it only requires a non-empty type containing no ':' and a non-empty
// value (spire pkg/server/api/selector.go SelectorsFromProto). Entry creation on
// the server runs the same validation, so operators can put this type into a
// registration entry.
const SelectorTypeSIX = "spire_identity_exchange"

// selectorStackNamePrefix yields "spire_identity_exchange:stack:name:<stack>".
const selectorStackNamePrefix = "stack:name:"

// sixStackSelector returns the selector naming the stack the request was made
// against: the {stack} REST path segment, or MintCertificateRequest.stackName
// (which falls back to the plugin name for single-plugin calls).
//
// stackName needs no sanitization or escaping. Every caller reaches this only
// after a successful cfg.Auth.LoadedStacks lookup, and that map is keyed solely
// by configured plugin and stack names, both already validated against
// config.PluginNamePattern (internal/config/config.go:19, applied at :288 and
// :318) — which permits no ':' and no whitespace. A future relaxation of that
// pattern would need to revisit this.
func sixStackSelector(stackName string) *types.Selector {
	return &types.Selector{
		Type:  SelectorTypeSIX,
		Value: selectorStackNamePrefix + stackName,
	}
}

// buildDelegatedSelectors generates the selectors a stack derives from validated
// claims and appends the selector naming that stack, producing the set handed to
// the Delegated Identity API. Registration entries include the stack selector to
// scope themselves to a single stack; entries that omit it keep matching from any
// stack, since SPIRE matches when an entry's selectors are a subset of those
// supplied.
//
// Returns nil when the claim-derived set is empty, so callers keep rejecting "no
// selectors derivable from token claims". The stack selector must never be the
// only selector supplied: because matching is subset-based, a lone stack selector
// would match an entry scoped only by stack name and grant it to any token that
// stack accepts.
func buildDelegatedSelectors(gen validator.SelectorGenerator, claims validator.Claims, stackName string) []*types.Selector {
	selectors := gen.GenerateSelectors(claims)
	if len(selectors) == 0 {
		return nil
	}
	// Full slice expression so append allocates a new array rather than writing
	// into spare capacity of one the generator may still hold.
	return append(selectors[:len(selectors):len(selectors)], sixStackSelector(stackName))
}
