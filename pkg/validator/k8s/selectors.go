package k8s

import (
	"fmt"

	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// SelectorType is the SPIRE selector type emitted for K8s SA token claims.
// Matches SPIRE's k8s_psat node attestor naming so operators see a single
// consistent identifier across both attestation and exchange surfaces.
const SelectorType = "k8s_psat"

// GenerateSelectors produces SPIRE selectors from validated K8s service-account
// token claims. Implements validator.SelectorGenerator.
func (v *Validator) GenerateSelectors(claims validator.Claims) []*types.Selector {
	c := claimsFromRaw(claims.GetRaw())
	return buildSelectors(c)
}

func buildSelectors(c *Claims) []*types.Selector {
	var selectors []*types.Selector

	add := func(key, value string) {
		if value != "" {
			selectors = append(selectors, &types.Selector{
				Type:  SelectorType,
				Value: fmt.Sprintf("%s:%s", key, value),
			})
		}
	}

	add("cluster_name", c.ClusterName)
	add("namespace", c.Namespace)
	add("service_account_name", c.ServiceAccountName)
	add("service_account_uid", c.ServiceAccountUID)
	add("pod_name", c.PodName)
	add("pod_uid", c.PodUID)
	add("node_name", c.NodeName)
	add("node_uid", c.NodeUID)
	add("sub", c.Subject)

	return selectors
}
