package service

import "fmt"

// validateMintAudiences enforces a stack's optional mintAudiences allowlist.
// When allowed is empty, any non-empty requested list is accepted.
func validateMintAudiences(allowed, requested []string) error {
	if len(allowed) == 0 {
		return nil
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, aud := range allowed {
		allowedSet[aud] = struct{}{}
	}
	var disallowed []string
	for _, aud := range requested {
		if _, ok := allowedSet[aud]; !ok {
			disallowed = append(disallowed, aud)
		}
	}
	if len(disallowed) > 0 {
		return fmt.Errorf("audiences %v are not permitted for this stack", disallowed)
	}
	return nil
}
