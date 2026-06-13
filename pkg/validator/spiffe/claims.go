package spiffe

// Claims holds SPIFFE-specific claim fields from a validated SPIFFE SVID JWT.
// Used internally for typed access when generating selectors.
type Claims struct {
    // TrustDomain is the SPIFFE trust domain from the sub claim
    TrustDomain string
    // Path is the SPIFFE ID path from the sub claim
    Path string
    // RawSubject is the original, URL-decoded 'sub' claim value
    RawSubject string
}

// claimsFromRaw reconstructs SPIFFE Claims from the raw claims map.
func claimsFromRaw(raw map[string]interface{}) *Claims {
    c := &Claims{}

    getString := func(key string) string {
        if v, ok := raw[key].(string); ok {
            return v
        }
        return ""
    }

    sub := getString("sub")
    c.RawSubject = sub

    return c
}
