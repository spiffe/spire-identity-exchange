package utils

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	constant "github.com/spiffe/spire-identity-exchange/internal/const"
)

// GenerateTemplateData transforms JWT claims into template data for SPIFFE ID generation.
// All raw claims are included as base data, so any JWT claim is accessible in templates.
// GitHub-specific claims (repository, workflow, etc.) are additionally processed and sanitized.
func GenerateTemplateData(claims map[string]interface{}, td string) map[string]interface{} {
	// Start with all raw claims so any JWT field is accessible in the template
	data := make(map[string]interface{}, len(claims)+1)
	for k, v := range claims {
		data[k] = v
	}
	data[constant.TrustDomain] = td

	// Copy basic claims
	data[constant.ClaimSub] = GetStringClaim(claims, constant.ClaimSub)
	data[constant.ClaimIss] = GetStringClaim(claims, constant.ClaimIss)

	// Parse repository into org and repo parts
	parseRepository(data, claims)

	// Sanitize workflow-related claims
	sanitizeWorkflowClaims(data, claims)

	// Clean up git ref (remove refs/heads/ or refs/tags/)
	cleanGitRef(data, claims)

	return data
}

func parseRepository(data map[string]interface{}, claims map[string]interface{}) {
	repository := GetStringClaim(claims, constant.ClaimRepository)
	if repository == "" {
		return
	}

	parts := strings.SplitN(repository, "/", 2)
	if len(parts) == 2 {
		data[constant.ClaimOrg] = sanitizeForSPIFFE(parts[0])
		data[constant.ClaimRepository] = sanitizeForSPIFFE(parts[1])
	} else {
		// Fallback: use repository name for both org and repo
		data[constant.ClaimOrg] = sanitizeForSPIFFE(repository)
		data[constant.ClaimRepository] = sanitizeForSPIFFE(repository)
	}
}

func sanitizeWorkflowClaims(data map[string]interface{}, claims map[string]interface{}) {
	workflowClaims := []string{
		constant.ClaimWorkflow,
		constant.ClaimSHA,
		constant.ClaimWorkflowRef,
		constant.ClaimJobWorkflowRef,
		constant.ClaimActor,
		constant.ClaimRunnerEnvironment,
		constant.ClaimRunID,
		constant.ClaimRunNumber,
	}

	for _, key := range workflowClaims {
		data[key] = sanitizeForSPIFFE(GetStringClaim(claims, key))
	}
}

func cleanGitRef(data map[string]interface{}, claims map[string]interface{}) {
	ref := GetStringClaim(claims, constant.ClaimRef)
	if ref == "" {
		return
	}

	// Remove git ref prefixes
	ref = strings.TrimPrefix(ref, "refs/heads/")
	ref = strings.TrimPrefix(ref, "refs/tags/")

	data[constant.ClaimRef] = sanitizeForSPIFFE(ref)
}

// IsValueAllowed checks if a value matches any of the allowed patterns
func IsValueAllowed(value string, allowedValues []string) bool {
	for _, av := range allowedValues {
		if strings.Contains(av, "*") {
			pattern := strings.TrimSuffix(av, "*")
			if strings.HasPrefix(value, pattern) {
				return true
			}
		} else if value == av {
			return true
		}
	}
	return false
}

// GetStringClaim is a helper function to get string claim value
func GetStringClaim(claims map[string]interface{}, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

var consecutiveDashesRE = regexp.MustCompile(`-+`)

// sanitizeForSPIFFE sanitizes a string for use in SPIFFE IDs
func sanitizeForSPIFFE(str string) string {
	if str == "" {
		return ""
	}
	const maxLength = 255
	if len(str) > maxLength {
		str = str[:maxLength]
	}
	replacer := strings.NewReplacer(
		"_", "-",
		".", "-",
		"/", "-",
		" ", "-",
		":", "-",
		"@", "-",
		"[", "-",
		"]", "-",
	)
	str = replacer.Replace(str)
	str = strings.ToLower(str)

	str = consecutiveDashesRE.ReplaceAllString(str, "-")
	str = strings.Trim(str, "-")

	return str
}

// GenerateSPIFFEID generates a SPIFFE ID from raw JWT claims using the configured template.
func GenerateSPIFFEID(rawClaims map[string]interface{}, spiffeIDTemplate *template.Template, trustDomain string) (spiffeid.ID, error) {
	// Ensure template is configured
	if spiffeIDTemplate == nil {
		return spiffeid.ID{}, fmt.Errorf("SPIFFE ID template is empty")
	}

	// Get template data from claims
	data := GenerateTemplateData(rawClaims, trustDomain)

	// Execute template
	var buf bytes.Buffer
	if err := spiffeIDTemplate.Execute(&buf, data); err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to execute SPIFFE ID template: %w", err)
	}

	spiffeIDStr := buf.String()

	// Parse SPIFFE ID
	spiffeID, err := spiffeid.FromString(spiffeIDStr)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("failed to parse SPIFFE ID %s: %w", spiffeIDStr, err)
	}

	return spiffeID, nil
}
