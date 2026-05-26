package github

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spiffe/spire-identity-exchange/pkg/validator"
)

// Claims holds the parsed claims from a GitHub Actions OIDC token.
// It embeds jwt.RegisteredClaims so that jwt/v5 handles exp, nbf, iat,
// iss, sub, aud validation via ParserOptions.
type Claims struct {
	jwt.RegisteredClaims

	Repository           string `json:"repository"`
	RepositoryID         string `json:"repository_id"`
	RepositoryOwner      string `json:"repository_owner"`
	RepositoryOwnerID    string `json:"repository_owner_id"`
	RepositoryVisibility string `json:"repository_visibility"`
	Workflow             string `json:"workflow"`
	WorkflowRef          string `json:"workflow_ref"`
	WorkflowSHA          string `json:"workflow_sha"`
	JobWorkflowRef       string `json:"job_workflow_ref"`
	JobWorkflowSHA       string `json:"job_workflow_sha"`
	Ref                  string `json:"ref"`
	RefType              string `json:"ref_type"`
	RefProtected         string `json:"ref_protected"`
	SHA                  string `json:"sha"`
	HeadRef              string `json:"head_ref"`
	BaseRef              string `json:"base_ref"`
	EventName            string `json:"event_name"`
	Actor                string `json:"actor"`
	ActorID              string `json:"actor_id"`
	RunID                string `json:"run_id"`
	RunNumber            string `json:"run_number"`
	RunAttempt           string `json:"run_attempt"`
	Environment          string `json:"environment"`
	EnvironmentNodeID    string `json:"environment_node_id"`
	RunnerEnvironment    string `json:"runner_environment"`
	Enterprise           string `json:"enterprise"`
}

// ToCommonClaims converts GitHub-specific claims to the shared JWTClaims type.
func (c *Claims) ToCommonClaims() *validator.JWTClaims {
	raw := make(map[string]interface{})
	if b, err := json.Marshal(c); err == nil {
		json.Unmarshal(b, &raw) //nolint:errcheck
	}

	var expiry int64
	if c.ExpiresAt != nil {
		expiry = c.ExpiresAt.Unix()
	}
	var notBefore int64
	if c.NotBefore != nil {
		notBefore = c.NotBefore.Unix()
	}
	var issuedAt int64
	if c.IssuedAt != nil {
		issuedAt = c.IssuedAt.Unix()
	}

	aud := []string{}
	if c.Audience != nil {
		aud = []string(c.Audience)
	}

	return &validator.JWTClaims{
		Issuer:    c.Issuer,
		Subject:   c.Subject,
		Audience:  aud,
		Expiry:    expiry,
		NotBefore: notBefore,
		IssuedAt:  issuedAt,
		JTI:       c.ID,
		Raw:       raw,
	}
}
