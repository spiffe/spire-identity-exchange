package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestX509Purpose(t *testing.T) {
	p := X509Purpose()
	assert.Equal(t, "x509", p.String())
}

func TestJWTPurpose_OrderIndependent(t *testing.T) {
	p1 := JWTPurpose([]string{"b", "a"})
	p2 := JWTPurpose([]string{"a", "b"})
	assert.Equal(t, p1.String(), p2.String(), "same audiences in different order should produce the same purpose")
}

func TestJWTPurpose_DifferentAudiences(t *testing.T) {
	p1 := JWTPurpose([]string{"api.example.com"})
	p2 := JWTPurpose([]string{"db.example.com"})
	assert.NotEqual(t, p1.String(), p2.String(), "different audiences should produce different purposes")
}

func TestJWTPurpose_Prefix(t *testing.T) {
	p := JWTPurpose([]string{"example.com"})
	assert.Contains(t, p.String(), "jwt:", "JWT purpose should have jwt: prefix")
}

func TestJWTPurpose_DoesNotMutateInput(t *testing.T) {
	input := []string{"c", "a", "b"}
	original := make([]string, len(input))
	copy(original, input)
	_ = JWTPurpose(input)
	assert.Equal(t, original, input, "JWTPurpose should not mutate the input slice")
}
