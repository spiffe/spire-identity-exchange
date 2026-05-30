package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJWTClaims_GetRaw(t *testing.T) {
	tests := []struct {
		name     string
		raw      map[string]interface{}
		expected map[string]interface{}
	}{
		{
			name:     "returns_raw_map",
			raw:      map[string]interface{}{"iss": "test", "sub": "user"},
			expected: map[string]interface{}{"iss": "test", "sub": "user"},
		},
		{
			name:     "nil_raw",
			raw:      nil,
			expected: nil,
		},
		{
			name:     "empty_raw",
			raw:      map[string]interface{}{},
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JWTClaims{Raw: tt.raw}
			assert.Equal(t, tt.expected, c.GetRaw())
		})
	}
}

func TestJWTClaims_GetUniqueID(t *testing.T) {
	tests := []struct {
		name     string
		jti      string
		expected string
	}{
		{
			name:     "returns_jti",
			jti:      "unique-id-123",
			expected: "unique-id-123",
		},
		{
			name:     "empty_jti",
			jti:      "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JWTClaims{JTI: tt.jti}
			assert.Equal(t, tt.expected, c.GetUniqueID())
		})
	}
}

func TestJWTClaims_GetExpiration(t *testing.T) {
	tests := []struct {
		name     string
		expiry   int64
		expected int64
	}{
		{
			name:     "returns_expiry",
			expiry:   1700000000,
			expected: 1700000000,
		},
		{
			name:     "zero_value",
			expiry:   0,
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &JWTClaims{Expiry: tt.expiry}
			assert.Equal(t, tt.expected, c.GetExpiration())
		})
	}
}
