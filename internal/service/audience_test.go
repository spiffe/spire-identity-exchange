package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateMintAudiences(t *testing.T) {
	t.Run("no allowlist accepts any request", func(t *testing.T) {
		require.NoError(t, validateMintAudiences(nil, []string{"a", "b"}))
		require.NoError(t, validateMintAudiences([]string{}, []string{"anything"}))
	})

	t.Run("exact match allowed", func(t *testing.T) {
		require.NoError(t, validateMintAudiences([]string{"zot"}, []string{"zot"}))
	})

	t.Run("subset of allowlist allowed", func(t *testing.T) {
		require.NoError(t, validateMintAudiences([]string{"zot", "registry"}, []string{"zot"}))
	})

	t.Run("disallowed audience rejected", func(t *testing.T) {
		err := validateMintAudiences([]string{"zot"}, []string{"admin-api"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "admin-api")
	})

	t.Run("extra audience alongside allowed one rejected", func(t *testing.T) {
		err := validateMintAudiences([]string{"zot"}, []string{"zot", "other"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "other")
	})
}
