package service

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteJWTSVIDResponse(t *testing.T) {
	resp := &jwtSVIDResponse{
		SpiffeID:  "spiffe://example.org/workload",
		Token:     "eyJhbGciOiJSUzI1NiJ9.payload.signature",
		ExpiresAt: 1700000000,
	}

	t.Run("default json", func(t *testing.T) {
		w := httptest.NewRecorder()
		require.NoError(t, writeJWTSVIDResponse(w, "", resp))

		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		var got jwtSVIDResponse
		require.NoError(t, json.NewDecoder(w.Body).Decode(&got))
		assert.Equal(t, *resp, got)
	})

	t.Run("format token", func(t *testing.T) {
		w := httptest.NewRecorder()
		require.NoError(t, writeJWTSVIDResponse(w, "token", resp))

		assert.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
		assert.Equal(t, resp.Token, w.Body.String())
	})

	t.Run("invalid format", func(t *testing.T) {
		w := httptest.NewRecorder()
		err := writeJWTSVIDResponse(w, "xml", resp)
		require.ErrorIs(t, err, errInvalidJWTSVIDFormat)
	})
}
