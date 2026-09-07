// internal/middleware/error_handler_test.go
package middleware

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"bom-tanstack-api/internal/apperr"

	"github.com/labstack/echo/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeErrorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body
}

func TestErrorHandler_MapsDomainErrorsToStatusCodes(t *testing.T) {
	cases := []struct {
		err            error
		expectedStatus int
	}{
		{apperr.ErrInvalidCredentials, http.StatusUnauthorized},
		{apperr.ErrTokenInvalid, http.StatusUnauthorized},
		{apperr.ErrTokenExpired, http.StatusUnauthorized},
		{apperr.ErrUserInactive, http.StatusForbidden},
		{apperr.ErrPermissionDenied, http.StatusForbidden},
		{apperr.ErrUserNotFound, http.StatusNotFound},
		{apperr.ErrEmailAlreadyExists, http.StatusConflict},
	}

	for _, tc := range cases {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		ErrorHandler(c, tc.err)

		assert.Equal(t, tc.expectedStatus, rec.Code, "error: %v", tc.err)
	}
}

func TestErrorHandler_UnknownErrorReturns500WithGenericMessage(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	ErrorHandler(c, assert.AnError)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	body := decodeErrorBody(t, rec)
	assert.Equal(t, "internal server error", body["error"])
	assert.NotContains(t, rec.Body.String(), assert.AnError.Error())
}
